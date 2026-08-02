//go:build linux

package store

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type offlinePortalFixture struct {
	path     string
	database *sql.DB
}

func newOfflinePortalFixture(t *testing.T) *offlinePortalFixture {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "portal #1.db")
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := uri.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	uri.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	fixture := &offlinePortalFixture{path: path, database: database}
	t.Cleanup(func() { _ = database.Close() })
	value := &Store{db: database}
	if err := value.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *offlinePortalFixture) insertIdentity(t *testing.T, tenantID, runtimeUser, dataRoot string, enabled any) {
	t.Helper()
	if _, err := f.database.Exec(`INSERT INTO portal_users
(username,username_norm,password_hash,tenant_id,runtime_user,data_root,enabled,is_admin,auth_version,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,0,1,1700000000,1700000000)`, runtimeUser, runtimeUser, "hash-placeholder", tenantID, runtimeUser, dataRoot, enabled); err != nil {
		t.Fatal(err)
	}
}

func (f *offlinePortalFixture) protectSet(t *testing.T) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Chmod(f.path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func (f *offlinePortalFixture) close(t *testing.T) {
	t.Helper()
	if f.database == nil {
		return
	}
	if err := f.database.Close(); err != nil {
		t.Fatal(err)
	}
	f.database = nil
	if err := os.Chmod(f.path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectPortalIdentitiesOfflineReadsWALOnlyCommittedRows(t *testing.T) {
	fixture := newOfflinePortalFixture(t)
	fixture.insertIdentity(t, "11111111-1111-4111-8111-111111111111", "workagent_first", "/srv/workagent/users/11111111-1111-4111-8111-111111111111", true)
	fixture.insertIdentity(t, "22222222-2222-4222-8222-222222222222", "workagent_second", "/srv/workagent/users/22222222-2222-4222-8222-222222222222", false)
	fixture.protectSet(t)
	wal, err := os.Stat(fixture.path + "-wal")
	if err != nil || wal.Size() == 0 {
		t.Fatalf("fixture row was not retained in WAL: info=%v err=%v", wal, err)
	}

	identities, err := InspectPortalIdentitiesOffline(context.Background(), fixture.path, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	want := []PortalUserIdentity{
		{TenantID: "11111111-1111-4111-8111-111111111111", RuntimeUser: "workagent_first", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111", Enabled: true},
		{TenantID: "22222222-2222-4222-8222-222222222222", RuntimeUser: "workagent_second", DataRoot: "/srv/workagent/users/22222222-2222-4222-8222-222222222222", Enabled: false},
	}
	if len(identities) != len(want) {
		t.Fatalf("unexpected identities: %+v", identities)
	}
	for index := range want {
		if identities[index] != want[index] {
			t.Fatalf("identity %d: got %+v want %+v", index, identities[index], want[index])
		}
	}
}

func TestInspectPortalIdentitiesOfflineDoesNotCreateMissingDatabase(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "missing.db")
	if _, err := InspectPortalIdentitiesOffline(context.Background(), path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
		t.Fatal("missing Portal database was accepted")
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspection created %s: %v", path+suffix, err)
		}
	}
}

func TestInspectPortalIdentitiesOfflineRejectsUnsafeLiveFiles(t *testing.T) {
	t.Run("database symlink", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		fixture.close(t)
		target := fixture.path + ".real"
		if err := os.Rename(fixture.path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, fixture.path); err != nil {
			t.Fatal(err)
		}
		assertOfflinePortalRejected(t, fixture.path)
	})

	t.Run("database hardlink", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		fixture.close(t)
		if err := os.Link(fixture.path, fixture.path+".alias"); err != nil {
			t.Fatal(err)
		}
		assertOfflinePortalRejected(t, fixture.path)
	})

	t.Run("database mode", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		fixture.close(t)
		if err := os.Chmod(fixture.path, 0o640); err != nil {
			t.Fatal(err)
		}
		assertOfflinePortalRejected(t, fixture.path)
	})

	t.Run("WAL symlink", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		fixture.close(t)
		outside := filepath.Join(t.TempDir(), "outside-wal")
		if err := os.WriteFile(outside, []byte("untrusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, fixture.path+"-wal"); err != nil {
			t.Fatal(err)
		}
		assertOfflinePortalRejected(t, fixture.path)
	})

	if os.Geteuid() == 0 {
		t.Run("database owner", func(t *testing.T) {
			fixture := newOfflinePortalFixture(t)
			fixture.close(t)
			if err := os.Chown(fixture.path, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			assertOfflinePortalRejected(t, fixture.path)
		})
	}
}

func assertOfflinePortalRejected(t *testing.T, path string) {
	t.Helper()
	if _, err := InspectPortalIdentitiesOffline(context.Background(), path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
		t.Fatal("unsafe Portal database set was accepted")
	}
}

func TestInspectPortalIdentitiesOfflineRejectsMalformedSchemaAndRows(t *testing.T) {
	t.Run("wrong version", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		if _, err := fixture.database.Exec(`PRAGMA user_version=3`); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		assertOfflinePortalRejected(t, fixture.path)
	})

	t.Run("incomplete v4 schema", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, "portal.db")
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, execErr := database.Exec(`CREATE TABLE portal_users (
id INTEGER PRIMARY KEY, username TEXT, username_norm TEXT, password_hash TEXT,
tenant_id TEXT, runtime_user TEXT, data_root TEXT, enabled INTEGER, is_admin INTEGER,
auth_version INTEGER, created_at INTEGER, updated_at INTEGER, last_login_at INTEGER);
PRAGMA user_version=4;`)
		closeErr := database.Close()
		if execErr != nil || closeErr != nil {
			t.Fatal(errors.Join(execErr, closeErr))
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		assertOfflinePortalRejected(t, path)
	})

	t.Run("foreign key violation", func(t *testing.T) {
		fixture := newOfflinePortalFixture(t)
		if _, err := fixture.database.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.Exec(`INSERT INTO portal_sessions
(token_hash,csrf_hash,user_id,auth_version,created_at,expires_at,last_seen_at,remote_ip,user_agent_hash)
VALUES(?,?,999,1,1,2,1,'192.0.2.1','agent')`, make([]byte, 32), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		assertOfflinePortalRejected(t, fixture.path)
	})

	for _, test := range []struct {
		name    string
		enabled any
	}{
		{name: "integer outside boolean domain", enabled: int64(2)},
		{name: "non-integer boolean", enabled: "not-an-integer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOfflinePortalFixture(t)
			if _, err := fixture.database.Exec(`PRAGMA ignore_check_constraints=ON`); err != nil {
				t.Fatal(err)
			}
			fixture.insertIdentity(t, "11111111-1111-4111-8111-111111111111", "workagent_invalid", "/srv/workagent/users/11111111-1111-4111-8111-111111111111", test.enabled)
			fixture.close(t)
			if _, err := InspectPortalIdentitiesOffline(context.Background(), fixture.path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
				t.Fatal("malformed enabled value was accepted")
			}
		})
	}
}

func TestQueryOfflinePortalIdentitiesRequiresExactIntegerBoolean(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled any
	}{
		{name: "integer outside domain", enabled: int64(2)},
		{name: "text", enabled: "not-an-integer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			if _, err := database.Exec(`CREATE TABLE portal_users (id INTEGER PRIMARY KEY, tenant_id TEXT, runtime_user TEXT, data_root TEXT, enabled, is_admin); INSERT INTO portal_users VALUES(1,'11111111-1111-4111-8111-111111111111','workagent_invalid','/srv/workagent/users/11111111-1111-4111-8111-111111111111',?,0)`, test.enabled); err != nil {
				t.Fatal(err)
			}
			transaction, err := database.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.Rollback()
			if _, err := queryOfflinePortalIdentities(context.Background(), transaction); err == nil || !strings.Contains(err.Error(), "enabled") {
				t.Fatalf("non-boolean enabled value was accepted or misdiagnosed: %v", err)
			}
		})
	}
}

func TestInspectOfflinePortalCopyDoesNotCreateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := inspectOfflinePortalCopy(context.Background(), path); err == nil {
		t.Fatal("missing private copy was accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mode=rw inspection created a database: %v", err)
	}
}

func TestOfflinePortalPrivateCopyIncludesJournalButExcludesSHM(t *testing.T) {
	fixture := newOfflinePortalFixture(t)
	fixture.close(t)
	journal := []byte("cold rollback journal fixture")
	if err := os.WriteFile(fixture.path+"-journal", journal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.path+"-shm", make([]byte, 32*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	sources, err := openOfflinePortalSources(fixture.path, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.close()
	workRoot, workFD, err := makeOfflinePortalWorkRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupOfflinePortalWorkRoot(workRoot, workFD)
	for _, source := range sources.files {
		if !source.present || source.suffix == "-shm" {
			continue
		}
		if err := copyOfflinePortalSource(context.Background(), workFD, "portal.db"+source.suffix, source); err != nil {
			t.Fatal(err)
		}
	}
	copiedJournal, err := os.ReadFile(filepath.Join(workRoot, "portal.db-journal"))
	if err != nil || string(copiedJournal) != string(journal) {
		t.Fatalf("rollback journal was not copied exactly: payload=%q err=%v", copiedJournal, err)
	}
	if _, err := os.Lstat(filepath.Join(workRoot, "portal.db-shm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live SHM was copied into the private inspection set: %v", err)
	}
	if err := sources.revalidate(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenProtectsSQLiteSetDespiteInheritedUmask(t *testing.T) {
	previousUmask := syscall.Umask(0o022)
	defer syscall.Umask(previousUmask)
	state := filepath.Join(t.TempDir(), "state")
	value, err := Open(filepath.Join(state, "portal.db"), filepath.Join(state, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := filepath.Join(state, "portal.db") + suffix
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			t.Fatalf("SQLite%s was not present for protection readback: %v", suffix, err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
			t.Fatalf("SQLite%s protection mismatch: mode=%#o uid=%d gid=%d nlink=%d", suffix, stat.Mode&0o7777, stat.Uid, stat.Gid, stat.Nlink)
		}
	}
}

func TestInspectPortalIdentitiesOfflineRecoversHotRollbackJournal(t *testing.T) {
	fixture := newOfflinePortalFixture(t)
	fixture.insertIdentity(t, "11111111-1111-4111-8111-111111111111", "workagent_committed", "/srv/workagent/users/11111111-1111-4111-8111-111111111111", true)
	fixture.close(t)

	database := openOfflineTestDatabase(t, fixture.path, "DELETE")
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	largeDetails := strings.Repeat("a", 32*1024)
	for index := 0; index < 32; index++ {
		if _, err := transaction.Exec(`INSERT INTO audit_events(occurred_at,action,outcome,details_json) VALUES(1,'fixture','success',?)`, largeDetails); err != nil {
			transaction.Rollback()
			database.Close()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.path, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOfflinePortalHotJournalWriterProcess$", "-test.count=1")
	command.Env = append(os.Environ(), "WORKAGENT_HOT_JOURNAL_DB="+fixture.path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "WORKAGENT_HOT_JOURNAL_READY" {
			ready = true
			break
		}
	}
	if !ready {
		waitErr := command.Wait()
		t.Fatalf("hot-journal writer did not become ready: scan=%v wait=%v stderr=%s", scanner.Err(), waitErr, stderr.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	for _, suffix := range []string{"", "-journal"} {
		if err := os.Chmod(fixture.path+suffix, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	identities, err := InspectPortalIdentitiesOffline(context.Background(), fixture.path, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].RuntimeUser != "workagent_committed" {
		t.Fatalf("hot rollback journal was not applied to the private copy: %+v", identities)
	}
}

func TestOfflinePortalHotJournalWriterProcess(t *testing.T) {
	path := os.Getenv("WORKAGENT_HOT_JOURNAL_DB")
	if path == "" {
		t.Skip("helper process")
	}
	database := openOfflineTestDatabase(t, path, "DELETE")
	if _, err := database.Exec(`PRAGMA cache_size=1; PRAGMA cache_spill=ON; PRAGMA synchronous=FULL`); err != nil {
		t.Fatal(err)
	}
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`UPDATE portal_users SET runtime_user='workagent_uncommitted'`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`UPDATE audit_events SET details_json=details_json||'b'`); err != nil {
		t.Fatal(err)
	}
	journalPath := path + "-journal"
	deadline := time.Now().Add(10 * time.Second)
	magic := []byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}
	for {
		file, openErr := os.Open(journalPath)
		var header [8]byte
		read := 0
		if openErr == nil {
			read, _ = file.Read(header[:])
			_ = file.Close()
		}
		if read == len(header) && string(header[:]) == string(magic) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rollback journal never became hot: open=%v header=%x", openErr, header)
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Println("WORKAGENT_HOT_JOURNAL_READY")
	blockForever := make(chan struct{})
	<-blockForever
	runtime.KeepAlive(transaction)
	runtime.KeepAlive(database)
}

func openOfflineTestDatabase(t *testing.T, path, journalMode string) *sql.DB {
	t.Helper()
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := uri.Query()
	query.Set("mode", "rw")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode("+journalMode+")")
	query.Add("_pragma", "synchronous(FULL)")
	uri.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	if err := database.Ping(); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database
}
