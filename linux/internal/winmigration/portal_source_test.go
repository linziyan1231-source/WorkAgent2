package winmigration

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortalWorkingCopyIncludesFrozenWALWithoutMutatingSnapshot(t *testing.T) {
	liveRoot := t.TempDir()
	livePath := filepath.Join(liveRoot, "portal.db")
	writer, err := sql.Open("sqlite", livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA wal_autocheckpoint=0`,
		`CREATE TABLE marker(value TEXT NOT NULL)`,
		`INSERT INTO marker(value) VALUES('main')`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
		`INSERT INTO marker(value) VALUES('wal')`,
	} {
		if _, err := writer.Exec(statement); err != nil {
			t.Fatalf("prepare WAL fixture with %q: %v", statement, err)
		}
	}
	walInfo, err := os.Stat(livePath + "-wal")
	if err != nil || walInfo.Size() == 0 {
		t.Fatalf("fixture has no uncheckpointed WAL: info=%v err=%v", walInfo, err)
	}

	snapshotRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(snapshotRoot, "global"), 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(snapshotRoot, filepath.FromSlash(sourcePortalRelative))
	for source, destination := range map[string]string{
		livePath:          snapshotPath,
		livePath + "-wal": snapshotPath + "-wal",
		livePath + "-shm": snapshotPath + "-shm",
	} {
		payload, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotFileDigests(t, snapshotPath)

	snapshotFD, err := openSnapshotRoot(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(snapshotFD)
	source, err := inspectPortalSourceSet(snapshotFD)
	if err != nil {
		t.Fatal(err)
	}
	workRoot, workPath, err := preparePortalWorkingCopy(snapshotFD, source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupPortalWorkRoot(workRoot)
	reader, err := openWALAwareReadOnlySQLite(workPath)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	queryErr := reader.QueryRow(`SELECT COUNT(*) FROM marker`).Scan(&count)
	closeErr := reader.Close()
	if queryErr != nil || closeErr != nil {
		t.Fatalf("read frozen WAL snapshot: query=%v close=%v", queryErr, closeErr)
	}
	if count != 2 {
		t.Fatalf("WAL-aware working-copy reader lost an uncheckpointed WAL row: got %d want 2", count)
	}
	if after := snapshotFileDigests(t, snapshotPath); after != before {
		t.Fatalf("read-only Portal inspection mutated the frozen DB/WAL/SHM set: before=%v after=%v", before, after)
	}
	cleanupPortalWorkRoot(workRoot)
	if _, err := os.Lstat(workRoot); !os.IsNotExist(err) {
		t.Fatalf("private Portal working copy was not cleaned up: %v", err)
	}
}

func snapshotFileDigests(t *testing.T, databasePath string) [3][32]byte {
	t.Helper()
	var result [3][32]byte
	for index, suffix := range []string{"", "-wal", "-shm"} {
		payload, err := os.ReadFile(databasePath + suffix)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = sha256.Sum256(payload)
	}
	return result
}

func TestPortalWALAndSHMHashesAreBoundIntoSourceFingerprint(t *testing.T) {
	report := Report{
		SchemaVersion:         ReportSchemaVersion,
		SourcePortalSHA256:    strings.Repeat("a", 64),
		SourcePortalWALSHA256: strings.Repeat("b", 64),
		SourcePortalSHMSHA256: strings.Repeat("c", 64),
		SourceCPAStateSHA256:  strings.Repeat("d", 64),
		TenantDataRoot:        "/srv/workagent/users",
	}
	base, err := sourceFingerprint(report)
	if err != nil {
		t.Fatal(err)
	}
	report.SourcePortalWALSHA256 = strings.Repeat("e", 64)
	changedWAL, err := sourceFingerprint(report)
	if err != nil {
		t.Fatal(err)
	}
	report.SourcePortalWALSHA256 = strings.Repeat("b", 64)
	report.SourcePortalSHMSHA256 = strings.Repeat("f", 64)
	changedSHM, err := sourceFingerprint(report)
	if err != nil {
		t.Fatal(err)
	}
	if base == changedWAL || base == changedSHM || changedWAL == changedSHM {
		t.Fatal("Portal WAL or SHM hash did not change the canonical source fingerprint")
	}
}
