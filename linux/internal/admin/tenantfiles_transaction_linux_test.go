package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/posixacl"

	"golang.org/x/sys/unix"
)

var errTenantFileTestCrash = errors.New("simulated process crash")

func TestTenantFileTransactionRecoversEveryDurableInterruption(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	probeRoot := filepath.Join(t.TempDir(), "probe")
	probePlan, probeOld := makeTenantFileTransactionTestPlan(t, probeRoot, "new")
	expectedPoints := tenantFileTransactionFaultPoints(probePlan, true)
	installTenantFileTransactionTestState(t, probeOld)
	var observed []string
	if err := publishTenantFileSet(context.Background(), probePlan, func(point string) error {
		observed = append(observed, point)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(observed, expectedPoints) {
		t.Fatalf("transaction fault surface changed:\n got %q\nwant %q", observed, expectedPoints)
	}

	for _, point := range expectedPoints {
		t.Run(strings.ReplaceAll(point, ":", "_"), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "transaction")
			plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
			installTenantFileTransactionTestState(t, old)
			err := publishTenantFileSet(context.Background(), plan, func(actual string) error {
				if actual == point {
					return errTenantFileTestCrash
				}
				return nil
			})
			if !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("fault point %s did not interrupt the transaction: %v", point, err)
			}
			assertTenantFileSetContainsOnlyOldOrNew(t, plan, old)
			if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
				t.Fatalf("reconcile after %s: %v", point, err)
			}
			assertTenantFileSetMatchesPlan(t, plan)
			assertTenantFileTransactionClean(t, plan)
		})
	}
}

func TestTenantFileTransactionRecoversInitiallyAbsentTargetsAtEveryInterruption(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	probe, _ := makeTenantFileTransactionTestPlan(t, filepath.Join(t.TempDir(), "probe"), "new")
	expectedPoints := tenantFileTransactionFaultPoints(probe, false)
	for _, point := range expectedPoints {
		t.Run(strings.ReplaceAll(point, ":", "_"), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "initial")
			plan, _ := makeTenantFileTransactionTestPlan(t, root, "new")
			err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt(point))
			if !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("fault point %s did not interrupt initial publication: %v", point, err)
			}
			for _, entry := range plan.Entries {
				payload, readErr := os.ReadFile(entry.Target)
				if readErr == nil && !slices.Equal(payload, entry.Payload) {
					t.Fatalf("initial target %s contains unintended content: %q", entry.Name, payload)
				}
				if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("inspect interrupted initial target %s: %v", entry.Name, readErr)
				}
			}
			if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
				t.Fatalf("reconcile initial publication after %s: %v", point, err)
			}
			assertTenantFileSetMatchesPlan(t, plan)
			assertTenantFileTransactionClean(t, plan)
		})
	}
}

func TestTenantFileTransactionSecurelyCreatesMissingDropInDirectory(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := filepath.Join(t.TempDir(), "initial")
	plan, _ := makeTenantFileTransactionTestPlan(t, root, "new")
	dropIn := filepath.Dir(plan.Entries[0].Target)
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
		t.Fatalf("publish through securely created drop-in directory: %v", err)
	}
	assertTenantFileSetMatchesPlan(t, plan)
	assertTenantFileTransactionClean(t, plan)
	var stat unix.Stat_t
	if err := unix.Lstat(dropIn, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o777 != 0o755 {
		t.Fatalf("created drop-in directory metadata is unsafe: stat=%+v err=%v", stat, err)
	}
}

func TestTenantFileTransactionFinishesPendingIntentBeforeNewRequest(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := filepath.Join(t.TempDir(), "transaction")
	first, old := makeTenantFileTransactionTestPlan(t, root, "first")
	installTenantFileTransactionTestState(t, old)
	err := publishTenantFileSet(context.Background(), first, stopTenantFileTransactionAt("file-publish-durable:resources"))
	if !errors.Is(err, errTenantFileTestCrash) {
		t.Fatalf("first transaction did not stop mid-commit: %v", err)
	}
	second, _ := makeTenantFileTransactionTestPlan(t, root, "second")
	if err := publishTenantFileSet(context.Background(), second, nil); err != nil {
		t.Fatalf("publish replacement after pending transaction: %v", err)
	}
	assertTenantFileSetMatchesPlan(t, second)
	assertTenantFileTransactionClean(t, second)

	third, _ := makeTenantFileTransactionTestPlan(t, root, "third")
	err = publishTenantFileSet(context.Background(), third, stopTenantFileTransactionAt("file-published:identity"))
	if !errors.Is(err, errTenantFileTestCrash) {
		t.Fatalf("third transaction did not stop mid-commit: %v", err)
	}
	rollback, _ := makeTenantFileTransactionTestPlan(t, root, "second")
	if err := publishTenantFileSet(context.Background(), rollback, nil); err != nil {
		t.Fatalf("roll back requested state after pending transaction: %v", err)
	}
	assertTenantFileSetMatchesPlan(t, rollback)
	assertTenantFileTransactionClean(t, rollback)
}

func TestTenantFileTransactionIsIdempotentAndRepairsConfigACL(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := filepath.Join(t.TempDir(), "transaction")
	plan, _ := makeTenantFileTransactionTestPlan(t, root, "current")
	installTenantFileTransactionTestState(t, plan)
	var before unix.Stat_t
	if err := unix.Lstat(plan.Entries[0].Target, &before); err != nil {
		t.Fatal(err)
	}
	if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
		t.Fatalf("idempotent tenant file publication failed: %v", err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(plan.Entries[0].Target, &after); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("idempotent publication replaced an already exact tenant file")
	}
	assertTenantFileTransactionClean(t, plan)

	if err := setACL(context.Background(), plan.Entries[2].Target, "u:2:r--"); err != nil {
		t.Fatal(err)
	}
	if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
		t.Fatalf("repair tenant config ACL: %v", err)
	}
	assertTenantFileSetMatchesPlan(t, plan)
	if _, err := posixacl.UserPermissions(plan.Entries[2].Target, 2); err == nil {
		t.Fatal("transaction retained an unexpected tenant config ACL principal")
	}
}

func TestTenantFileTransactionRejectsUnsafeJournalMetadata(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	mutations := map[string]func(*testing.T, tenantFileSetPlan){
		"symlink": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			if err := os.Remove(plan.JournalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(plan.Entries[0].Stage, plan.JournalPath); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			if err := os.Link(plan.JournalPath, plan.JournalPath+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"writable mode": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			if err := os.Chmod(plan.JournalPath, 0o620); err != nil {
				t.Fatal(err)
			}
		},
		"foreign owner": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			if err := os.Chown(plan.JournalPath, 1, 1); err != nil {
				t.Fatal(err)
			}
		},
		"unknown field": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			payload, err := os.ReadFile(plan.JournalPath)
			if err != nil {
				t.Fatal(err)
			}
			payload = append([]byte(`{"unexpected":true,"wrapped":`), append(payload[:len(payload)-1], '}', '\n')...)
			if err := os.WriteFile(plan.JournalPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"foreign target": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			journal := readTenantFileTestJournal(t, plan.JournalPath)
			journal.Entries[0].Target = "/etc/passwd"
			writeTenantFileTestJournal(t, plan.JournalPath, journal)
		},
		"forged desired hash": func(t *testing.T, plan tenantFileSetPlan) {
			t.Helper()
			journal := readTenantFileTestJournal(t, plan.JournalPath)
			journal.Entries[0].Desired.SHA256 = strings.Repeat("0", 64)
			writeTenantFileTestJournal(t, plan.JournalPath, journal)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "transaction")
			plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
			installTenantFileTransactionTestState(t, old)
			if err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt("journal-durable")); !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("create pending transaction: %v", err)
			}
			mutate(t, plan)
			if err := publishTenantFileSet(context.Background(), plan, nil); err == nil {
				t.Fatal("unsafe journal metadata was accepted")
			}
			assertTenantFileSetMatchesPlan(t, old)
		})
	}
}

func TestTenantFileTransactionRejectsUnsafeStagesAndTargets(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	for name, mutate := range map[string]func(*testing.T, tenantFileSetPlan){
		"stage symlink": func(t *testing.T, plan tenantFileSetPlan) {
			if err := os.Symlink(plan.Entries[0].Target, plan.Entries[0].Stage); err != nil {
				t.Fatal(err)
			}
		},
		"stage hardlink": func(t *testing.T, plan tenantFileSetPlan) {
			if _, err := prepareJournalBoundTenantFileStage(context.Background(), plan.Entries[0], nil); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(plan.Entries[0].Stage, plan.Entries[0].Stage+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"stage wrong payload prefix": func(t *testing.T, plan tenantFileSetPlan) {
			if err := os.WriteFile(plan.Entries[0].Stage, []byte("foreign\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(plan.Entries[0].Stage, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "transaction")
			plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
			installTenantFileTransactionTestState(t, old)
			if err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt("journal-durable")); !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("create pending transaction: %v", err)
			}
			mutate(t, plan)
			if err := publishTenantFileSet(context.Background(), plan, nil); err == nil {
				t.Fatal("unsafe staged inode was accepted")
			}
			assertTenantFileSetMatchesPlan(t, old)
		})
	}

	for name, mutate := range map[string]func(*testing.T, tenantFileIntent){
		"target symlink": func(t *testing.T, entry tenantFileIntent) {
			if err := os.Remove(entry.Target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", entry.Target); err != nil {
				t.Fatal(err)
			}
		},
		"target hardlink": func(t *testing.T, entry tenantFileIntent) {
			if err := os.Link(entry.Target, entry.Target+".link"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "transaction")
			plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
			installTenantFileTransactionTestState(t, old)
			mutate(t, plan.Entries[0])
			if err := publishTenantFileSet(context.Background(), plan, nil); err == nil {
				t.Fatal("unsafe target inode was accepted")
			}
		})
	}
}

func TestTenantFileTransactionRejectsCASDivergence(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := filepath.Join(t.TempDir(), "transaction")
	plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
	installTenantFileTransactionTestState(t, old)
	if err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt("journal-durable")); !errors.Is(err, errTenantFileTestCrash) {
		t.Fatalf("create pending transaction: %v", err)
	}
	replacement := plan.Entries[0].Target + ".external"
	if err := os.WriteFile(replacement, []byte("external\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(replacement, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, plan.Entries[0].Target); err != nil {
		t.Fatal(err)
	}
	if err := publishTenantFileSet(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "CAS mismatch") {
		t.Fatalf("external target divergence was not rejected: %v", err)
	}
	payload, err := os.ReadFile(plan.Entries[0].Target)
	if err != nil || string(payload) != "external\n" {
		t.Fatalf("CAS failure overwrote the external state: %q, %v", payload, err)
	}
}

func TestTenantFileTransactionNeverDeletesUnboundReservedResidue(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	for _, residue := range []string{"journal temporary", "stage"} {
		t.Run(residue, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "transaction")
			plan, old := makeTenantFileTransactionTestPlan(t, root, "new")
			installTenantFileTransactionTestState(t, old)
			path := plan.JournalPath + ".tmp"
			if residue == "stage" {
				path = plan.Entries[0].Stage
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := publishTenantFileSet(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "unbound") {
				t.Fatalf("unbound reserved residue was accepted: %v", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("unbound reserved residue was deleted: %v", err)
			}
			assertTenantFileSetMatchesPlan(t, old)
		})
	}
}

func TestTenantFileAnonymousJournalPreLinkCrashLeavesNoVisibleResidue(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	for _, point := range []string{
		"journal-anonymous-created",
		"journal-anonymous-write-started",
		"journal-anonymous-written",
		"journal-anonymous-synced",
	} {
		t.Run(point, func(t *testing.T) {
			plan, old := makeTenantFileTransactionTestPlan(t, filepath.Join(t.TempDir(), "transaction"), "new")
			installTenantFileTransactionTestState(t, old)
			if err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt(point)); !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("pre-link interruption %s did not fire: %v", point, err)
			}
			assertTenantFileTransactionClean(t, plan)
			assertTenantFileSetMatchesPlan(t, old)
			if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
				t.Fatalf("retry after %s: %v", point, err)
			}
			assertTenantFileSetMatchesPlan(t, plan)
		})
	}
}

func TestTenantFileTransactionRecoversArbitraryJournalBoundWorkBytes(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	for name, payload := range map[string][]byte{
		"empty":       nil,
		"non-prefix":  []byte("foreign dirty blocks\x00\xff"),
		"zero-filled": make([]byte, 64*1024),
	} {
		t.Run(name, func(t *testing.T) {
			plan, old := makeTenantFileTransactionTestPlan(t, filepath.Join(t.TempDir(), "transaction"), "new")
			installTenantFileTransactionTestState(t, old)
			if err := publishTenantFileSet(context.Background(), plan, stopTenantFileTransactionAt("journal-durable")); !errors.Is(err, errTenantFileTestCrash) {
				t.Fatalf("create durable intent journal: %v", err)
			}
			stage := plan.Entries[0].Stage
			if err := os.WriteFile(stage, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stage, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(stage, 0, 0); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(stage, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			clearErr := clearTenantFileACL(fd)
			closeErr := unix.Close(fd)
			if clearErr != nil || closeErr != nil {
				t.Fatalf("normalize injected work inode: clear=%v close=%v", clearErr, closeErr)
			}
			if err := publishTenantFileSet(context.Background(), plan, nil); err != nil {
				t.Fatalf("recover arbitrary durable work bytes: %v", err)
			}
			assertTenantFileSetMatchesPlan(t, plan)
			assertTenantFileTransactionClean(t, plan)
		})
	}
}

func TestTenantFileCapabilityFailurePrecedesEveryDirectoryMutation(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	plan, _ := makeTenantFileTransactionTestPlan(t, filepath.Join(t.TempDir(), "transaction"), "new")
	dropIn := filepath.Dir(plan.Entries[0].Target)
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	probeErr := errors.New("simulated O_TMPFILE unavailable")
	err := publishTenantFileSetWithProbe(context.Background(), plan, nil, func(tenantFileSetPlan) error {
		return probeErr
	})
	if !errors.Is(err, probeErr) {
		t.Fatalf("capability failure was not returned: %v", err)
	}
	if _, err := os.Lstat(dropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("capability failure left a drop-in directory mutation: %v", err)
	}
	assertTenantFileTransactionClean(t, plan)
}

func TestTenantFileTransactionRejectsSymlinkedParentComponent(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.MkdirAll(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	plan, _ := makeTenantFileTransactionTestPlan(t, filepath.Join(linkParent, "nested"), "new")
	if err := publishTenantFileSet(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "symbolic-link component") {
		t.Fatalf("symlinked transaction parent was not rejected: %v", err)
	}
}

func TestTenantFileDirectoryCreationFsyncsEachNewChildAndParent(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "first", "second")
	type inode struct{ dev, ino uint64 }
	var synced []inode
	syncFD := func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		synced = append(synced, inode{stat.Dev, stat.Ino})
		return unix.Fsync(fd)
	}
	if err := validateTenantFileDirectoryAncestry(root, target); err != nil {
		t.Fatalf("prevalidate missing protected directory: %v", err)
	}
	if err := ensureTenantFileDirectory(root, target, syncFD); err != nil {
		t.Fatalf("create protected directory: %v", err)
	}
	statInode := func(path string) inode {
		t.Helper()
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o777 != 0o755 {
			t.Fatalf("created directory %s has unsafe metadata: mode=%#o uid=%d", path, stat.Mode&0o7777, stat.Uid)
		}
		return inode{stat.Dev, stat.Ino}
	}
	first := statInode(filepath.Join(root, "first"))
	second := statInode(target)
	want := []inode{first, statInode(root), second, first}
	if !slices.Equal(synced, want) {
		t.Fatalf("directory durability order = %+v, want child/parent per creation %+v", synced, want)
	}
	synced = nil
	if err := ensureTenantFileDirectory(root, target, syncFD); err != nil {
		t.Fatalf("revalidate existing protected directory: %v", err)
	}
	if !slices.Equal(synced, want) {
		t.Fatalf("retry did not re-establish parent durability: got %+v want %+v", synced, want)
	}
}

func TestTenantFileDirectoryValidationDoesNotMutateEarlierValidPath(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := t.TempDir()
	validRoot := filepath.Join(root, "valid")
	outside := filepath.Join(root, "outside")
	for _, path := range []string{validRoot, outside} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	invalidRoot := filepath.Join(root, "invalid-root")
	if err := os.Symlink(outside, invalidRoot); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(validRoot, "must-not-be-created")
	plan := tenantFileSetPlan{
		TenantID:    "11111111-1111-4111-8111-111111111111",
		JournalPath: filepath.Join(missing, ".workagent-tenant-files.transaction.json"),
		Entries: []tenantFileIntent{
			{Name: tenantFileIdentity, ProtectedRoot: validRoot, Target: filepath.Join(missing, "identity.conf"), Stage: filepath.Join(missing, "identity.conf.workagent-stage"), Payload: []byte("identity\n"), Mode: 0o644},
			{Name: tenantFileResources, ProtectedRoot: validRoot, Target: filepath.Join(missing, "resources.conf"), Stage: filepath.Join(missing, "resources.conf.workagent-stage"), Payload: []byte("resources\n"), Mode: 0o644},
			{Name: tenantFileConfig, ProtectedRoot: invalidRoot, Target: filepath.Join(invalidRoot, "tenant.json"), Stage: filepath.Join(invalidRoot, "tenant.json.workagent-stage"), Payload: []byte("config\n"), Mode: 0o640, GID: 1, ACLUser: 1},
		},
	}
	if err := validateTenantFileSetPlan(plan); err != nil {
		t.Fatalf("test plan is invalid before ancestry validation: %v", err)
	}
	if err := prepareTenantFileDirectories(plan, unix.Fsync); err == nil {
		t.Fatal("symlinked later protected root was accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an earlier valid plan path was mutated before all ancestry validation: %v", err)
	}
}

func TestTenantFileDirectoryCreationNeverTraversesSymlink(t *testing.T) {
	requireTenantFileTransactionTestHost(t)
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := ensureTenantFileDirectory(root, filepath.Join(root, "link", "child"), unix.Fsync); err == nil {
		t.Fatal("symlinked tenant directory ancestry was accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "child")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory was created through a rejected symbolic link: %v", err)
	}
}

func makeTenantFileTransactionTestPlan(t *testing.T, root, version string) (tenantFileSetPlan, tenantFileSetPlan) {
	t.Helper()
	dropIn := filepath.Join(root, "systemd", "workagent-userhost@11111111-1111-4111-8111-111111111111.service.d")
	configs := filepath.Join(root, "configs")
	for _, directory := range []string{dropIn, configs} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(directory, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	identity := filepath.Join(dropIn, "identity.conf")
	resources := filepath.Join(dropIn, "resources.conf")
	configPath := filepath.Join(configs, "11111111-1111-4111-8111-111111111111.json")
	systemdRoot := filepath.Join(root, "systemd")
	makePlan := func(label string) tenantFileSetPlan {
		return tenantFileSetPlan{
			TenantID:    "11111111-1111-4111-8111-111111111111",
			JournalPath: filepath.Join(dropIn, ".workagent-tenant-files.transaction.json"),
			Entries: []tenantFileIntent{
				{Name: tenantFileIdentity, ProtectedRoot: systemdRoot, Target: identity, Stage: identity + ".workagent-stage", Payload: []byte(label + "-identity\n"), Mode: 0o644, UID: 0, GID: 0},
				{Name: tenantFileResources, ProtectedRoot: systemdRoot, Target: resources, Stage: resources + ".workagent-stage", Payload: []byte(label + "-resources\n"), Mode: 0o644, UID: 0, GID: 0},
				{Name: tenantFileConfig, ProtectedRoot: configs, Target: configPath, Stage: configPath + ".workagent-stage", Payload: []byte(label + "-config\n"), Mode: 0o640, UID: 0, GID: 1, ACLUser: 1},
			},
		}
	}
	return makePlan(version), makePlan("old")
}

func installTenantFileTransactionTestState(t *testing.T, plan tenantFileSetPlan) {
	t.Helper()
	for _, entry := range plan.Entries {
		if _, err := prepareTenantFileStage(context.Background(), entry, nil); err != nil {
			t.Fatal(err)
		}
		if err := unix.Renameat2(unix.AT_FDCWD, entry.Stage, unix.AT_FDCWD, entry.Target, unix.RENAME_NOREPLACE); err != nil {
			t.Fatal(err)
		}
		if err := syncTenantFileDirectory(filepath.Dir(entry.Target)); err != nil {
			t.Fatal(err)
		}
	}
}

func stopTenantFileTransactionAt(want string) tenantFileFaultHook {
	return func(point string) error {
		if point == want {
			return errTenantFileTestCrash
		}
		return nil
	}
}

func tenantFileTransactionFaultPoints(plan tenantFileSetPlan, displacedPreState bool) []string {
	points := []string{
		"journal-anonymous-created",
		"journal-anonymous-write-started",
		"journal-anonymous-written",
		"journal-anonymous-synced",
		"journal-linked",
		"journal-linked-verified",
		"journal-durable",
	}
	for _, entry := range plan.Entries {
		points = append(points,
			"stage-anonymous-created:"+entry.Name,
			"stage-work-synced:"+entry.Name,
		)
		for index := range entry.Payload {
			points = append(points, fmt.Sprintf("stage-write-byte:%s:%d", entry.Name, index+1))
		}
		points = append(points,
			"stage-content-synced:"+entry.Name,
			"stage-final-owner:"+entry.Name,
			"stage-final-acl:"+entry.Name,
			"stage-final-mode:"+entry.Name,
			"stage-final-synced:"+entry.Name,
			"stage-linked:"+entry.Name,
			"stage-linked-verified:"+entry.Name,
			"stage-durable:"+entry.Name,
			"file-published:"+entry.Name,
			"file-publish-durable:"+entry.Name,
		)
		if displacedPreState {
			points = append(points, "stage-removed:"+entry.Name, "stage-removal-durable:"+entry.Name)
		}
	}
	return append(points, "journal-removed", "transaction-complete")
}

func assertTenantFileSetContainsOnlyOldOrNew(t *testing.T, current, old tenantFileSetPlan) {
	t.Helper()
	for index, entry := range current.Entries {
		payload, err := os.ReadFile(entry.Target)
		if err != nil {
			t.Fatalf("read target %s after interruption: %v", entry.Name, err)
		}
		if !slices.Equal(payload, entry.Payload) && !slices.Equal(payload, old.Entries[index].Payload) {
			t.Fatalf("target %s contains neither old nor new content: %q", entry.Name, payload)
		}
	}
}

func assertTenantFileSetMatchesPlan(t *testing.T, plan tenantFileSetPlan) {
	t.Helper()
	for _, entry := range plan.Entries {
		state, payload, err := inspectTenantFile(entry.Target, tenantFileMaximumSize)
		if err != nil {
			t.Fatalf("inspect target %s: %v", entry.Name, err)
		}
		matched, err := tenantFileStateMatchesIntent(entry.Target, state, entry)
		if err != nil || !matched || !slices.Equal(payload, entry.Payload) {
			t.Fatalf("target %s does not match requested state: state=%+v payload=%q err=%v", entry.Name, state, payload, err)
		}
	}
	if err := posixacl.VerifyExclusiveUserPermissions(plan.Entries[2].Target, plan.Entries[2].ACLUser, 0o4); err != nil {
		t.Fatalf("tenant config ACL drifted: %v", err)
	}
}

func assertTenantFileTransactionClean(t *testing.T, plan tenantFileSetPlan) {
	t.Helper()
	paths := []string{plan.JournalPath, plan.JournalPath + ".tmp"}
	for _, entry := range plan.Entries {
		paths = append(paths, entry.Stage)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction residue remains at %s: %v", path, err)
		}
	}
}

func readTenantFileTestJournal(t *testing.T, path string) tenantFileJournal {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var journal tenantFileJournal
	if err := json.Unmarshal(payload, &journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

func writeTenantFileTestJournal(t *testing.T, path string, journal tenantFileJournal) {
	t.Helper()
	payload, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func requireTenantFileTransactionTestHost(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership is required for tenant file transaction tests")
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl is unavailable")
	}
}
