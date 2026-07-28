//go:build linux

package deployassets

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

type frozenTreeEntry struct {
	Path   string
	Type   string
	Mode   uint32
	UID    uint32
	GID    uint32
	SHA256 string
}

func thawFixtureForCleanup(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else if entry.Type().IsRegular() {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
}

func createModeFreezeFixture(t *testing.T, parent, mask string) string {
	t.Helper()
	root := filepath.Join(parent, "tree")
	command := exec.Command("/bin/bash", "-c", `
set -euo pipefail
mask=$1
root=$2
umask "$mask"
mkdir -p -- "$root/bin" "$root/share/nested"
printf '%s\n' '#!/bin/sh' 'echo fixture' > "$root/bin/app"
chmod u+x -- "$root/bin/app"
printf '%s\n' 'ordinary' > "$root/README"
printf '%s\n' 'nested' > "$root/share/nested/data.txt"
`, "mode-fixture", mask, root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create mode-freeze fixture: %v\n%s", err, output)
	}
	t.Cleanup(func() { thawFixtureForCleanup(root) })
	return root
}

func runModeFreeze(t *testing.T, mask, profile, root, manifest string, executables ...string) ([]byte, error) {
	t.Helper()
	helper := filepath.Join(repositoryRoot(t), "scripts", "freeze-release-tree-modes.sh")
	arguments := []string{"-c", `
set -euo pipefail
mask=$1
shift
umask "$mask"
exec "$@"
	`, "mode-freeze", mask, helper, "freeze", profile, root, manifest}
	arguments = append(arguments, executables...)
	return exec.Command("/bin/bash", arguments...).CombinedOutput()
}

func runModeVerify(t *testing.T, profile, root, manifest string, executables ...string) ([]byte, error) {
	t.Helper()
	helper := filepath.Join(repositoryRoot(t), "scripts", "freeze-release-tree-modes.sh")
	arguments := []string{"verify", profile, root, manifest}
	arguments = append(arguments, executables...)
	return exec.Command(helper, arguments...).CombinedOutput()
}

func runContentInventory(t *testing.T, operation, root string) ([]byte, error) {
	t.Helper()
	helper := filepath.Join(repositoryRoot(t), "scripts", "release-tree-sha256.sh")
	return exec.Command(helper, operation, root).CombinedOutput()
}

func snapshotFrozenTree(t *testing.T, root string) []frozenTreeEntry {
	t.Helper()
	var entries []frozenTreeEntry
	err := filepath.WalkDir(root, func(path string, directoryEntry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("stat identity unavailable for %s", relative)
		}
		entry := frozenTreeEntry{Path: relative, Mode: uint32(info.Mode().Perm()), UID: stat.Uid, GID: stat.Gid}
		switch {
		case info.IsDir():
			entry.Type = "d"
		case info.Mode().IsRegular():
			entry.Type = "f"
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			hash := sha256.New()
			_, copyErr := io.Copy(hash, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		default:
			return fmt.Errorf("unsupported entry survived freeze: %s", relative)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

func assertFrozenModes(t *testing.T, entries []frozenTreeEntry, directoryMode, regularMode, executableMode uint32) {
	t.Helper()
	for _, entry := range entries {
		expected := regularMode
		if entry.Type == "d" {
			expected = directoryMode
		} else if entry.Path == "bin/app" {
			expected = executableMode
		}
		if entry.Mode != expected {
			t.Fatalf("mode for %s = %04o, want %04o", entry.Path, entry.Mode, expected)
		}
	}
}

func expectedTreeModeManifest(profile string, entries []frozenTreeEntry) []byte {
	records := make([]string, 0, len(entries))
	for _, entry := range entries {
		records = append(records, fmt.Sprintf("%s\t%04o\t%s", entry.Type, entry.Mode, entry.Path))
	}
	sort.Strings(records)
	return []byte("# workagent-release-tree-modes-v1 profile=" + profile + "\n" + strings.Join(records, "\n") + "\n")
}

func TestReleaseTreeModeFreezeIsIndependentOfParentUmask(t *testing.T) {
	type result struct {
		tree     []frozenTreeEntry
		manifest []byte
	}
	results := make(map[string]result)
	for _, mask := range []string{"022", "077"} {
		parent := t.TempDir()
		root := createModeFreezeFixture(t, parent, mask)
		manifest := filepath.Join(parent, "tree-modes.tsv")
		if output, err := runModeFreeze(t, mask, "public", root, manifest, "bin/app"); err != nil {
			t.Fatalf("freeze with umask %s: %v\n%s", mask, err, output)
		}
		payload, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("mode manifest mode = %04o, want 0400", info.Mode().Perm())
		}
		entries := snapshotFrozenTree(t, root)
		assertFrozenModes(t, entries, 0o555, 0o444, 0o555)
		if expected := expectedTreeModeManifest("public", entries); !reflect.DeepEqual(payload, expected) {
			t.Fatalf("mode manifest does not exactly cover the frozen tree:\ngot:\n%s\nwant:\n%s", payload, expected)
		}
		results[mask] = result{tree: entries, manifest: payload}
	}
	if !reflect.DeepEqual(results["022"].tree, results["077"].tree) {
		t.Fatalf("frozen type/mode/UID/GID/content trees differ:\n022=%#v\n077=%#v", results["022"].tree, results["077"].tree)
	}
	if !reflect.DeepEqual(results["022"].manifest, results["077"].manifest) {
		t.Fatalf("deterministic mode manifests differ:\n022=%s\n077=%s", results["022"].manifest, results["077"].manifest)
	}
}

func TestReleaseTreeModeFreezeRootOnlyProfile(t *testing.T) {
	parent := t.TempDir()
	root := createModeFreezeFixture(t, parent, "022")
	manifest := filepath.Join(parent, "tree-modes.tsv")
	if output, err := runModeFreeze(t, "022", "root-only", root, manifest, "bin/app"); err != nil {
		t.Fatalf("freeze root-only fixture: %v\n%s", err, output)
	}
	entries := snapshotFrozenTree(t, root)
	assertFrozenModes(t, entries, 0o500, 0o400, 0o500)
	payload, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if expected := expectedTreeModeManifest("root-only", entries); !reflect.DeepEqual(payload, expected) {
		t.Fatalf("root-only manifest does not exactly cover the frozen tree:\ngot:\n%s\nwant:\n%s", payload, expected)
	}
}

func TestReleaseTreeModeVerifyRejectsPostFreezeDrift(t *testing.T) {
	newFrozenTree := func(t *testing.T) (string, string) {
		t.Helper()
		parent := t.TempDir()
		root := createModeFreezeFixture(t, parent, "077")
		manifest := filepath.Join(parent, "tree-modes.tsv")
		if output, err := runModeFreeze(t, "077", "public", root, manifest, "bin/app"); err != nil {
			t.Fatalf("freeze fixture: %v\n%s", err, output)
		}
		if output, err := runModeVerify(t, "public", root, manifest, "bin/app"); err != nil {
			t.Fatalf("verify unchanged frozen fixture: %v\n%s", err, output)
		}
		return root, manifest
	}

	t.Run("ordinary file made executable", func(t *testing.T) {
		root, manifest := newFrozenTree(t)
		if err := os.Chmod(filepath.Join(root, "README"), 0o555); err != nil {
			t.Fatal(err)
		}
		if output, err := runModeVerify(t, "public", root, manifest, "bin/app"); err == nil || !strings.Contains(string(output), "executable outside the allowlist") {
			t.Fatalf("post-freeze executable drift was not rejected precisely: err=%v output=%s", err, output)
		}
	})

	t.Run("same-content external hardlink substitution", func(t *testing.T) {
		root, manifest := newFrozenTree(t)
		outside := filepath.Join(filepath.Dir(root), "outside-copy")
		if err := os.WriteFile(outside, []byte("ordinary\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "README")); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(root, "README")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o555); err != nil {
			t.Fatal(err)
		}
		if output, err := runModeVerify(t, "public", root, manifest, "bin/app"); err == nil || !strings.Contains(string(output), "multiply-linked file") {
			t.Fatalf("post-freeze hardlink substitution was not rejected precisely: err=%v output=%s", err, output)
		}
	})

	t.Run("mode manifest tampering", func(t *testing.T) {
		root, manifest := newFrozenTree(t)
		if err := os.Chmod(manifest, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, []byte("tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manifest, 0o400); err != nil {
			t.Fatal(err)
		}
		if output, err := runModeVerify(t, "public", root, manifest, "bin/app"); err == nil || !strings.Contains(string(output), "does not exactly match") {
			t.Fatalf("mode manifest tampering was not rejected precisely: err=%v output=%s", err, output)
		}
	})
}

func TestReleaseTreeContentInventoryIsCompleteAndFailClosed(t *testing.T) {
	parent := t.TempDir()
	root := createModeFreezeFixture(t, parent, "077")
	if output, err := runContentInventory(t, "write", root); err != nil {
		t.Fatalf("write complete content inventory: %v\n%s", err, output)
	}
	manifest := filepath.Join(root, "SHA256SUMS")
	payload, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(payload), "\n"); lines != 3 {
		t.Fatalf("content inventory has %d entries, want 3: %s", lines, payload)
	}
	if output, err := runContentInventory(t, "verify", root); err != nil {
		t.Fatalf("verify unchanged content inventory: %v\n%s", err, output)
	}
	if output, err := runContentInventory(t, "write", root); err == nil || !strings.Contains(string(output), "SHA256SUMS destination already exists") {
		t.Fatalf("second inventory publication was not rejected precisely: err=%v output=%s", err, output)
	}

	extra := filepath.Join(root, "unlisted-ordinary-file")
	if err := os.WriteFile(extra, []byte("extra\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if output, err := runContentInventory(t, "verify", root); err == nil || !strings.Contains(string(output), "does not exactly cover the current regular-file inventory") {
		t.Fatalf("unlisted ordinary file was not rejected precisely: err=%v output=%s", err, output)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runContentInventory(t, "verify", root); err == nil || !strings.Contains(string(output), "does not exactly cover the current regular-file inventory") {
		t.Fatalf("changed content was not rejected precisely: err=%v output=%s", err, output)
	}
}

func TestReleaseTreeModeFreezeRejectsUnsafeOrIncompleteTrees(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(t *testing.T, root string)
		executables []string
		wantMessage string
	}{
		{
			name: "executable at wrong path",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				path := filepath.Join(root, "wrong-executable")
				if err := os.WriteFile(path, []byte("wrong\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree contains an executable outside the allowlist: wrong-executable",
		},
		{
			name: "missing executable",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "bin", "app")); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "allowlisted executable is missing, unsafe, or not executable: bin/app",
		},
		{
			name: "allowlisted file lacks execute mode",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "bin", "app"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "allowlisted executable is missing, unsafe, or not executable: bin/app",
		},
		{
			name:        "duplicate executable",
			prepare:     func(*testing.T, string) {},
			executables: []string{"bin/app", "bin/app"},
			wantMessage: "duplicate executable allowlist path: bin/app",
		},
		{
			name:        "path traversal",
			prepare:     func(*testing.T, string) {},
			executables: []string{"bin/../bin/app"},
			wantMessage: "non-canonical relative path",
		},
		{
			name: "symlink",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Symlink("../README", filepath.Join(root, "share", "link")); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree contains a symlink or special entry",
		},
		{
			name: "special file",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree contains a symlink or special entry",
		},
		{
			name: "setuid executable",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "bin", "app"), 0o700|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree entry has setuid, setgid, or sticky mode bits: bin/app",
		},
		{
			name: "sticky directory",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, "share"), 0o700|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree entry has setuid, setgid, or sticky mode bits: share",
		},
		{
			name: "setgid tree root",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(root, 0o700|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree root has setuid, setgid, or sticky mode bits",
		},
		{
			name: "hardlink inside tree",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Link(filepath.Join(root, "README"), filepath.Join(root, "share", "README.hardlink")); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree contains a multiply-linked file:",
		},
		{
			name: "hardlink outside tree",
			prepare: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Link(filepath.Join(root, "README"), filepath.Join(filepath.Dir(root), "outside.hardlink")); err != nil {
					t.Fatal(err)
				}
			},
			executables: []string{"bin/app"},
			wantMessage: "tree contains a multiply-linked file: README",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			root := createModeFreezeFixture(t, parent, "077")
			test.prepare(t, root)
			manifest := filepath.Join(parent, "tree-modes.tsv")
			output, err := runModeFreeze(t, "077", "public", root, manifest, test.executables...)
			if err == nil {
				t.Fatalf("unsafe tree was accepted:\n%s", output)
			}
			if !strings.Contains(string(output), test.wantMessage) {
				t.Fatalf("unexpected rejection; want %q:\n%s", test.wantMessage, output)
			}
			if _, err := os.Lstat(manifest); !os.IsNotExist(err) {
				t.Fatalf("failed freeze published a mode manifest: %v", err)
			}
		})
	}
}

func bashArray(t *testing.T, source, name string) []string {
	t.Helper()
	startMarker := name + "=(\n"
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing Bash array %s", name)
	}
	start += len(startMarker)
	end := strings.Index(source[start:], "\n)")
	if end < 0 {
		t.Fatalf("unterminated Bash array %s", name)
	}
	return strings.Fields(source[start : start+end])
}

func TestSourceGateFreezesAndBindsExactReleaseTreeModes(t *testing.T) {
	source := repositoryFile(t, "scripts/source-gate.sh")
	for _, required := range []string{
		"umask 0077",
		`"schema_version": 2`,
		`"content_manifest_version": 1`,
		`"tree_mode_manifest_version": 1`,
		`"$mode_freeze_helper" freeze public "$artifact_directory/control-plane"`,
		`"$mode_freeze_helper" verify public "$artifact_directory/control-plane"`,
		`"$binary_directory/workagent-release" validate-layout`,
		`--root "$artifact_directory/control-plane" --profile public`,
		"control-plane.tree-modes.tsv",
		`"$content_manifest_helper" write "$artifact_directory/control-plane"`,
		`"$content_manifest_helper" verify "$artifact_directory/control-plane"`,
		`$package != github.com/linziyan1231-source/WorkAgent2/linux/internal/release`,
		`$go_binary test -count=1 "${nonroot_packages[@]}"`,
		`$go_binary test -count=1 -race "${nonroot_packages[@]}"`,
		`run_go_tests_as_production_owner -count=1 ./...`,
		`run_go_tests_as_production_owner -count=1 -race ./...`,
		`GOPROXY=off`,
		`GOSUMDB=off`,
		`export GOENV=off`,
		`export GO111MODULE=on`,
		`export GOWORK=off`,
		`export GOOS=linux`,
		`export GOARCH=amd64`,
		`export GOAMD64=v1`,
		`export GOEXPERIMENT=`,
		`export GOFIPS140=off`,
		`export GIT_CONFIG_GLOBAL=/dev/null`,
		`export GIT_CONFIG_NOSYSTEM=1`,
		`export GIT_ATTR_NOSYSTEM=1`,
		`unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT`,
		`govulncheck_version_output=$("$govulncheck_binary" -version)`,
		`shellcheck_version_output=$("$shellcheck_binary" --version)`,
		`grep -Fq 'v1.6.0' <<< "$govulncheck_version_output"`,
		`grep -Fq 'version: 0.11.0' <<< "$shellcheck_version_output"`,
		`GIT_OBJECT_DIRECTORY`,
		`GIT_ALTERNATE_OBJECT_DIRECTORIES`,
		`source_gate_cache_root=$(mktemp -d /tmp/workagent-source-gate-go-cache.XXXXXX)`,
		`export GOCACHE="$source_gate_cache_root/test"`,
		`export GOCACHE="$source_gate_cache_root/build"`,
		`EXPECTED_SOURCE_REVISION`,
		`GIT_INDEX_FILE=$clean_index git --git-dir="$object_repository" --work-tree="$repo_root"`,
		`status --porcelain=v1 --untracked-files=all -- . ':(top,literal,exclude).git'`,
		`require_empty_artifact_directory`,
		`object_repository=$(mktemp -d /tmp/workagent-source-gate-objects.XXXXXX)`,
		`git -c fetch.fsckObjects=true --git-dir="$object_repository"`,
		`git --git-dir="$object_repository" update-ref --no-deref HEAD "$source_revision"`,
		`prepare_locked_tree_inventory`,
		`if ! git ls-files -z -- '*.bash' '*.sh' \`,
		`'deploy/libexec/workagent-core-activation-admission-v1' \`,
		`'deploy/libexec/workagent-edge-publication-admission-v1' \`,
		`'deploy/libexec/workagent-fixed-root-exec-v1' \`,
		`'deploy/libexec/workagent-recovery-activation-admission-v1' > "$shell_file_inventory"`,
		`ls-tree -r -t -z --full-tree "$source_revision" > "$temporary"`,
		`done < "$locked_tree_inventory"`,
		`--template="$empty_git_template"`,
		`git --git-dir="$object_repository" cat-file blob "$object_id" > "$path"`,
		`actual_object=$(git --git-dir="$object_repository" hash-object --no-filters -- "$path")`,
		`materialize_locked_tree "$test_snapshot" true`,
		`verify_materialized_snapshot "$test_snapshot" "clean test" true`,
		`verify_build_snapshot`,
		`local -A expected_specs=(`,
		`verify_artifact_envelope false`,
		`verify_artifact_envelope true`,
		`SOURCE_GATE_MODE must be quality or artifact`,
		`verify_materialized_snapshot "$snapshot" "source evidence after scanners" false`,
		`QUALITY_GATE_SOURCE_REVISION`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("source gate does not enforce %q", required)
		}
	}
	for _, forbidden := range []string{`git clone`, `git -C "$repo_root" archive`, `git checkout`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("source gate still uses attribute/filter-sensitive Git source materialization %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		`$govulncheck_binary -version | grep`,
		`$shellcheck_binary --version | grep`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("source gate uses a SIGPIPE-prone short-circuiting version pipeline %q", forbidden)
		}
	}
	wantControl := []string{
		"admin/install-core-activation-admission-v1", "admin/install-edge-publication-admission-v1", "admin/install-fixed-root-exec-v1", "admin/install-recovery-activation-admission-v1", "admin/production-host-prepare", "admin/production-preflight", "admin/smoke-chatforward-browser-sandbox", "admin/verify-host-rpms",
		"bin/workagent-admin", "bin/workagent-backup", "bin/workagent-cliproxy", "bin/workagent-healthcheck",
		"bin/workagent-notification", "bin/workagent-portal", "bin/workagent-provision", "bin/workagent-release", "bin/workagent-secret", "bin/workagent-userhost",
		"share/deploy/libexec/workagent-core-activation-admission-v1", "share/deploy/libexec/workagent-edge-publication-admission-v1", "share/deploy/libexec/workagent-fixed-root-exec-v1",
		"share/deploy/libexec/workagent-recovery-activation-admission-v1",
	}
	if got := bashArray(t, source, "control_executables"); !reflect.DeepEqual(got, wantControl) {
		t.Fatalf("control executable allowlist drifted:\ngot  %q\nwant %q", got, wantControl)
	}
	wantGoControl := []string{
		"workagent-admin", "workagent-backup", "workagent-cliproxy", "workagent-notification",
		"workagent-portal", "workagent-provision", "workagent-release", "workagent-secret", "workagent-userhost",
	}
	if got := bashArray(t, source, "go_control_commands"); !reflect.DeepEqual(got, wantGoControl) {
		t.Fatalf("Go control build-info set drifted: got %q want %q", got, wantGoControl)
	}
	for _, required := range []string{
		`verify_go_build_identity() {`,
		`$go_binary version -m "$binary_path"`,
		`verify_go_build_identity "$binary_directory/$command" "$command"`,
		`local expected_main_path=github.com/linziyan1231-source/WorkAgent2/linux/cmd/$evidence_label`,
		`$2 == "path" { path_keys++; if ($3 == expected_path) path_matches++ }`,
		`index($3, "vcs=") == 1`,
		`$3 == "vcs=git"`,
		`index($3, "vcs.revision=") == 1`,
		`$3 == "vcs.revision=" revision`,
		`index($3, "vcs.modified=") == 1`,
		`$3 == "vcs.modified=false"`,
		`$vcs_keys != 1 || $vcs_matches != 1 || $revision_keys != 1 || $revision_matches != 1`,
		`$path_keys != 1 || $path_matches != 1`,
		`$modified_keys != 1 || $modified_matches != 1`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("source gate omits exact Go build identity check %q", required)
		}
	}
	for invocation, label := range map[string]string{
		`verify_go_build_identity "$binary_directory/$command" "$command"`: "control",
	} {
		if strings.Count(source, invocation) != 2 {
			t.Fatalf("source gate must check %s Go build identities once before scanners and once before final evidence", label)
		}
	}
	moduleDownload := strings.Index(source, `$go_binary mod download all`)
	offlineBoundary := strings.Index(source, `export GOPROXY=off`)
	if moduleDownload < 0 || offlineBoundary < 0 || moduleDownload >= offlineBoundary {
		t.Fatal("source gate does not populate and verify its private module cache before going offline")
	}
	lockedRevision := strings.Index(source, `source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')`)
	rootTests := strings.Index(source, `run_go_tests_as_production_owner -count=1 ./...`)
	cleanMaterialization := strings.LastIndex(source, `materialize_locked_tree "$build_snapshot" true`)
	buildDirectory := strings.Index(source, `cd "$build_snapshot"`)
	firstArtifactBuild := strings.Index(source, `CGO_ENABLED=0 $go_binary build`)
	if lockedRevision < 0 || rootTests < 0 || cleanMaterialization < 0 || buildDirectory < 0 || firstArtifactBuild < 0 ||
		lockedRevision >= rootTests || rootTests >= cleanMaterialization || cleanMaterialization >= buildDirectory || buildDirectory >= firstArtifactBuild {
		t.Fatal("source gate does not lock the revision before tests and build only from the later direct-blob materialization")
	}
	indexAfter := func(needle string, offset int) int {
		if offset < 0 || offset >= len(source) {
			return -1
		}
		index := strings.Index(source[offset:], needle)
		if index < 0 {
			return -1
		}
		return offset + index
	}
	controlFreeze := strings.Index(source, `"$mode_freeze_helper" freeze public`)
	controlGitleaks := indexAfter(`$gitleaks_binary dir`, controlFreeze)
	if controlFreeze < 0 || controlGitleaks < 0 || controlFreeze >= controlGitleaks {
		t.Fatal("source gate does not freeze the payload before its final secret scan phase")
	}
	controlFinalModes := strings.LastIndex(source, `"$mode_freeze_helper" verify public`)
	controlFinalLayout := strings.LastIndex(source, `--root "$artifact_directory/control-plane" --profile public`)
	controlFinalContent := strings.LastIndex(source, `"$content_manifest_helper" verify "$artifact_directory/control-plane"`)
	controlFinalIdentity := strings.LastIndex(source, `verify_go_build_identity "$binary_directory/$command" "$command"`)
	evidenceStart := strings.LastIndex(source, "  sha256sum \\\n")
	evidenceEnd := strings.LastIndex(source, " > EVIDENCE.sha256")
	if evidenceStart < 0 || evidenceEnd <= evidenceStart {
		t.Fatal("source gate evidence hash block is missing")
	}
	if !(controlGitleaks < controlFinalModes && controlFinalModes < controlFinalLayout && controlFinalLayout < controlFinalContent && controlFinalContent < controlFinalIdentity && controlFinalIdentity < evidenceStart) {
		t.Fatal("source gate does not repeat complete layout and content verification after both scanner phases and before evidence publication")
	}
	evidenceBlock := source[evidenceStart:evidenceEnd]
	for _, manifest := range []string{"control-plane.tree-modes.tsv"} {
		if !strings.Contains(evidenceBlock, manifest) {
			t.Fatalf("EVIDENCE.sha256 does not bind %s", manifest)
		}
	}
}

func sourceGateGoBuildIdentityFunction(t *testing.T) string {
	t.Helper()
	source := repositoryFile(t, "scripts/source-gate.sh")
	start := strings.Index(source, "verify_go_build_identity() {")
	if start < 0 {
		t.Fatal("could not isolate source-gate Go build identity verifier")
	}
	endMarker := "\n}\n\nbinary_directory="
	end := strings.Index(source[start:], endMarker)
	if end < 0 {
		t.Fatal("source-gate Go build identity verifier is unterminated")
	}
	return source[start : start+end+2]
}

func TestSourceGateGoBuildIdentityVerifierRejectsAmbiguousOrDirtyEvidence(t *testing.T) {
	root := t.TempDir()
	fakeGo := filepath.Join(root, "go")
	if err := os.WriteFile(fakeGo, []byte(`#!/bin/bash
if [[ ${FAKE_GO_FAIL:-0} == 1 ]]; then
  exit 23
fi
[[ $1 == version && $2 == -m && $# == 3 ]] || exit 24
printf '%s' "${FAKE_GO_OUTPUT:-}"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(root, "verify-build-identity")
	harnessPayload := "#!/bin/bash\nset -u -o pipefail\n" + sourceGateGoBuildIdentityFunction(t) + `
go_binary=$1
source_revision=$2
verify_go_build_identity "$3" fixture-binary
`
	if err := os.WriteFile(harness, []byte(harnessPayload), 0o700); err != nil {
		t.Fatal(err)
	}
	revision := "1234567890abcdef1234567890abcdef12345678"
	exact := "fixture: go1.26.5\n\tpath\tgithub.com/linziyan1231-source/WorkAgent2/linux/cmd/fixture-binary\n\tbuild\tvcs=git\n\tbuild\tvcs.revision=" + revision + "\n\tbuild\tvcs.modified=false\n"
	run := func(payload string, fail bool) ([]byte, error) {
		command := exec.Command(harness, fakeGo, revision, filepath.Join(root, "fixture-binary"))
		failValue := "0"
		if fail {
			failValue = "1"
		}
		command.Env = []string{"LC_ALL=C", "FAKE_GO_OUTPUT=" + payload, "FAKE_GO_FAIL=" + failValue}
		return command.CombinedOutput()
	}
	if output, err := run(exact, false); err != nil {
		t.Fatalf("one exact clean Git identity was rejected: %v output=%s", err, output)
	}
	tests := []struct {
		name    string
		payload string
		failGo  bool
	}{
		{name: "missing modified", payload: strings.ReplaceAll(exact, "\tbuild\tvcs.modified=false\n", "")},
		{name: "dirty", payload: strings.ReplaceAll(exact, "vcs.modified=false", "vcs.modified=true")},
		{name: "wrong revision", payload: strings.ReplaceAll(exact, revision, strings.Repeat("f", 40))},
		{name: "swapped command package", payload: strings.ReplaceAll(exact, "cmd/fixture-binary", "cmd/workagent-portal")},
		{name: "duplicate main package", payload: exact + "\tpath\tgithub.com/linziyan1231-source/WorkAgent2/linux/cmd/fixture-binary\n"},
		{name: "duplicate key", payload: exact + "\tbuild\tvcs=git\n"},
		{name: "wrong VCS", payload: strings.ReplaceAll(exact, "vcs=git", "vcs=hg")},
		{name: "unreadable build info", payload: exact, failGo: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := run(test.payload, test.failGo)
			if err == nil {
				t.Fatalf("invalid build identity was accepted: %s", output)
			}
			if !strings.Contains(string(output), "fixture-binary") {
				t.Fatalf("identity rejection did not name its evidence label: %s", output)
			}
		})
	}
}

func sourceGateMaterializerFunctions(t *testing.T) string {
	t.Helper()
	source := repositoryFile(t, "scripts/source-gate.sh")
	start := strings.Index(source, "validate_source_relative_path() {")
	end := strings.Index(source, "\nverify_artifact_envelope() {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate the source-gate materializer functions")
	}
	return source[start:end]
}

func sourceGateCleanlinessFunction(t *testing.T) string {
	t.Helper()
	source := repositoryFile(t, "scripts/source-gate.sh")
	start := strings.Index(source, "require_clean_source() {")
	end := strings.Index(source, "\nrequire_empty_artifact_directory() {")
	if start < 0 || end <= start {
		t.Fatal("could not isolate the source-gate cleanliness function")
	}
	return source[start:end]
}

func runFixtureGit(t *testing.T, directory string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LC_ALL=C",
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_AUTHOR_NAME=WorkAgent Test",
		"GIT_AUTHOR_EMAIL=contact@example.invalid",
		"GIT_COMMITTER_NAME=WorkAgent Test",
		"GIT_COMMITTER_EMAIL=contact@example.invalid",
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return output
}

func writeSourceGateHarness(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "materializer-harness.sh")
	script := `#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_GRAFT_FILE \
  GIT_TEMPLATE_DIR GIT_EXEC_PATH GIT_REPLACE_REF_BASE GIT_EXTERNAL_DIFF GIT_DIFF_OPTS || true
for git_config_variable in ${!GIT_CONFIG_KEY_@} ${!GIT_CONFIG_VALUE_@}; do
  unset "$git_config_variable"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_ATTR_NOSYSTEM=1
export GIT_NO_REPLACE_OBJECTS=1
source_gate_uid=$(id -u)
source_gate_gid=$(id -g)
locked_tree_inventory=
` + sourceGateMaterializerFunctions(t) + "\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSourceGateCleanlinessHarness(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cleanliness-harness.sh")
	script := `#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_GRAFT_FILE \
  GIT_TEMPLATE_DIR GIT_EXEC_PATH GIT_REPLACE_REF_BASE GIT_EXTERNAL_DIFF GIT_DIFF_OPTS || true
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_ATTR_NOSYSTEM=1
export GIT_NO_REPLACE_OBJECTS=1
` + sourceGateCleanlinessFunction(t) + `
repo_root=$1
object_repository=$2
empty_git_template=$3
source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
git init --quiet --bare --template="$empty_git_template" -- "$object_repository"
git -c fetch.fsckObjects=true --git-dir="$object_repository" fetch --quiet --no-tags "$repo_root" HEAD
git --git-dir="$object_repository" update-ref refs/workagent/source "$source_revision"
git --git-dir="$object_repository" update-ref --no-deref HEAD "$source_revision"
require_clean_source
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSourceGateCleanlinessUsesLockedRawBytesAndRejectsUntrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	repository := filepath.Join(root, "source")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "init", "--quiet")
	runFixtureGit(t, repository, "config", "filter.hostile.clean", "sed s/FILTERED/LOCKED/g")
	runFixtureGit(t, repository, "config", "filter.hostile.smudge", "sed s/LOCKED/FILTERED/g")
	runFixtureGit(t, repository, "config", "filter.hostile.required", "true")
	for name, payload := range map[string]string{
		".gitattributes": "payload.txt filter=hostile\n",
		"payload.txt":    "LOCKED\n",
	} {
		if err := os.WriteFile(filepath.Join(repository, name), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runFixtureGit(t, repository, "add", "--all")
	runFixtureGit(t, repository, "commit", "--quiet", "-m", "cleanliness fixture")
	harness := writeSourceGateCleanlinessHarness(t)
	runCheck := func(name string, wantSuccess bool) {
		t.Helper()
		objectRepository := filepath.Join(root, "objects-"+name)
		emptyTemplate := filepath.Join(root, "template-"+name)
		if err := os.Mkdir(emptyTemplate, 0o700); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("/bin/bash", harness, repository, objectRepository, emptyTemplate)
		output, err := command.CombinedOutput()
		if wantSuccess && err != nil {
			t.Fatalf("clean source was rejected: %v\n%s", err, output)
		}
		if !wantSuccess && err == nil {
			t.Fatalf("dirty source %q was accepted", name)
		}
	}
	runCheck("clean", true)
	if err := os.WriteFile(filepath.Join(repository, "ordinary-untracked"), []byte("untracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCheck("untracked", false)
	if err := os.Remove(filepath.Join(repository, "ordinary-untracked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repository, "payload.txt")); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "checkout", "--", "payload.txt")
	if status := strings.TrimSpace(string(runFixtureGit(t, repository, "status", "--porcelain=v1", "--untracked-files=all"))); status != "" {
		t.Fatalf("hostile filter fixture is not locally Git-clean: %q", status)
	}
	if payload, err := os.ReadFile(filepath.Join(repository, "payload.txt")); err != nil || string(payload) != "FILTERED\n" {
		t.Fatalf("hostile smudge filter did not alter the worktree: %q err=%v", payload, err)
	}
	runCheck("smudged", false)
}

func TestLockedTreeMaterializationIgnoresFiltersAndArchiveAttributes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	repository := filepath.Join(root, "source")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "init", "--quiet")
	runFixtureGit(t, repository, "config", "filter.hostile.clean", "sed s/FILTERED/LOCKED/g")
	runFixtureGit(t, repository, "config", "filter.hostile.smudge", "sed s/LOCKED/FILTERED/g")
	runFixtureGit(t, repository, "config", "filter.hostile.required", "true")
	for name, payload := range map[string]string{
		".gitattributes": "payload.txt filter=hostile\n",
		"payload.txt":    "LOCKED\n",
		"must-keep":      "committed evidence\n",
	} {
		if err := os.WriteFile(filepath.Join(repository, name), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runFixtureGit(t, repository, "add", "--all")
	runFixtureGit(t, repository, "commit", "--quiet", "-m", "hostile attributes fixture")
	if err := os.Remove(filepath.Join(repository, "payload.txt")); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "checkout", "--", "payload.txt")
	if payload, err := os.ReadFile(filepath.Join(repository, "payload.txt")); err != nil || string(payload) != "FILTERED\n" {
		t.Fatalf("fixture smudge filter did not alter the clean worktree: %q err=%v", payload, err)
	}
	infoDirectory := filepath.Join(repository, ".git", "info")
	if err := os.MkdirAll(infoDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(infoDirectory, "attributes"), []byte("must-keep export-ignore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := strings.TrimSpace(string(runFixtureGit(t, repository, "status", "--porcelain=v1", "--untracked-files=all"))); status != "" {
		t.Fatalf("hostile filter fixture is not Git-clean: %q", status)
	}

	archive := runFixtureGit(t, repository, "archive", "--format=tar", "HEAD")
	archiveReader := tar.NewReader(bytes.NewReader(archive))
	foundMustKeep := false
	for {
		header, err := archiveReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		foundMustKeep = foundMustKeep || header.Name == "must-keep"
	}
	if foundMustKeep {
		t.Fatal("fixture info/attributes did not demonstrate archive omission")
	}

	destination := filepath.Join(root, "snapshot")
	objectRepository := filepath.Join(root, "objects")
	emptyTemplate := filepath.Join(root, "empty-template")
	for _, directory := range []string{destination, objectRepository, emptyTemplate} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	harness := writeSourceGateHarness(t, `
repo_root=$1
destination=$2
object_repository=$3
empty_git_template=$4
source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
git init --quiet --bare --template="$empty_git_template" -- "$object_repository"
git -c fetch.fsckObjects=true --git-dir="$object_repository" fetch --quiet --no-tags "$repo_root" HEAD
git --git-dir="$object_repository" update-ref refs/workagent/source "$source_revision"
git --git-dir="$object_repository" fsck --strict --no-dangling "$source_revision" >/dev/null
prepare_locked_tree_inventory
materialize_locked_tree "$destination" true
`)
	command := exec.Command("/bin/bash", harness, repository, destination, objectRepository, emptyTemplate)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("direct blob materialization failed: %v\n%s", err, output)
	}
	if payload, err := os.ReadFile(filepath.Join(destination, "payload.txt")); err != nil || string(payload) != "LOCKED\n" {
		t.Fatalf("materializer trusted smudged bytes instead of the Git blob: %q err=%v", payload, err)
	}
	if payload, err := os.ReadFile(filepath.Join(destination, "must-keep")); err != nil || string(payload) != "committed evidence\n" {
		t.Fatalf("materializer honored archive-only omission attributes: %q err=%v", payload, err)
	}
}

func TestLockedTreeInventoryPropagatesPartialLSTreeFailure(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	repository := filepath.Join(t.TempDir(), "source")
	for _, directory := range []string{repository, filepath.Join(repository, "a"), filepath.Join(repository, "z")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a/file", "z/file"} {
		if err := os.WriteFile(filepath.Join(repository, filepath.FromSlash(name)), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runFixtureGit(t, repository, "init", "--quiet")
	runFixtureGit(t, repository, "add", "--all")
	runFixtureGit(t, repository, "commit", "--quiet", "-m", "partial tree fixture")
	runFixtureGit(t, repository, "fsck", "--strict", "--no-dangling", "HEAD")
	revision := strings.TrimSpace(string(runFixtureGit(t, repository, "rev-parse", "HEAD")))
	zTree := strings.TrimSpace(string(runFixtureGit(t, repository, "rev-parse", "HEAD:z")))
	looseTree := filepath.Join(repository, ".git", "objects", zTree[:2], zTree[2:])
	if err := os.Remove(looseTree); err != nil {
		t.Fatalf("fixture tree object is not loose: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "inventory-accepted")
	harness := writeSourceGateHarness(t, `
repo_root=$1
source_revision=$2
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
object_repository=$repo_root/.git
empty_git_template=$repo_root/.git
prepare_locked_tree_inventory
touch "$3"
`)
	command := exec.Command("/bin/bash", harness, repository, revision, marker)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("partial ls-tree output was accepted:\n%s", output)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("failed tree enumeration published a success marker: %v", err)
	}
}

func TestLockedTreeInventoryRejectsEmptyGitTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	repository := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "init", "--quiet")
	runFixtureGit(t, repository, "commit", "--quiet", "--allow-empty", "-m", "empty tree fixture")
	revision := strings.TrimSpace(string(runFixtureGit(t, repository, "rev-parse", "HEAD")))
	marker := filepath.Join(t.TempDir(), "inventory-accepted")
	harness := writeSourceGateHarness(t, `
repo_root=$1
source_revision=$2
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
object_repository=$repo_root/.git
empty_git_template=$repo_root/.git
prepare_locked_tree_inventory
touch "$3"
`)
	command := exec.Command("/bin/bash", harness, repository, revision, marker)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("empty Git tree was accepted:\n%s", output)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("empty Git tree published a success marker: %v", err)
	}
}

func TestLockedTreeRejectsControlCharacterPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	repository := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(repository, "bad\x07name"), []byte("control path\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, "add", "--all")
	runFixtureGit(t, repository, "commit", "--quiet", "-m", "control path fixture")
	revision := strings.TrimSpace(string(runFixtureGit(t, repository, "rev-parse", "HEAD")))
	marker := filepath.Join(t.TempDir(), "inventory-accepted")
	harness := writeSourceGateHarness(t, `
repo_root=$1
source_revision=$2
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
object_repository=$repo_root/.git
empty_git_template=$repo_root/.git
prepare_locked_tree_inventory
touch "$3"
`)
	command := exec.Command("/bin/bash", harness, repository, revision, marker)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("control-character Git path was accepted:\n%s", output)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid path inventory published a success marker: %v", err)
	}
}

func TestSystemdReleaseVerificationDistinguishesExecutableAndDataPaths(t *testing.T) {
	for relative, required := range map[string][]string{
		"deploy/systemd/workagent-portal.service": {
			"--required-executable bin/workagent-release --required-executable bin/workagent-portal",
		},
		"deploy/systemd/workagent-notification.service": {
			"--required-executable bin/workagent-notification --required-executable bin/workagent-release",
		},
		"deploy/systemd/workagent-backup.service": {
			"--required-executable bin/workagent-backup --required-executable bin/workagent-release",
		},
		"deploy/systemd/workagent-healthcheck.service": {
			"--required-executable bin/workagent-healthcheck --required-executable bin/workagent-release",
		},
		"deploy/systemd/workagent-userhost@.service": {
			"--required-executable bin/workagent-admin --required-executable bin/workagent-release --required-executable bin/workagent-userhost",
		},
		"deploy/systemd/cliproxyapi.service": {
			"--required-executable bin/workagent-cliproxy --required-executable bin/workagent-release",
			"--required-executable cliproxyapi/bin/cli-proxy-api --required-executable cliproxyapi/plugins/cpa-key-policy-v0.4.5.so",
		},
		"deploy/systemd/workagent-chatforward.service": {
			"--required-executable bin/workagent-release",
			"--required chatforward/app/src/server.js --required-executable chatforward/integration/run-server.sh --required-executable chatforward/node/bin/node --required-executable chatforward/integration/readiness.mjs",
		},
		"deploy/systemd/workagent-chatforward-browser.service": {
			"--required-executable bin/workagent-release",
			"--required chatforward/app/extension/manifest.json --required-executable chatforward/integration/run-browser.sh --required-executable chatforward/node/bin/node --required-executable chatforward/integration/readiness.mjs",
		},
	} {
		content := repositoryFile(t, relative)
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "workagent-release verify") && strings.Contains(line, "--release-id") {
				t.Fatalf("fixed-root systemd verification incorrectly hard-codes a changing release ID: %s", line)
			}
		}
		for _, expected := range required {
			if !strings.Contains(content, expected) {
				t.Fatalf("%s does not preserve executable/data verification boundary %q", relative, expected)
			}
		}
	}
}

func TestCIUploadsOnlyAModePreservingSourceGateArchive(t *testing.T) {
	workflow := repositoryFile(t, ".github/workflows/source-gate.yml")
	for _, required := range []string{
		`tar --create --file="$archive"`,
		`--sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner`,
		`--format=posix --pax-option=delete=atime,delete=ctime`,
		`--no-acls --no-xattrs`,
		`EVIDENCE.sha256`,
		`control-plane control-plane.tree-modes.tsv`,
		`sudo sh -c 'cd "$1" && sha256sum workagent-source-gate.tar' sh "$upload_root"`,
		`archive=$upload_root/workagent-source-gate.tar`,
		`checksum=$upload_root/workagent-source-gate.tar.sha256`,
		`sudo chmod 0555 "$upload_root"`,
		`/opt/workagent-source-gate-upload/workagent-source-gate.tar`,
		`/opt/workagent-source-gate-upload/workagent-source-gate.tar.sha256`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("source-gate workflow does not preserve archive semantics %q", required)
		}
	}
	if strings.Contains(workflow, "path: ${{ runner.temp }}/workagent-artifacts") {
		t.Fatal("source-gate workflow directly uploads a directory and would lose Unix modes")
	}
	if !strings.Contains(workflow, `EXPECTED_SOURCE_REVISION: ${{ github.sha }}`) {
		t.Fatal("source-gate workflow does not pin evidence to the checked-out GitHub revision")
	}
	for _, required := range []string{
		"quality:",
		"verify:",
		"needs: quality",
		"SOURCE_GATE_MODE: quality",
		"SOURCE_GATE_MODE=artifact",
		"QUALITY_GATE_SOURCE_REVISION: ${{ github.sha }}",
		"cache: false",
		"fetch-depth: 0",
		`git --no-replace-objects cat-file blob`,
		`source_root=$isolated_root/source`,
		`sudo cp -a --reflink=never -- "$GITHUB_WORKSPACE/." "$source_root/"`,
		`sudo chown -R "$builder:$builder" -- "$isolated_root/tools" "$source_root"`,
		`find "$GITHUB_WORKSPACE" -writable -print -quit`,
		`cd -- "$1"; exec "$2" "$3"`,
		`sudo pkill -KILL -u "$builder"`,
		`sudo cp -a --reflink=never -- "$isolated_root/artifacts/."`,
		`verify_content_inventory "$sealed/control-plane"`,
		`verify_mode_manifest public`,
		`verify_source_gate_metadata "$sealed"`,
		`verify_outer_evidence "$sealed"`,
		`verify_outer_evidence "$extracted"`,
		`sudo tar --extract`,
		`sudo cmp -- "$archive" "$roundtrip"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("source-gate workflow does not use an isolated fresh artifact job boundary %q", required)
		}
	}
	if strings.Contains(workflow, "download-artifact") {
		t.Fatal("fresh artifact job imports mutable output from the quality job")
	}
	if strings.Contains(workflow, `--directory="$RUNNER_TEMP/workagent-artifacts" .`) {
		t.Fatal("source-gate workflow archives an open-ended artifact directory")
	}
	if strings.Count(workflow, "fetch-depth: 0") != 2 {
		t.Fatal("both source-gate jobs must fetch the complete exact revision history")
	}
	if strings.Contains(workflow, `archive=$RUNNER_TEMP/`) || strings.Contains(workflow, `checksum=$RUNNER_TEMP/`) {
		t.Fatal("source-gate transport files remain replaceable below the runner-writable temporary directory")
	}
	for _, line := range strings.Split(workflow, "\n") {
		if strings.Contains(line, "chown") && strings.Contains(line, "GITHUB_WORKSPACE") {
			t.Fatal("source-gate workflow changes ownership of the original checkout")
		}
	}
}

func createSourceGateTransportFixture(t *testing.T, parent string, timestamp time.Time) string {
	t.Helper()
	root := filepath.Join(parent, "evidence")
	for _, directory := range []string{
		root,
		filepath.Join(root, "control-plane"),
		filepath.Join(root, "control-plane", "bin"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { thawFixtureForCleanup(root) })
	files := map[string]struct {
		mode os.FileMode
		body string
	}{
		"EVIDENCE.sha256":                          {0o600, "outer evidence\n"},
		"control-plane/README":                     {0o444, "control data\n"},
		"control-plane/bin/app":                    {0o555, "control executable\n"},
		"control-plane.tree-modes.tsv":             {0o400, "control modes\n"},
		"source-gate.json":                         {0o600, "source gate\n"},
		"not-authorized-for-transport.extra-proof": {0o600, "must be omitted\n"},
	}
	for relative, value := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.WriteFile(path, []byte(value.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, value.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, timestamp, timestamp); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Join(root, "control-plane", "bin"): 0o555,
		filepath.Join(root, "control-plane"):        0o555,
		root:                                        0o700,
	} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, timestamp, timestamp); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func sourceGateTransportArguments(root, archivePath string) []string {
	return []string{
		"--create", "--file=" + archivePath,
		"--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner",
		"--format=posix", "--pax-option=delete=atime,delete=ctime",
		"--no-acls", "--no-xattrs", "--directory=" + root,
		"EVIDENCE.sha256",
		"control-plane", "control-plane.tree-modes.tsv",
		"source-gate.json",
	}

}

func createSourceGateTransportArchive(t *testing.T, root, archivePath string) []byte {
	t.Helper()
	arguments := sourceGateTransportArguments(root, archivePath)
	if output, err := exec.Command("tar", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("create source-gate transport archive: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSourceGateTransportRejectsEmptyEvidenceDirectory(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar is unavailable")
	}
	root := t.TempDir()
	archivePath := filepath.Join(t.TempDir(), "evidence.tar")
	command := exec.Command("tar", sourceGateTransportArguments(root, archivePath)...)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("empty evidence directory produced a transport archive:\n%s", output)
	}
}

func TestSourceGateTransportArchiveRoundTripsExactModesAndOwners(t *testing.T) {
	firstParent, secondParent := t.TempDir(), t.TempDir()
	firstRoot := createSourceGateTransportFixture(t, firstParent, time.Unix(1_700_000_000, 0))
	secondRoot := createSourceGateTransportFixture(t, secondParent, time.Unix(1_900_000_000, 0))
	firstArchive, secondArchive := filepath.Join(firstParent, "evidence.tar"), filepath.Join(secondParent, "evidence.tar")
	first := createSourceGateTransportArchive(t, firstRoot, firstArchive)
	second := createSourceGateTransportArchive(t, secondRoot, secondArchive)
	if !bytes.Equal(first, second) {
		t.Fatal("mode-preserving transport archive changed when only source mtimes changed")
	}

	expectedModes := map[string]int64{
		"EVIDENCE.sha256":              0o600,
		"control-plane/":               0o555,
		"control-plane/README":         0o444,
		"control-plane/bin/":           0o555,
		"control-plane/bin/app":        0o555,
		"control-plane.tree-modes.tsv": 0o400,
		"source-gate.json":             0o600,
	}
	reader := tar.NewReader(bytes.NewReader(first))
	observed := make(map[string]bool, len(expectedModes))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		expectedMode, ok := expectedModes[header.Name]
		if !ok {
			t.Fatalf("transport archive contains an unexpected entry: %q", header.Name)
		}
		if observed[header.Name] {
			t.Fatalf("transport archive duplicates %q", header.Name)
		}
		observed[header.Name] = true
		if header.Mode != expectedMode || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0)) {
			t.Fatalf("transport metadata drifted for %q: mode=%04o uid=%d gid=%d mtime=%s", header.Name, header.Mode, header.Uid, header.Gid, header.ModTime)
		}
	}
	if len(observed) != len(expectedModes) {
		t.Fatalf("transport archive has %d exact entries, want %d", len(observed), len(expectedModes))
	}

	if os.Geteuid() != 0 {
		return
	}
	extracted := filepath.Join(t.TempDir(), "extracted")
	if err := os.Mkdir(extracted, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { thawFixtureForCleanup(extracted) })
	command := exec.Command("tar", "--extract", "--file="+firstArchive, "--same-owner", "--same-permissions", "--directory="+extracted)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("extract source-gate transport archive: %v\n%s", err, output)
	}
	for relative, mode := range expectedModes {
		path := filepath.Join(extracted, filepath.FromSlash(strings.TrimSuffix(relative, "/")))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || int64(info.Mode().Perm()) != mode {
			t.Fatalf("round-trip metadata drifted for %q", relative)
		}
	}
}
