//go:build linux

package wincapture

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSSHArgumentsHexEncodeUntrustedPaths(t *testing.T) {
	untrusted := "/c/fixture/path;$(touch should-not-run) ' quoted"
	arguments := sshCommandArguments("inventory", []string{untrusted})
	wantPrefix := []string{"-T", "-oBatchMode=yes", "-oClearAllForwardings=yes", "-oForwardAgent=no", "-oForwardX11=no", "-oPermitLocalCommand=no", "-oRequestTTY=no", "reference-host", "--", "/usr/bin/bash", "-s", "--", "inventory"}
	if len(arguments) != len(wantPrefix)+1 {
		t.Fatalf("argument count = %d", len(arguments))
	}
	for index := range wantPrefix {
		if arguments[index] != wantPrefix[index] {
			t.Fatalf("fixed argument %d = %q", index, arguments[index])
		}
	}
	encoded := arguments[len(arguments)-1]
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(encoded) || strings.Contains(encoded, "touch") {
		t.Fatalf("untrusted argument was not opaque hex: %q", encoded)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || string(decoded) != untrusted {
		t.Fatal("hex argument did not round trip")
	}
}

func TestRemoteCommandsHaveFiniteOperationalDeadline(t *testing.T) {
	if remoteReadOnlyCommandTimeout < time.Hour || remoteReadOnlyCommandTimeout > 24*time.Hour {
		t.Fatalf("remote command timeout is not an operational finite bound: %s", remoteReadOnlyCommandTimeout)
	}
	if remoteReadOnlyWaitDelay <= 0 || remoteReadOnlyWaitDelay > time.Minute {
		t.Fatalf("remote command wait delay is not tightly bounded: %s", remoteReadOnlyWaitDelay)
	}
}

func TestRemoteScriptHasNarrowReadOnlySurface(t *testing.T) {
	for _, forbidden := range []string{"eval ", "bash -c", "powershell", "cmd.exe", "taskkill", "kill ", "sqlite", "mktemp", "touch ", "mkdir ", "rm ", "cp ", "mv ", "chmod ", "chown ", ">/", "> /"} {
		if strings.Contains(strings.ToLower(readOnlyRemoteScript), forbidden) {
			t.Fatalf("remote script contains forbidden mutation surface %q", forbidden)
		}
	}
	for _, allowed := range []string{"find ", "stat ", "sha256sum", "tar "} {
		if !strings.Contains(readOnlyRemoteScript, allowed) {
			t.Fatalf("remote script is missing read-only primitive %q", allowed)
		}
	}
	for _, fixed := range []string{"/usr/bin/find", "/usr/bin/stat", "/usr/bin/sha256sum", "/usr/bin/tar"} {
		if !strings.Contains(readOnlyRemoteScript, fixed) {
			t.Fatalf("remote program path is not fixed: %s", fixed)
		}
	}
	if arguments := sshCommandArguments("inventory", []string{"/c/fixture"}); len(arguments) < 10 || arguments[9] != "/usr/bin/bash" {
		t.Fatal("remote Bash path is not fixed")
	}
}

func TestRemoteScriptBashSyntaxAndShellCheck(t *testing.T) {
	syntax := exec.Command("bash", "-n")
	syntax.Stdin = strings.NewReader(readOnlyRemoteScript)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("remote script Bash syntax failed: %v: %s", err, output)
	}
	shellcheck, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is unavailable")
	}
	check := exec.Command(shellcheck, "--shell=bash", "--severity=warning", "-")
	check.Stdin = strings.NewReader(readOnlyRemoteScript)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("remote script ShellCheck failed: %v: %s", err, output)
	}
}

func TestRemoteScriptInventoryIsNULSafeAndRejectsHardlinks(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "line\nbreak")
	if err := os.WriteFile(filename, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runScript(t, "inventory", root, SourceDirectory, "10", "1000")
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 1000}
	parsed, err := readInventory(output, source)
	if err != nil || parsed.summary.Files != 1 || parsed.summary.Bytes != 7 {
		t.Fatalf("NUL-safe inventory failed: %#v %v", parsed.summary, err)
	}
	newlineIndex := indexOfInventory(parsed.entries, "line\nbreak")
	if len(parsed.entries) != 2 || newlineIndex < 0 || parsed.entries[newlineIndex].Path != "line\nbreak" {
		t.Fatal("newline-bearing filename did not survive the NUL-delimited inventory")
	}
	if err := os.Link(filename, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "inventory", root, SourceDirectory, "10", "1000"); err == nil {
		t.Fatal("hardlinked source file was accepted")
	}
}

func TestRemoteScriptEnforcesInventoryLimitsDuringWalk(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "inventory", root, SourceDirectory, "1", "1000"); err == nil {
		t.Fatal("directory inventory exceeded its entry limit without failing")
	}
	if _, err := runScript(t, "inventory", root, SourceDirectory, "10", "6"); err == nil {
		t.Fatal("directory inventory exceeded its byte limit without failing")
	}
	if _, err := runScript(t, "inventory", filepath.Join(root, "payload"), SourceFile, "1", "6"); err == nil {
		t.Fatal("single-file inventory exceeded its byte limit without failing")
	}
}

func TestRemoteScriptEnforcesOAuthLimitsDuringWalk(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "two"), []byte("5678"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "oauth", root, "1", "100"); err == nil {
		t.Fatal("OAuth inventory exceeded its file limit without failing")
	}
	if _, err := runScript(t, "oauth", root, "10", "7"); err == nil {
		t.Fatal("OAuth inventory exceeded its byte limit without failing")
	}
}

func TestRemoteScriptRejectsNewlinesInBoundPaths(t *testing.T) {
	parent := t.TempDir()
	newlineRoot := filepath.Join(parent, "source\nroot")
	if err := os.Mkdir(newlineRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "inventory", newlineRoot, SourceDirectory, "10", "1000"); err == nil {
		t.Fatal("remote source root containing a newline was accepted")
	}
	cleanRoot := filepath.Join(parent, "clean")
	if err := os.Mkdir(cleanRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "inventory", cleanRoot, SourceDirectory, "10", "1000", "excluded\npath"); err == nil {
		t.Fatal("remote exclusion containing a newline was accepted")
	}
	if validateRemotePath("/c/source\nroot") == nil || safeRelative("excluded\npath") || !safeCapturedRelative("line\nbreak") {
		t.Fatal("local path policy disagrees with the NUL-delimited remote protocol")
	}
}

func TestRemoteInventoryExclusionsAreLiteralFindPaths(t *testing.T) {
	root, exclusions, retained := literalExclusionFixture(t)
	arguments := []string{root, SourceDirectory, "100", "10000"}
	arguments = append(arguments, exclusions...)
	output, err := runScript(t, "inventory", arguments...)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := readInventory(output, Source{SourcePath: root, Kind: SourceDirectory, MaxFiles: 100, MaxBytes: 10000})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(parsed.entries))
	for _, entry := range parsed.entries {
		seen[entry.Path] = true
	}
	for _, relative := range exclusions {
		if seen[relative] || seen[relative+"/payload"] {
			t.Fatalf("literal exclusion was inventoried: %q", relative)
		}
	}
	for _, relative := range retained {
		if !seen[relative] || !seen[relative+"/payload"] {
			t.Fatalf("glob-like neighbor was incorrectly pruned: %q", relative)
		}
	}
}

func TestRemoteTarExclusionsRemainLiteralAfterNoWildcards(t *testing.T) {
	root, exclusions, retained := literalExclusionFixture(t)
	arguments := []string{root, SourceDirectory}
	arguments = append(arguments, exclusions...)
	archive, err := runScript(t, "tar", arguments...)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		seen[strings.TrimSuffix(header.Name, "/")] = true
	}
	base := filepath.Base(root)
	for _, relative := range exclusions {
		prefix := base + "/" + relative
		if seen[prefix] || seen[prefix+"/payload"] {
			t.Fatalf("literal tar exclusion was archived: %q", relative)
		}
	}
	for _, relative := range retained {
		prefix := base + "/" + relative
		if !seen[prefix] || !seen[prefix+"/payload"] {
			t.Fatalf("tar --no-wildcards excluded a glob-like neighbor: %q", relative)
		}
	}
}

func literalExclusionFixture(t *testing.T) (string, []string, []string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source[parent]")
	exclusions := []string{"drop*", "ask?", "set[ab]", "close]", `slash\name`}
	retained := []string{"dropXYZ", "askX", "seta", "closeX", "slashname"}
	for _, relative := range append(append([]string(nil), exclusions...), retained...) {
		directory := filepath.Join(root, relative)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "payload"), []byte(relative), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, exclusions, retained
}

func TestInventoryRejectsFilesystemCrossing(t *testing.T) {
	source := Source{Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 1000}
	entries := []inventoryEntry{
		{Path: ".", Kind: 'd', Mode: 0o700, MTime: 1, Device: 1, Inode: 1, NLink: 2},
		{Path: "mounted", Kind: 'd', Mode: 0o700, MTime: 1, Device: 2, Inode: 1, NLink: 2},
	}
	if _, err := readInventory(inventoryWire(entries), source); err == nil || !strings.Contains(err.Error(), "filesystem") {
		t.Fatalf("cross-filesystem source was accepted: %v", err)
	}
}

func TestRemoteSparseSourceFailsClosed(t *testing.T) {
	sourceRoot := t.TempDir()
	sparse := filepath.Join(sourceRoot, "sparse.bin")
	file, err := os.OpenFile(sparse, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1024 * 1024); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{1}, 1024*1024-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(sparse, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Blocks*512 >= stat.Size {
		t.Skip("test filesystem did not create a sparse fixture")
	}
	if _, err := runScript(t, "inventory", sourceRoot, SourceDirectory, "10", "2097152"); err == nil {
		t.Fatal("sparse remote source passed the rehearsal inventory")
	}
	archive, err := runScript(t, "tar", sourceRoot, SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	destinationRoot := privateTemp(t)
	fd, _, err := openPrivateRoot(destinationRoot, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	source := Source{SourcePath: sourceRoot, Destination: "payload", Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 2 * 1024 * 1024, MaxTarBytes: 3 * 1024 * 1024}
	if _, err := extractTar(fd, bytes.NewReader(archive), source, uint32(os.Geteuid())); err == nil {
		t.Fatal("sparse remote source was accepted")
	}
}

func TestValidateSpecRejectsGlobalAndOverlappingExclusions(t *testing.T) {
	spec := validSpec(t)
	spec.Sources[6].Exclusions = []Exclusion{{Path: "node_modules", Type: ExcludeNodeModules}, {Path: "node_modules/.cache", Type: ExcludeDownloadCache}}
	if err := validateSpec(spec); err == nil {
		t.Fatalf("overlapping exclusions accepted: %v", err)
	}
	spec = validSpec(t)
	spec.Sources[6].Exclusions = []Exclusion{{Path: "any/name", Type: ExcludeNodeModules}}
	if err := validateSpec(spec); err == nil {
		t.Fatal("non-explicit node_modules exclusion accepted")
	}
}

func TestExternalBackendVenvNeedsPositiveMarker(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, "backend", ".venv")
	if err := os.MkdirAll(venv, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runScript(t, "exclusions", root, "1", "backend/.venv", ExcludeExternalBackendEnv); err == nil {
		t.Fatal("external backend venv was accepted without pyvenv.cfg and runtime directory")
	}
	if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(venv, "Scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := runScript(t, "exclusions", root, "1", "backend/.venv", ExcludeExternalBackendEnv)
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Exclusions: []Exclusion{{Path: "backend/.venv", Type: ExcludeExternalBackendEnv}}}
	if _, err := readExclusionEvidence(payload, source); err != nil {
		t.Fatalf("positive venv evidence rejected: %v", err)
	}
}

func TestEmptyExclusionEvidenceAcceptsRegularFileSource(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(filename, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := runScript(t, "exclusions", filename, "0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readExclusionEvidence(payload, Source{}); err != nil {
		t.Fatalf("empty regular-file exclusion evidence was rejected: %v", err)
	}
}

func TestLoadSpecRejectsSymlinkAndHardlink(t *testing.T) {
	spec := validSpec(t)
	root := t.TempDir()
	path := writeSpec(t, root, spec)
	symlink := filepath.Join(root, "spec-link.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSpec(symlink, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink spec accepted")
	}
	hardlink := filepath.Join(root, "spec-hard.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSpec(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("hardlinked spec accepted")
	}
}

func TestPrivateSpecPublishingConvergesAfterCompanionOnly(t *testing.T) {
	root := privateTemp(t)
	uid := uint32(os.Geteuid())
	companion := filepath.Join(root, "capture-spec.json.external-workspaces.json")
	spec := filepath.Join(root, "capture-spec.json")
	companionPayload := []byte("{\"schema_version\":1}\n")
	specPayload := []byte("{\"schema_version\":1,\"fixture\":true}\n")

	// This is the state left by interruption between the two no-replace
	// publications. A rerun must accept the exact companion and finish.
	if err := writePrivateSpecNoReplace(companion, companionPayload, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(spec); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("spec unexpectedly exists before retry")
	}
	if err := writePrivateSpecNoReplace(companion, companionPayload, uid); err != nil {
		t.Fatalf("exact companion retry was not convergent: %v", err)
	}
	if err := writePrivateSpecNoReplace(spec, specPayload, uid); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateSpecNoReplace(spec, specPayload, uid); err != nil {
		t.Fatalf("exact spec retry was not convergent: %v", err)
	}
	if err := writePrivateSpecNoReplace(spec, []byte("different\n"), uid); err == nil {
		t.Fatal("different existing spec content was accepted")
	}
	stored, err := os.ReadFile(spec)
	if err != nil || !bytes.Equal(stored, specPayload) {
		t.Fatal("collision altered the published spec")
	}
	partials, err := filepath.Glob(filepath.Join(root, ".capture-spec.partial-*"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("private spec partials were not cleaned: %v %v", partials, err)
	}
}

func TestTarExtractionRejectsTraversalLinksDevicesAndDuplicates(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
	}{
		{"traversal", []*tar.Header{{Name: "source/../../escape", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}}},
		{"symlink", []*tar.Header{{Name: "source/link", Typeflag: tar.TypeSymlink, Linkname: "target", Mode: 0o777}}},
		{"hardlink", []*tar.Header{{Name: "source/link", Typeflag: tar.TypeLink, Linkname: "source/file", Mode: 0o600}}},
		{"device", []*tar.Header{{Name: "source/device", Typeflag: tar.TypeChar, Mode: 0o600}}},
		{"sparse", []*tar.Header{{Name: "source/sparse", Typeflag: tar.TypeGNUSparse, Mode: 0o600, Size: 1}}},
		{"duplicate", []*tar.Header{{Name: "source/file", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}, {Name: "source/file", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := makeTar(t, test.headers, []byte("xx"))
			root := privateTemp(t)
			fd, _, err := openPrivateRoot(root, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			source := Source{SourcePath: "/c/fixture/source", Destination: "payload", Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 100, MaxTarBytes: 4096}
			if _, err := extractTar(fd, bytes.NewReader(payload), source, uint32(os.Geteuid())); err == nil {
				t.Fatal("unsafe tar accepted")
			}
		})
	}
}

func TestTarExtractionRejectsPreexistingSymlinkTOCTOU(t *testing.T) {
	root := privateTemp(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "payload")); err != nil {
		t.Fatal(err)
	}
	fd, _, err := openPrivateRoot(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	payload := makeTar(t, []*tar.Header{{Name: "source", Typeflag: tar.TypeDir, Mode: 0o700}, {Name: "source/file", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}}, []byte("x"))
	source := Source{SourcePath: "/c/fixture/source", Destination: "payload", Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 100, MaxTarBytes: 4096}
	if _, err := extractTar(fd, bytes.NewReader(payload), source, uint32(os.Geteuid())); err == nil {
		t.Fatal("preexisting destination symlink accepted")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("tar extraction escaped through symlink")
	}
}

func TestApprovedSameTenantBuiltinSkillsSymlinkRoundTrips(t *testing.T) {
	root := privateTemp(t)
	fd, _, err := openPrivateRoot(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	source := Source{
		Role: RoleTenantTree, SourcePath: "/c/Users/fixture-owner/AionUiPortal",
		Destination: "tenants/raw/alice/AionUiPortal", Kind: SourceDirectory,
		MaxFiles: 16, MaxBytes: 1024, MaxTarBytes: 64 * 1024,
	}
	target := strings.Join([]string{"C:", "Users", "fixture-owner", "AionUiPortal", "data", "builtin-skills", "canonical"}, string(rune(92)))
	mtime := time.Unix(1_700_000_000, 0)
	payload := makeTar(t, []*tar.Header{
		{Name: "AionUiPortal", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime},
		{Name: "AionUiPortal/data", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime},
		{Name: "AionUiPortal/data/builtin-skills", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime},
		{Name: "AionUiPortal/data/builtin-skills/canonical", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime},
		{Name: "AionUiPortal/profile", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime},
		{Name: "AionUiPortal/profile/alias", Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777, ModTime: mtime},
	}, nil)
	captured, err := extractTar(fd, bytes.NewReader(payload), source, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("approved tenant builtin-skills link was rejected: %v", err)
	}
	if captured.summary.Symlinks != 1 {
		t.Fatalf("captured symlink count = %d", captured.summary.Symlinks)
	}
	stored := filepath.Join(root, filepath.FromSlash(source.Destination), "profile", "alias")
	if got, err := os.Readlink(stored); err != nil || got != target {
		t.Fatalf("captured symlink target = %q, err %v", got, err)
	}
	reopened, err := inventoryStoredSource(fd, source, uint32(os.Geteuid()))
	if err != nil || reopened.summary != captured.summary {
		t.Fatalf("approved captured symlink did not survive stored revalidation: %#v %v", reopened.summary, err)
	}
}

func TestOwnerExecutableFileIsPrivatelyPreserved(t *testing.T) {
	root := privateTemp(t)
	fd, _, err := openPrivateRoot(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	mtime := time.Unix(1_700_000_000, 0)
	archive := makeTar(t, []*tar.Header{
		{Name: "source", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: mtime},
		{Name: "source/tool.sh", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, ModTime: mtime},
	}, []byte("x"))
	source := Source{SourcePath: "/c/fixture/source", Destination: "payload", Kind: SourceDirectory, MaxFiles: 10, MaxBytes: 100, MaxTarBytes: 4096}
	captured, err := extractTar(fd, bytes.NewReader(archive), source, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "payload", "tool.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("captured executable mode = %v", info.Mode().Perm())
	}
	reopened, err := inventoryStoredSource(fd, source, uint32(os.Geteuid()))
	if err != nil || reopened.summary != captured.summary {
		t.Fatalf("executable semantic hash did not survive stored revalidation: %#v %v", reopened.summary, err)
	}
}

func TestCompareInventoriesDetectsContentAndIdentityDrift(t *testing.T) {
	entry := inventoryEntry{Path: ".", Kind: 'f', Mode: 0o600, Size: 1, MTime: 1, SHA256: strings.Repeat("a", 64), Device: 1, Inode: 2, NLink: 1}
	before := inventory{entries: []inventoryEntry{entry}, summary: Summary{Files: 1, Bytes: 1, SHA256: hashInventory([]inventoryEntry{entry}, false)}, evidenceSHA256: hashInventory([]inventoryEntry{entry}, true)}
	after := before
	after.entries = append([]inventoryEntry(nil), before.entries...)
	after.entries[0].Inode++
	after.evidenceSHA256 = hashInventory(after.entries, true)
	if err := compareInventories(before, after); err == nil {
		t.Fatal("inode drift was accepted")
	}
	after = before
	after.summary.SHA256 = strings.Repeat("b", 64)
	if err := compareInventories(before, after); err == nil {
		t.Fatal("content drift was accepted")
	}
}

func TestCollectionUsesBoundedReadOnlyConcurrency(t *testing.T) {
	spec := validSpec(t)
	transport := &concurrencyFixtureTransport{spec: spec}
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	inventories, exclusions, _, err := engine.collect(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventories) != len(spec.Sources) || len(exclusions) != len(spec.Sources) {
		t.Fatal("concurrent collection lost a source result")
	}
	if maximum := transport.maximum.Load(); maximum < 2 || maximum > maxConcurrentReadOnlySources {
		t.Fatalf("read-only collection concurrency = %d", maximum)
	}
}

func TestCapturePublishesPrivatelyAndIsIdempotent(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
	id := "frozen-capture-0001"
	destination := filepath.Join(parent, id)
	report, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete-frozen-capture" || report.Sources != len(spec.Sources) {
		t.Fatalf("unexpected report: %#v", report)
	}
	assertPrivateTree(t, destination)
	calls := transport.callCount()
	second, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true})
	if err != nil || second != report || transport.callCount() != calls {
		t.Fatalf("idempotent replay failed: %#v %v", second, err)
	}
}

func TestExistingCaptureRevalidatesStoredContent(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
	id := "frozen-capture-tamper"
	destination := filepath.Join(parent, id)
	if _, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}); err != nil {
		t.Fatal(err)
	}
	firstSource := spec.Sources[0].Destination
	if err := os.WriteFile(filepath.Join(destination, filepath.FromSlash(firstSource)), []byte("altered"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := transport.callCount()
	if _, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}); err == nil || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("damaged existing capture was accepted: %v", err)
	}
	if transport.callCount() != calls {
		t.Fatal("existing-capture validation unexpectedly contacted Windows")
	}
}

func TestExistingCaptureRevalidatesEvidenceFiles(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
	id := "frozen-capture-evidence"
	destination := filepath.Join(parent, id)
	if _, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "evidence-before.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := transport.callCount()
	if _, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}); err == nil || !strings.Contains(err.Error(), "before evidence") {
		t.Fatalf("damaged capture evidence was accepted: %v", err)
	}
	if transport.callCount() != calls {
		t.Fatal("existing evidence validation unexpectedly contacted Windows")
	}
}

func TestCaptureDriftLeavesUnpublishedPartialEvidence(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	transport.driftAfterTar = true
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	id := "frozen-capture-drift"
	destination := filepath.Join(parent, id)
	_, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true})
	if err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("expected drift failure, got %v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("drifted capture was published")
	}
	partials, err := filepath.Glob(filepath.Join(parent, "."+id+".partial-*"))
	if err != nil || len(partials) != 1 {
		t.Fatalf("partial evidence count = %d, err %v", len(partials), err)
	}
	if _, err := os.Stat(filepath.Join(partials[0], "failure.json")); err != nil {
		t.Fatal("failure evidence was not retained")
	}
}

func TestCaptureRequiresFreezeAndFreeSpace(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	engine := &captureEngine{remote: newFixtureTransport(t, spec), expectedUID: uint32(os.Geteuid()), now: time.Now}
	id := "frozen-capture-gates"
	_, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: filepath.Join(parent, id), CaptureID: id, Confirm: finalConfirmationPrefix + id})
	if err == nil {
		t.Fatal("capture accepted without external freeze declaration")
	}
	spec.Limits.MaxCaptureBytes = 2 << 40
	spec.Limits.MinFreeBytes = 1 << 40
	specPath = writeSpecNamed(t, parent, "large-spec.json", spec)
	_, err = engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: filepath.Join(parent, id), CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true})
	if err == nil || !strings.Contains(err.Error(), "free-space") {
		t.Fatalf("free-space gate failed: %v", err)
	}
}

func TestCheckRejectsChangedPrivateLocalInputBeforeWindowsContact(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	if err := os.WriteFile(filepath.Join(parent, "external-source-manifest.json"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	if _, err := engine.check(context.Background(), CheckOptions{SpecPath: specPath}); err == nil || !strings.Contains(err.Error(), "local input") {
		t.Fatalf("changed private local input was accepted: %v", err)
	}
	if transport.callCount() != 0 {
		t.Fatal("Windows transport was contacted before private local input validation")
	}
}

func TestFailedTarRetainsPartialAndRedactsTransportDetails(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	transport.tarError = errors.New("secret password=should-never-appear")
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	id := "frozen-capture-error"
	_, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: filepath.Join(parent, id), CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true})
	if err == nil || strings.Contains(err.Error(), "should-never-appear") {
		t.Fatalf("transport error was not redacted: %v", err)
	}
	partials, _ := filepath.Glob(filepath.Join(parent, "."+id+".partial-*"))
	if len(partials) != 1 {
		t.Fatalf("expected one retained partial, got %d", len(partials))
	}
}

func TestENOSPCFailureKeepsUnpublishedPartial(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	transport.tarError = unix.ENOSPC
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	id := "frozen-capture-enospc"
	destination := filepath.Join(parent, id)
	if _, err := engine.capture(context.Background(), CaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}); err == nil {
		t.Fatal("ENOSPC capture failure was accepted")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ENOSPC capture was published")
	}
	partials, err := filepath.Glob(filepath.Join(parent, "."+id+".partial-*"))
	if err != nil || len(partials) != 1 {
		t.Fatalf("ENOSPC partial evidence count = %d, err %v", len(partials), err)
	}
	if _, err := os.Stat(filepath.Join(partials[0], "failure.json")); err != nil {
		t.Fatal("ENOSPC partial has no durable failure evidence")
	}
}

func TestBoundedWriterStopsOversizeOutput(t *testing.T) {
	var output bytes.Buffer
	writer := &boundedWriter{destination: &output, remaining: 3}
	if _, err := writer.Write([]byte("oversize")); err == nil || output.String() != "ove" || !writer.exceeded {
		t.Fatal("bounded output did not fail closed")
	}
}

func TestSpecAccountsForLocalInputsAndFilesystemOverhead(t *testing.T) {
	spec := validSpec(t)
	spec.LocalFiles[0].SourcePath = "/private/external-workspaces.json"
	spec.Limits.MaxCaptureBytes = spec.Limits.MaxTotalBytes
	if err := validateSpec(spec); err == nil || !strings.Contains(err.Error(), "max_capture_bytes") {
		t.Fatalf("capture disk estimate omitted local inputs or overhead: %v", err)
	}
	spec = validSpec(t)
	spec.LocalFiles[0].SourcePath = "/private/external-workspaces.json"
	for len(spec.LocalFiles) < 17 {
		spec.LocalFiles = append(spec.LocalFiles, LocalFile{SourcePath: "/private/input-" + formatInt(int64(len(spec.LocalFiles))), Destination: "private/input-" + formatInt(int64(len(spec.LocalFiles))), SHA256: strings.Repeat("a", 64), MaxBytes: 1})
	}
	if err := validateSpec(spec); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("local-input count limit was not enforced: %v", err)
	}
}

func TestPublishNoReplacePreservesBothSidesOnCollision(t *testing.T) {
	parent := privateTemp(t)
	partial := filepath.Join(parent, ".capture.partial-test")
	destination := filepath.Join(parent, "capture-collision")
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishNoReplace(partial, destination); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("rename collision did not fail closed: %v", err)
	}
	if _, err := os.Stat(partial); err != nil {
		t.Fatal("partial was lost on rename collision")
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatal("existing destination was replaced on rename collision")
	}
}

func TestStderrDigestWriterStopsAtHardLimitWithoutRetainingText(t *testing.T) {
	writer := newDigestWriter(4)
	if _, err := writer.Write([]byte("password=unbounded-secret")); err == nil {
		t.Fatal("stderr writer did not stop at its hard limit")
	}
	summary := writer.summary()
	if !summary.Exceeded || summary.Bytes != int64(len("password=unbounded-secret")) || strings.Contains(summary.SHA256, "secret") {
		t.Fatalf("unexpected bounded stderr summary: %#v", summary)
	}
}

func runScript(t *testing.T, action string, arguments ...string) ([]byte, error) {
	t.Helper()
	encoded := []string{"-s", "--", action}
	for _, argument := range arguments {
		encoded = append(encoded, hex.EncodeToString([]byte(argument)))
	}
	command := exec.Command("bash", encoded...)
	command.Stdin = strings.NewReader(readOnlyRemoteScript)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	return output.Bytes(), err
}

func validSpec(t *testing.T) Spec {
	t.Helper()
	sources := []Source{
		{ID: "portal-db", Role: RolePortalDatabase, SourcePath: "/c/fixture/global/portal.db", Destination: "global/portal.windows.db", Kind: SourceFile},
		{ID: "portal-wal", Role: RolePortalWAL, SourcePath: "/c/fixture/global/portal.db-wal", Destination: "global/portal.windows.db-wal", Kind: SourceFile},
		{ID: "portal-shm", Role: RolePortalSHM, SourcePath: "/c/fixture/global/portal.db-shm", Destination: "global/portal.windows.db-shm", Kind: SourceFile},
		{ID: "portal-config", Role: RolePortalConfig, SourcePath: "/c/fixture/global/portal.json", Destination: "global/portal.json", Kind: SourceFile},
		{ID: "notification-state", Role: RoleNotification, SourcePath: "/c/fixture/global/notification.json", Destination: "global/notification.json", Kind: SourceFile},
		{ID: "chatforward-state", Role: RoleChatForward, SourcePath: "/c/fixture/global/chatforward.key", Destination: "global/chatforward.key", Kind: SourceFile},
	}
	for index := 0; index < 8; index++ {
		sources = append(sources, Source{ID: "tenant-0" + string(rune('1'+index)), Role: RoleTenantTree, SourcePath: "/c/Users/tenant-0" + string(rune('1'+index)) + "/AionUiPortal", Destination: "tenants/raw/tenant-0" + string(rune('1'+index)) + "/AionUiPortal", Kind: SourceDirectory})
	}
	sources = append(sources,
		Source{ID: "policy-state", Role: RolePolicyState, SourcePath: "/c/fixture/policy/state.json", Destination: "cliproxy/cpa-key-policy-state.json", Kind: SourceFile},
		Source{ID: "cliproxy-config", Role: RoleCLIProxyConfig, SourcePath: "/c/fixture/policy/config.yaml", Destination: "cliproxy/config.yaml", Kind: SourceFile},
		Source{ID: "cliproxy-admin", Role: RoleCLIProxyAdmin, SourcePath: "/c/fixture/policy/.management-key", Destination: "cliproxy/.management-key", Kind: SourceFile},
		Source{ID: "external-01", Role: RoleExternal, SourcePath: "/d/fixture/workspace", Destination: "external-workspaces/workspace-01", Kind: SourceDirectory},
	)
	for index := range sources {
		sources[index].MaxFiles = 4
		sources[index].MaxBytes = 4096
		sources[index].MaxTarBytes = 64 * 1024
		if sources[index].Kind == SourceFile {
			sources[index].MaxFiles = 1
		}
	}
	return Spec{SchemaVersion: 1, ExpectedTenantCount: 8, ExpectedExternalWorkspaceCount: 1, Sources: sources,
		OAuthEvidence: OAuthEvidence{SourcePath: "/c/fixture/oauth-auth", MaxFiles: 100, MaxBytes: 1024 * 1024},
		LocalFiles:    []LocalFile{{Destination: "external-workspaces.json", SHA256: strings.Repeat("0", 64), MaxBytes: 1024 * 1024}},
		Limits:        AggregateLimits{MaxSources: 64, MaxTotalFiles: 1000, MaxTotalBytes: 1024 * 1024, MaxCaptureBytes: 32 * 1024 * 1024},
	}
}

func writeSpec(t *testing.T, directory string, spec Spec) string {
	t.Helper()
	return writeSpecNamed(t, directory, "capture-spec.json", spec)
}

func writeSpecNamed(t *testing.T, directory, name string, spec Spec) string {
	t.Helper()
	if len(spec.LocalFiles) > 0 && spec.LocalFiles[0].SourcePath == "" {
		manifest := filepath.Join(directory, "external-source-manifest.json")
		payload := []byte("{}\n")
		if err := os.WriteFile(manifest, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		spec.LocalFiles[0].SourcePath = manifest
		spec.LocalFiles[0].SHA256 = hex.EncodeToString(digest[:])
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, name)
	if err := os.WriteFile(filename, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func privateTemp(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

type fixtureTransport struct {
	t             *testing.T
	spec          Spec
	mu            sync.Mutex
	calls         int
	tarSeen       bool
	driftAfterTar bool
	tarError      error
}

type concurrencyFixtureTransport struct {
	spec    Spec
	active  atomic.Int64
	maximum atomic.Int64
}

func (transport *concurrencyFixtureTransport) run(ctx context.Context, action string, arguments []string, output io.Writer, _ int64) (stderrSummary, error) {
	active := transport.active.Add(1)
	for {
		maximum := transport.maximum.Load()
		if active <= maximum || transport.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer transport.active.Add(-1)
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return stderrSummary{}, ctx.Err()
	case <-timer.C:
	}
	switch action {
	case "inventory":
		var source Source
		for _, candidate := range transport.spec.Sources {
			if candidate.SourcePath == arguments[0] {
				source = candidate
				break
			}
		}
		if source.SourcePath == "" {
			return stderrSummary{}, errors.New("unknown concurrent fixture source")
		}
		_, err := output.Write(inventoryWire(fixtureEntries(source)))
		return stderrSummary{}, err
	case "exclusions":
		_, err := output.Write([]byte("WAX1\x00"))
		return stderrSummary{}, err
	case "oauth":
		_, err := output.Write([]byte("WAO1\x00"))
		return stderrSummary{}, err
	default:
		return stderrSummary{}, errors.New("unexpected concurrent fixture action")
	}
}

func newFixtureTransport(t *testing.T, spec Spec) *fixtureTransport {
	return &fixtureTransport{t: t, spec: spec}
}

func (transport *fixtureTransport) run(_ context.Context, action string, arguments []string, output io.Writer, _ int64) (stderrSummary, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls++
	switch action {
	case "inventory":
		source := transport.source(arguments[0])
		entries := fixtureEntries(source)
		if transport.driftAfterTar && transport.tarSeen {
			entries[len(entries)-1].SHA256 = strings.Repeat("f", 64)
		}
		_, err := output.Write(inventoryWire(entries))
		return stderrSummary{}, err
	case "exclusions":
		_, err := output.Write([]byte("WAX1\x00"))
		return stderrSummary{}, err
	case "oauth":
		_, err := output.Write([]byte("WAO1\x00"))
		return stderrSummary{}, err
	case "tar":
		transport.tarSeen = true
		if transport.tarError != nil {
			return stderrSummary{}, errors.New("remote read-only tar failed")
		}
		source := transport.source(arguments[0])
		_, err := output.Write(fixtureTar(transport.t, source))
		return stderrSummary{}, err
	default:
		return stderrSummary{}, errors.New("unexpected action")
	}
}

func (transport *fixtureTransport) source(sourcePath string) Source {
	for _, source := range transport.spec.Sources {
		if source.SourcePath == sourcePath {
			return source
		}
	}
	transport.t.Fatalf("unknown fixture source")
	return Source{}
}

func (transport *fixtureTransport) callCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

func fixtureEntries(source Source) []inventoryEntry {
	mtime := int64(1_700_000_000)
	if source.Kind == SourceFile {
		payload := []byte("fixture")
		digest := sha256.Sum256(payload)
		return []inventoryEntry{{Path: ".", Kind: 'f', Mode: 0o600, Size: int64(len(payload)), MTime: mtime, SHA256: hex.EncodeToString(digest[:]), Device: 1, Inode: uint64(len(source.SourcePath) + 1), NLink: 1}}
	}
	payload := []byte("fixture")
	digest := sha256.Sum256(payload)
	return []inventoryEntry{
		{Path: ".", Kind: 'd', Mode: 0o700, MTime: mtime, Device: 1, Inode: uint64(len(source.SourcePath) + 1), NLink: 2},
		{Path: "data.bin", Kind: 'f', Mode: 0o600, Size: int64(len(payload)), MTime: mtime, SHA256: hex.EncodeToString(digest[:]), Device: 1, Inode: uint64(len(source.SourcePath) + 2), NLink: 1},
	}
}

func inventoryWire(entries []inventoryEntry) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("WAI1\x00")
	for _, entry := range entries {
		physicalSize := entry.PhysicalSize
		if physicalSize == 0 && entry.Kind == 'f' {
			physicalSize = entry.Size
		}
		fields := []string{"E", entry.Path, string(entry.Kind), formatUint(uint64(entry.Mode), 8), formatInt(entry.Size), formatInt(entry.MTime), entry.SHA256, formatUint(entry.Device, 10), formatUint(entry.Inode, 10), formatUint(entry.NLink, 10), formatInt(physicalSize), entry.LinkTarget}
		for _, field := range fields {
			buffer.WriteString(field)
			buffer.WriteByte(0)
		}
	}
	return buffer.Bytes()
}

func fixtureTar(t *testing.T, source Source) []byte {
	t.Helper()
	base := filepath.Base(source.SourcePath)
	mtime := time.Unix(1_700_000_000, 0)
	if source.Kind == SourceFile {
		return makeTar(t, []*tar.Header{{Name: base, Typeflag: tar.TypeReg, Mode: 0o600, Size: 7, ModTime: mtime, Format: tar.FormatUSTAR}}, []byte("fixture"))
	}
	return makeTar(t, []*tar.Header{{Name: base, Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mtime, Format: tar.FormatUSTAR}, {Name: base + "/data.bin", Typeflag: tar.TypeReg, Mode: 0o600, Size: 7, ModTime: mtime, Format: tar.FormatUSTAR}}, []byte("fixture"))
}

func makeTar(t *testing.T, headers []*tar.Header, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	offset := 0
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			end := offset + int(header.Size)
			if end > len(data) {
				end = len(data)
			}
			if _, err := writer.Write(data[offset:end]); err != nil {
				t.Fatal(err)
			}
			offset = end
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func assertPrivateTree(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0o700 {
				t.Errorf("directory mode %s = %o", filename, info.Mode().Perm())
			}
		} else if info.Mode().IsRegular() {
			if info.Mode().Perm() != 0o600 {
				t.Errorf("file mode %s = %o", filename, info.Mode().Perm())
			}
		} else {
			t.Errorf("special entry in capture: %s", filename)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func formatUint(value uint64, base int) string {
	const digits = "0123456789abcdef"
	if value == 0 {
		return "0"
	}
	var result []byte
	for value > 0 {
		result = append(result, digits[value%uint64(base)])
		value /= uint64(base)
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return string(result)
}

func formatInt(value int64) string {
	if value < 0 {
		return "-" + formatUint(uint64(-value), 10)
	}
	return formatUint(uint64(value), 10)
}

var _ = sort.Strings
