//go:build linux

package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCanonicalEdgePublicationEvidenceIsExactAndBounded(t *testing.T) {
	const bootID = "11111111-2222-4333-8444-555555555555"
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "journal",
			value: edgePublicationJournal{SchemaVersion: 1, BootID: bootID, PermitDevice: 11, PermitInode: 22},
			want:  `{"schema_version":1,"boot_id":"11111111-2222-4333-8444-555555555555","permit_device":11,"permit_inode":22}` + "\n",
		},
		{
			name:  "permit",
			value: edgePublicationPermit{SchemaVersion: 1, BootID: bootID, JournalDevice: 33, JournalInode: 44},
			want:  `{"schema_version":1,"boot_id":"11111111-2222-4333-8444-555555555555","journal_device":33,"journal_inode":44}` + "\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalEdgePublicationJSON(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("canonical evidence=%q want=%q", got, test.want)
			}
			if len(got) > 1024 || got[len(got)-1] != '\n' || (len(got) > 1 && got[len(got)-2] == '\n') {
				t.Fatalf("canonical evidence framing is unsafe: length=%d payload=%q", len(got), got)
			}
		})
	}

	if _, err := canonicalEdgePublicationJSON(make(chan int)); err == nil {
		t.Fatal("an unencodable edge-publication value was accepted")
	}
	if _, err := canonicalEdgePublicationJSON(struct {
		Value string `json:"value"`
	}{Value: strings.Repeat("x", 1024)}); err == nil {
		t.Fatal("oversized edge-publication evidence was accepted")
	}
}

func TestSafeEdgeArtifactStatRequiresOneRootOwnedPrivateRegularFile(t *testing.T) {
	base := unix.Stat_t{
		Dev:   10,
		Ino:   20,
		Mode:  unix.S_IFREG | 0o600,
		Uid:   0,
		Gid:   0,
		Nlink: 1,
		Size:  1,
	}
	if !safeEdgeArtifactStat(base, false) {
		t.Fatal("safe edge-publication artifact metadata was rejected")
	}

	tests := []struct {
		name  string
		alter func(*unix.Stat_t)
	}{
		{name: "directory", alter: func(value *unix.Stat_t) { value.Mode = unix.S_IFDIR | 0o600 }},
		{name: "group readable", alter: func(value *unix.Stat_t) { value.Mode |= 0o040 }},
		{name: "setuid", alter: func(value *unix.Stat_t) { value.Mode |= unix.S_ISUID }},
		{name: "foreign owner", alter: func(value *unix.Stat_t) { value.Uid = 1 }},
		{name: "foreign group", alter: func(value *unix.Stat_t) { value.Gid = 1 }},
		{name: "hard linked", alter: func(value *unix.Stat_t) { value.Nlink = 2 }},
		{name: "negative size", alter: func(value *unix.Stat_t) { value.Size = -1 }},
		{name: "oversized", alter: func(value *unix.Stat_t) { value.Size = 1025 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.alter(&value)
			if safeEdgeArtifactStat(value, false) {
				t.Fatal("unsafe edge-publication artifact metadata was accepted")
			}
		})
	}

	empty := base
	empty.Size = 0
	if safeEdgeArtifactStat(empty, false) {
		t.Fatal("empty completed edge-publication evidence was accepted")
	}
	if !safeEdgeArtifactStat(empty, true) {
		t.Fatal("empty in-progress edge-publication evidence was rejected")
	}
	maximum := base
	maximum.Size = 1024
	if !safeEdgeArtifactStat(maximum, false) {
		t.Fatal("maximum-size edge-publication evidence was rejected")
	}
}

func TestSameEdgeArtifactStatBindsStableIdentityAndSecurityMetadata(t *testing.T) {
	base := unix.Stat_t{Dev: 10, Ino: 20, Mode: unix.S_IFREG | 0o600, Uid: 0, Gid: 0, Nlink: 1, Size: 100}
	if !sameEdgeArtifactStat(base, base) {
		t.Fatal("identical edge-publication metadata did not match")
	}
	tests := []struct {
		name  string
		alter func(*unix.Stat_t)
	}{
		{name: "device", alter: func(value *unix.Stat_t) { value.Dev++ }},
		{name: "inode", alter: func(value *unix.Stat_t) { value.Ino++ }},
		{name: "mode", alter: func(value *unix.Stat_t) { value.Mode |= 0o040 }},
		{name: "owner", alter: func(value *unix.Stat_t) { value.Uid++ }},
		{name: "group", alter: func(value *unix.Stat_t) { value.Gid++ }},
		{name: "link count", alter: func(value *unix.Stat_t) { value.Nlink++ }},
		{name: "size", alter: func(value *unix.Stat_t) { value.Size++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.alter(&changed)
			if sameEdgeArtifactStat(base, changed) {
				t.Fatal("changed edge-publication metadata matched its authenticated snapshot")
			}
		})
	}
}

func TestVerifyEdgeOpenArtifactDetectsContentAndPathReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production metadata contract requires root-owned fixtures")
	}
	payload := []byte("authenticated edge-publication evidence\n")

	t.Run("exact artifact", func(t *testing.T) {
		path, fd, stat := createEdgeArtifactFixture(t, payload)
		defer unix.Close(fd)
		if err := verifyEdgeOpenArtifact(fd, path, stat, payload); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("same-size content mutation", func(t *testing.T) {
		path, fd, stat := createEdgeArtifactFixture(t, payload)
		defer unix.Close(fd)
		changed := append([]byte(nil), payload...)
		changed[0] ^= 0x20
		if _, err := unix.Pwrite(fd, changed, 0); err != nil {
			t.Fatal(err)
		}
		if err := verifyEdgeOpenArtifact(fd, path, stat, payload); err == nil || !strings.Contains(err.Error(), "content changed") {
			t.Fatalf("same-size content mutation result=%v", err)
		}
	})

	t.Run("path replacement", func(t *testing.T) {
		path, fd, stat := createEdgeArtifactFixture(t, payload)
		defer unix.Close(fd)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyEdgeOpenArtifact(fd, path, stat, payload); err == nil {
			t.Fatal("replacement edge-publication path was accepted")
		}
	})
}

func TestEdgePublicationPermitLockPersistsUntilCallerClosesAfterFailClosedDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publication.permit")
	ownerFD, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	transaction := &edgePublicationTransaction{permitFD: ownerFD}
	if err := unix.Flock(ownerFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	observerFD, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(observerFD)
	if err := unix.Flock(observerFD, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("publication permit lock did not survive until caller-controlled cleanup: %v", err)
	}
	// Commit errors before the permit unlink deliberately leave this descriptor
	// open. The caller invokes Close only after it has proved Caddy disabled.
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	if transaction.permitFD != -1 {
		t.Fatalf("closed transaction retained permit descriptor %d", transaction.permitFD)
	}
	if err := unix.Flock(observerFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("orphaned publication permit did not become recoverable: %v", err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatalf("transaction close is not idempotent: %v", err)
	}
}

func TestEdgePublicationCommitDurablyClearsJournalBeforeFinalPermitSignal(t *testing.T) {
	function := parseEdgePublicationFunction(t, "Commit", true)
	if hasDeferredPermitClose(function.Body) {
		t.Fatal("Commit unconditionally deferred permit-lock release across pre-signal errors")
	}
	events := edgePublicationDurabilityEvents(function.Body)
	want := []string{
		"unlink:" + edgePublicationJournalPath,
		"sync:" + edgePublicationJournalPath,
		"unlink:" + edgePublicationPermitPath,
		"close:permitFD",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("Commit durability events=%v want=%v", events, want)
	}
	if calls := callsAfterPermitUnlink(function.Body); !reflect.DeepEqual(calls, []string{"unix.Close"}) {
		t.Fatalf("fallible calls after the final permit-unlink signal=%v want only lock release", calls)
	}
}

func TestEdgePublicationReconcileDisablesBeforeAndAfterManagerReload(t *testing.T) {
	function := parseEdgePublicationFunction(t, "reconcilePendingEdgePublication", false)
	var events []string
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isIdentifierCall(call, "rollbackPublishedCaddyFailClosed") {
			events = append(events, "disable")
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Action" || len(call.Args) != 2 {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		argument, literal := call.Args[1].(*ast.BasicLit)
		if ok && literal && receiver.Name == "controller" && argument.Value == `"daemon-reload"` {
			events = append(events, "daemon-reload")
		}
		return true
	})
	want := []string{"disable", "daemon-reload", "disable"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("edge-publication reconcile safety events=%v want=%v", events, want)
	}
}

func TestEdgePublicationBeginPublishesOnlyCanonicalAnonymousEvidenceJournalFirst(t *testing.T) {
	function := parseEdgePublicationFunction(t, "beginEdgePublication", false)
	if countASTSelector(function.Body, "unix", "O_TMPFILE") != 2 {
		t.Fatal("beginEdgePublication must create exactly two anonymous O_TMPFILE evidence inodes")
	}
	if countASTSelector(function.Body, "unix", "O_CREAT") != 0 {
		t.Fatal("beginEdgePublication must not expose a named empty evidence inode")
	}
	events := edgePublicationConstructionEvents(function.Body)
	wantSubsequence := []string{
		"flock:permitFD",
		"write:journalFD",
		"write:permitFD",
		"fsync:journalFD",
		"fsync:permitFD",
		"link:" + edgePublicationJournalPath,
		"sync:" + edgePublicationJournalPath,
		"link:" + edgePublicationPermitPath,
		"sync:" + edgePublicationPermitPath,
	}
	if !containsOrderedEvents(events, wantSubsequence) {
		t.Fatalf("beginEdgePublication construction events=%v; missing ordered subsequence %v", events, wantSubsequence)
	}
}

func createEdgeArtifactFixture(t *testing.T, payload []byte) (string, int, unix.Stat_t) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "publication.json")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err := writeEdgeFD(fd, payload); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if !safeEdgeArtifactStat(stat, false) {
		unix.Close(fd)
		t.Fatalf("test fixture has unsafe metadata: mode=%#o uid=%d gid=%d nlink=%d size=%d", stat.Mode, stat.Uid, stat.Gid, stat.Nlink, stat.Size)
	}
	return path, fd, stat
}

func parseEdgePublicationFunction(t *testing.T, name string, method bool) *ast.FuncDecl {
	t.Helper()
	_, testPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve edge-publication test source path")
	}
	mainPath := filepath.Join(filepath.Dir(testPath), "main.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), mainPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name && (function.Recv != nil) == method {
			return function
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func edgePublicationDurabilityEvents(node ast.Node) []string {
	var events []string
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isSelectorCall(call, "unix", "Unlink") {
			if path, ok := edgePublicationPathArgument(call.Args); ok {
				events = append(events, "unlink:"+path)
			}
			return true
		}
		if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "syncEdgeDirectory" {
			if path, ok := edgePublicationDirectoryArgument(call.Args); ok {
				events = append(events, "sync:"+path)
			}
			return true
		}
		if isSelectorCall(call, "unix", "Close") && isTransactionPermitFDArgument(call.Args) {
			events = append(events, "close:permitFD")
			return true
		}
		if isTransactionCloseCall(call) {
			events = append(events, "close:permitFD")
		}
		return true
	})
	return events
}

func callsAfterPermitUnlink(node ast.Node) []string {
	var permitUnlink token.Pos
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isSelectorCall(call, "unix", "Unlink") {
			if path, ok := edgePublicationPathArgument(call.Args); ok && path == edgePublicationPermitPath {
				permitUnlink = call.End()
			}
		}
		return true
	})
	if permitUnlink == token.NoPos {
		return nil
	}
	var calls []string
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || call.Pos() <= permitUnlink {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.SelectorExpr:
			if receiver, ok := function.X.(*ast.Ident); ok {
				calls = append(calls, receiver.Name+"."+function.Sel.Name)
			}
		case *ast.Ident:
			calls = append(calls, function.Name)
		}
		return true
	})
	return calls
}

func hasDeferredPermitClose(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		deferred, ok := node.(*ast.DeferStmt)
		if !ok {
			return true
		}
		ast.Inspect(deferred.Call, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && ((isSelectorCall(call, "unix", "Close") && isTransactionPermitFDArgument(call.Args)) || isTransactionCloseCall(call)) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

func isTransactionPermitFDArgument(arguments []ast.Expr) bool {
	if len(arguments) == 0 {
		return false
	}
	selector, ok := arguments[0].(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "permitFD" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && receiver.Name == "transaction"
}

func isTransactionCloseCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Close" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && receiver.Name == "transaction"
}

func edgePublicationConstructionEvents(node ast.Node) []string {
	var events []string
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isSelectorCall(call, "unix", "Open"):
			if path, ok := edgePublicationPathArgument(call.Args); ok {
				events = append(events, "open:"+path)
			}
		case isSelectorCall(call, "unix", "Flock"):
			if descriptor, ok := identifierArgument(call.Args); ok {
				events = append(events, "flock:"+descriptor)
			}
		case isSelectorCall(call, "unix", "Fsync"):
			if descriptor, ok := identifierArgument(call.Args); ok {
				events = append(events, "fsync:"+descriptor)
			}
		case isIdentifierCall(call, "writeEdgeFD"):
			if descriptor, ok := identifierArgument(call.Args); ok {
				events = append(events, "write:"+descriptor)
			}
		case isIdentifierCall(call, "syncEdgeDirectory"):
			if path, ok := edgePublicationDirectoryArgument(call.Args); ok {
				events = append(events, "sync:"+path)
			}
		case isSelectorCall(call, "unix", "Linkat"):
			if path, ok := edgePublicationLinkPathArgument(call.Args); ok {
				events = append(events, "link:"+path)
			}
		}
		return true
	})
	return events
}

func countASTSelector(node ast.Node, packageName, selectorName string) int {
	count := 0
	ast.Inspect(node, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != selectorName {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == packageName {
			count++
		}
		return true
	})
	return count
}

func isSelectorCall(call *ast.CallExpr, packageName, functionName string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != functionName {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == packageName
}

func isIdentifierCall(call *ast.CallExpr, functionName string) bool {
	identifier, ok := call.Fun.(*ast.Ident)
	return ok && identifier.Name == functionName
}

func identifierArgument(arguments []ast.Expr) (string, bool) {
	if len(arguments) == 0 {
		return "", false
	}
	identifier, ok := arguments[0].(*ast.Ident)
	return identifier.Name, ok
}

func edgePublicationPathArgument(arguments []ast.Expr) (string, bool) {
	identifier, ok := firstIdentifier(arguments)
	if !ok {
		return "", false
	}
	switch identifier {
	case "edgePublicationPermitPath":
		return edgePublicationPermitPath, true
	case "edgePublicationJournalPath":
		return edgePublicationJournalPath, true
	default:
		return "", false
	}
}

func edgePublicationLinkPathArgument(arguments []ast.Expr) (string, bool) {
	if len(arguments) < 4 {
		return "", false
	}
	identifier, ok := arguments[3].(*ast.Ident)
	if !ok {
		return "", false
	}
	return edgePublicationPathArgument([]ast.Expr{identifier})
}

func edgePublicationDirectoryArgument(arguments []ast.Expr) (string, bool) {
	if len(arguments) == 0 {
		return "", false
	}
	directoryCall, ok := arguments[0].(*ast.CallExpr)
	if !ok || !isSelectorCall(directoryCall, "filepath", "Dir") {
		return "", false
	}
	return edgePublicationPathArgument(directoryCall.Args)
}

func firstIdentifier(arguments []ast.Expr) (string, bool) {
	if len(arguments) == 0 {
		return "", false
	}
	identifier, ok := arguments[0].(*ast.Ident)
	if !ok {
		return "", false
	}
	return identifier.Name, true
}

func containsOrderedEvents(events, want []string) bool {
	index := 0
	for _, event := range events {
		if index < len(want) && event == want[index] {
			index++
		}
	}
	return index == len(want)
}
