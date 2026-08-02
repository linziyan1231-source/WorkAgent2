package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/posixacl"

	"golang.org/x/sys/unix"
)

const (
	tenantFileJournalSchema  = 2
	tenantFileMaximumSize    = 1024 * 1024
	tenantJournalMaximumSize = 4 * 1024 * 1024
)

const (
	tenantFileIdentity  = "identity"
	tenantFileResources = "resources"
	tenantFileConfig    = "config"
)

type tenantFileIntent struct {
	Name          string
	ProtectedRoot string
	Target        string
	Stage         string
	Payload       []byte
	Mode          os.FileMode
	UID           uint32
	GID           uint32
	ACLUser       uint32
}

type tenantFileSetPlan struct {
	TenantID        string
	JournalPath     string
	Entries         []tenantFileIntent
	ValidateJournal func([]tenantFileJournalEntry) error
}

type tenantFileState struct {
	Exists    bool   `json:"exists"`
	SHA256    string `json:"sha256,omitempty"`
	Mode      uint32 `json:"mode,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	GID       uint32 `json:"gid,omitempty"`
	Size      int64  `json:"size,omitempty"`
	ACLSHA256 string `json:"acl_sha256,omitempty"`
}

type tenantFileJournalEntry struct {
	Name    string          `json:"name"`
	Target  string          `json:"target"`
	Stage   string          `json:"stage"`
	Payload []byte          `json:"payload"`
	Mode    uint32          `json:"mode"`
	UID     uint32          `json:"uid"`
	GID     uint32          `json:"gid"`
	ACLUser uint32          `json:"acl_user,omitempty"`
	Before  tenantFileState `json:"before"`
	Desired tenantFileState `json:"desired"`
}

type tenantFileJournal struct {
	SchemaVersion int                      `json:"schema_version"`
	TenantID      string                   `json:"tenant_id"`
	Entries       []tenantFileJournalEntry `json:"entries"`
}

// tenantFileFaultHook is deliberately passed explicitly instead of being a
// package global. Production always supplies nil; tests can stop at each
// durable transition without introducing a process-wide data race.
type tenantFileFaultHook func(string) error

func publishTenantFileSet(ctx context.Context, plan tenantFileSetPlan, hook tenantFileFaultHook) error {
	return publishTenantFileSetWithProbe(ctx, plan, hook, probeTenantFileAnonymousCapabilities)
}

type tenantFileCapabilityProbe func(tenantFileSetPlan) error

func publishTenantFileSetWithProbe(ctx context.Context, plan tenantFileSetPlan, hook tenantFileFaultHook, probe tenantFileCapabilityProbe) error {
	if ctx == nil {
		return errors.New("tenant file transaction context is required")
	}
	if probe == nil {
		return errors.New("tenant file transaction capability probe is required")
	}
	if err := validateTenantFileSetPlan(plan); err != nil {
		return err
	}
	if err := validateTenantFilePlanDirectories(plan); err != nil {
		return err
	}

	journalExists, err := tenantPathExists(plan.JournalPath)
	if err != nil {
		return err
	}
	journalTemporary := plan.JournalPath + ".tmp"
	if journalExists {
		if err := prepareTenantFileDirectories(plan, unix.Fsync); err != nil {
			return err
		}
		if exists, err := tenantPathExists(journalTemporary); err != nil {
			return err
		} else if exists {
			return errors.New("tenant file transaction has both a journal and an unexpected journal temporary")
		}
		journal, err := loadTenantFileJournal(plan.JournalPath, plan)
		if err != nil {
			return err
		}
		if err := reconcileTenantFileJournal(ctx, plan, journal, hook); err != nil {
			return fmt.Errorf("reconcile pending tenant file transaction: %w", err)
		}
	}
	if err := rejectUnboundTenantFileResidue(plan); err != nil {
		return err
	}

	allDesired, err := tenantFileSetMatchesIntents(plan.Entries)
	if err != nil {
		return err
	}
	if allDesired {
		return nil
	}
	// O_TMPFILE support is established on the exact protected filesystem before
	// directory creation, setfacl, or any other mutation for a new transaction.
	// A failed probe therefore cannot strand even an empty drop-in directory.
	if err := probe(plan); err != nil {
		return err
	}
	if err := prepareTenantFileDirectories(plan, unix.Fsync); err != nil {
		return err
	}
	if exists, err := tenantPathExists(plan.JournalPath); err != nil {
		return err
	} else if exists {
		return errors.New("tenant file transaction journal appeared during exclusive publication")
	}
	if err := rejectUnboundTenantFileResidue(plan); err != nil {
		return err
	}

	journal := tenantFileJournal{SchemaVersion: tenantFileJournalSchema, TenantID: plan.TenantID}
	for _, intent := range plan.Entries {
		before, _, err := inspectTenantFile(intent.Target, tenantFileMaximumSize)
		if err != nil {
			return fmt.Errorf("inspect tenant %s pre-state: %w", intent.Name, err)
		}
		if before.Exists && (before.Mode != uint32(intent.Mode.Perm()) || before.UID != intent.UID || before.GID != intent.GID) {
			return fmt.Errorf("tenant %s pre-state metadata is unsafe", intent.Name)
		}
		journal.Entries = append(journal.Entries, tenantFileJournalEntry{
			Name: intent.Name, Target: intent.Target, Stage: intent.Stage,
			Payload: append([]byte(nil), intent.Payload...), Mode: uint32(intent.Mode.Perm()),
			UID: intent.UID, GID: intent.GID, ACLUser: intent.ACLUser,
			Before: before, Desired: desiredTenantFileJournalState(intent.Payload, intent.Mode, intent.UID, intent.GID),
		})
	}
	if plan.ValidateJournal != nil {
		if err := plan.ValidateJournal(journal.Entries); err != nil {
			return fmt.Errorf("validate tenant file transaction payloads: %w", err)
		}
	}
	if err := writeTenantFileJournal(plan.JournalPath, journal, hook); err != nil {
		return err
	}
	if err := reconcileTenantFileJournal(ctx, plan, journal, hook); err != nil {
		return fmt.Errorf("commit tenant file transaction: %w", err)
	}
	return nil
}

func validateTenantFileSetPlan(plan tenantFileSetPlan) error {
	if plan.TenantID == "" || !cleanTenantFilePath(plan.JournalPath) || len(plan.Entries) != 3 {
		return errors.New("tenant file transaction plan is invalid")
	}
	expectedNames := []string{tenantFileIdentity, tenantFileResources, tenantFileConfig}
	seenPaths := make(map[string]bool, 7)
	for index, entry := range plan.Entries {
		if entry.Name != expectedNames[index] || !cleanTenantFilePath(entry.ProtectedRoot) || !cleanTenantFilePath(entry.Target) || !cleanTenantFilePath(entry.Stage) ||
			filepath.Dir(entry.Target) != filepath.Dir(entry.Stage) || entry.Stage != entry.Target+".workagent-stage" ||
			!tenantPathWithin(entry.ProtectedRoot, filepath.Dir(entry.Target)) ||
			len(entry.Payload) == 0 || len(entry.Payload) > tenantFileMaximumSize || entry.UID != 0 {
			return fmt.Errorf("tenant %s file transaction intent is invalid", entry.Name)
		}
		if seenPaths[entry.Target] || seenPaths[entry.Stage] || entry.Target == entry.Stage {
			return errors.New("tenant file transaction paths overlap")
		}
		seenPaths[entry.Target], seenPaths[entry.Stage] = true, true
		switch entry.Name {
		case tenantFileIdentity, tenantFileResources:
			if entry.Mode.Perm() != 0o644 || entry.GID != 0 || entry.ACLUser != 0 {
				return fmt.Errorf("tenant %s file ownership policy is invalid", entry.Name)
			}
		case tenantFileConfig:
			if entry.Mode.Perm() != 0o640 || entry.GID == 0 || entry.ACLUser == 0 {
				return errors.New("tenant config file ownership or ACL policy is invalid")
			}
		}
	}
	if seenPaths[plan.JournalPath] || seenPaths[plan.JournalPath+".tmp"] ||
		plan.JournalPath != filepath.Join(filepath.Dir(plan.Entries[0].Target), ".workagent-tenant-files.transaction.json") {
		return errors.New("tenant file journal path is invalid or overlaps a payload")
	}
	return nil
}

func cleanTenantFilePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

type tenantFileDirectory struct {
	Root string
	Path string
}

type tenantDirectorySync func(int) error

const tenantDirectoryResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

// prepareTenantFileDirectories deliberately validates every protected root and
// every existing ancestor before it creates any missing directory. This keeps
// a bad later plan entry from leaving an earlier directory behind and ensures
// no setfacl, mkdir, or payload operation ever traverses a symbolic link.
func prepareTenantFileDirectories(plan tenantFileSetPlan, syncFD tenantDirectorySync) error {
	if syncFD == nil {
		return errors.New("tenant directory synchronization is required")
	}
	directories := tenantFilePlanDirectories(plan)
	for _, directory := range directories {
		if err := validateTenantFileDirectoryAncestry(directory.Root, directory.Path); err != nil {
			return fmt.Errorf("validate tenant file parent %s: %w", directory.Path, err)
		}
	}
	for _, directory := range directories {
		if err := ensureTenantFileDirectory(directory.Root, directory.Path, syncFD); err != nil {
			return fmt.Errorf("prepare tenant file parent %s: %w", directory.Path, err)
		}
	}
	return nil
}

func validateTenantFilePlanDirectories(plan tenantFileSetPlan) error {
	for _, directory := range tenantFilePlanDirectories(plan) {
		if err := validateTenantFileDirectoryAncestry(directory.Root, directory.Path); err != nil {
			return fmt.Errorf("validate tenant file parent %s: %w", directory.Path, err)
		}
	}
	return nil
}

func tenantFilePlanDirectories(plan tenantFileSetPlan) []tenantFileDirectory {
	directories := make([]tenantFileDirectory, 0, len(plan.Entries)+1)
	seen := make(map[string]bool, len(plan.Entries)+1)
	add := func(root, path string) {
		key := root + "\x00" + path
		if !seen[key] {
			seen[key] = true
			directories = append(directories, tenantFileDirectory{Root: root, Path: path})
		}
	}
	for _, entry := range plan.Entries {
		add(entry.ProtectedRoot, filepath.Dir(entry.Target))
	}
	add(plan.Entries[0].ProtectedRoot, filepath.Dir(plan.JournalPath))
	return directories
}

func tenantPathWithin(root, candidate string) bool {
	if !cleanTenantFilePath(root) || !cleanTenantFilePath(candidate) {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func tenantDirectoryComponents(root, target string) ([]string, error) {
	if !tenantPathWithin(root, target) {
		return nil, errors.New("tenant file parent is outside its protected root")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("tenant file parent relationship is invalid")
	}
	if relative == "." {
		return nil, nil
	}
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, filepath.Separator) {
			return nil, errors.New("tenant file parent contains an invalid component")
		}
	}
	return components, nil
}

func openTenantProtectedRoot(path string) (int, error) {
	if !cleanTenantFilePath(path) {
		return -1, errors.New("tenant protected root path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return -1, errors.New("tenant protected root contains a symbolic-link component")
		}
		return -1, fmt.Errorf("open tenant protected root: %w", err)
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || unsafeTenantDirectory(opened) {
		_ = unix.Close(fd)
		return -1, errors.New("tenant protected root is not a protected root-owned directory")
	}
	if err := unix.Lstat(path, &named); err != nil || named.Dev != opened.Dev || named.Ino != opened.Ino || named.Mode != opened.Mode || named.Uid != opened.Uid || named.Gid != opened.Gid {
		_ = unix.Close(fd)
		return -1, errors.New("tenant protected root pathname changed while it was opened")
	}
	return fd, nil
}

// openTenantFileDirectory pins an exact directory below a protected root and
// rejects mount or symlink traversal at every component.
func openTenantFileDirectory(root, path string) (int, error) {
	components, err := tenantDirectoryComponents(root, path)
	if err != nil {
		return -1, err
	}
	current, err := openTenantProtectedRoot(root)
	if err != nil {
		return -1, err
	}
	for _, component := range components {
		child, openErr := openTenantDirectoryComponent(current, component)
		if openErr != nil {
			_ = unix.Close(current)
			return -1, fmt.Errorf("open tenant file directory component %s: %w", component, openErr)
		}
		if err := verifyTenantDirectoryComponent(current, component, child); err != nil {
			_ = unix.Close(child)
			_ = unix.Close(current)
			return -1, err
		}
		_ = unix.Close(current)
		current = child
	}
	return current, nil
}

func unsafeTenantDirectory(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0
}

func openTenantDirectoryComponent(parentFD int, name string) (int, error) {
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: tenantDirectoryResolve,
	})
}

func verifyTenantDirectoryComponent(parentFD int, name string, childFD int) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(childFD, &opened); err != nil || unsafeTenantDirectory(opened) {
		return errors.New("tenant file parent component is not a protected root-owned directory")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		named.Dev != opened.Dev || named.Ino != opened.Ino || named.Mode != opened.Mode || named.Uid != opened.Uid || named.Gid != opened.Gid {
		return errors.New("tenant file parent component changed while it was opened")
	}
	return nil
}

func validateTenantFileDirectoryAncestry(root, path string) error {
	components, err := tenantDirectoryComponents(root, path)
	if err != nil {
		return err
	}
	current, err := openTenantProtectedRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for _, component := range components {
		child, openErr := openTenantDirectoryComponent(current, component)
		if errors.Is(openErr, unix.ENOENT) {
			return nil
		}
		if openErr != nil {
			return fmt.Errorf("open existing tenant file parent component %s: %w", component, openErr)
		}
		if err := verifyTenantDirectoryComponent(current, component, child); err != nil {
			_ = unix.Close(child)
			return err
		}
		_ = unix.Close(current)
		current = child
	}
	return nil
}

func ensureTenantFileDirectory(root, path string, syncFD tenantDirectorySync) error {
	components, err := tenantDirectoryComponents(root, path)
	if err != nil {
		return err
	}
	if syncFD == nil {
		return errors.New("tenant directory synchronization is required")
	}
	current, err := openTenantProtectedRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for _, component := range components {
		created := false
		child, openErr := openTenantDirectoryComponent(current, component)
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(current, component, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("create tenant file parent component %s: %w", component, err)
			} else if err == nil {
				created = true
			}
			child, openErr = openTenantDirectoryComponent(current, component)
		}
		if openErr != nil {
			return fmt.Errorf("open tenant file parent component %s: %w", component, openErr)
		}
		if created {
			if err := unix.Fchmod(child, 0o755); err != nil {
				_ = unix.Close(child)
				return fmt.Errorf("set tenant file parent component mode: %w", err)
			}
		}
		if err := verifyTenantDirectoryComponent(current, component, child); err != nil {
			_ = unix.Close(child)
			return err
		}
		// Sync existing components too: a previous process may have died after
		// mkdirat but before syncing the parent. Retrying must make that visible
		// directory durable even though this invocation did not create it.
		if err := syncFD(child); err != nil {
			_ = unix.Close(child)
			return fmt.Errorf("sync tenant file parent component: %w", err)
		}
		if err := syncFD(current); err != nil {
			_ = unix.Close(child)
			return fmt.Errorf("sync tenant file parent ancestry: %w", err)
		}
		_ = unix.Close(current)
		current = child
	}
	return nil
}

func tenantPathExists(path string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Lstat(path, &stat)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// rejectUnboundTenantFileResidue never removes a reserved pathname unless a
// durable journal has first bound that exact name to a transaction. A root-
// owned regular inode is not provenance: it may have been placed by an
// operator or another privileged component. Pre-journal crashes therefore
// fail closed and require explicit operator investigation instead of deleting
// an unknown file.
func rejectUnboundTenantFileResidue(plan tenantFileSetPlan) error {
	paths := []string{plan.JournalPath + ".tmp"}
	for _, entry := range plan.Entries {
		paths = append(paths, entry.Stage)
	}
	for _, path := range paths {
		exists, err := tenantPathExists(path)
		if err != nil {
			return fmt.Errorf("inspect unbound tenant transaction residue %s: %w", filepath.Base(path), err)
		}
		if exists {
			return fmt.Errorf("unbound tenant transaction residue exists at reserved path %s", filepath.Base(path))
		}
	}
	return nil
}

func tenantFileSetMatchesIntents(entries []tenantFileIntent) (bool, error) {
	for _, entry := range entries {
		state, _, err := inspectTenantFile(entry.Target, tenantFileMaximumSize)
		if err != nil {
			return false, err
		}
		matched, err := tenantFileStateMatchesIntent(entry.Target, state, entry)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func tenantFileStateMatchesIntent(path string, state tenantFileState, intent tenantFileIntent) (bool, error) {
	if !state.Exists || state.SHA256 != tenantPayloadSHA256(intent.Payload) || state.Mode != uint32(intent.Mode.Perm()) || state.UID != intent.UID || state.GID != intent.GID || state.Size != int64(len(intent.Payload)) {
		return false, nil
	}
	if intent.ACLUser != 0 {
		if err := posixacl.VerifyExclusiveUserPermissions(path, intent.ACLUser, 0o4); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func prepareTenantFileStage(ctx context.Context, intent tenantFileIntent, hook tenantFileFaultHook) (tenantFileState, error) {
	return prepareTenantFileStageMode(ctx, intent, hook, false)
}

// prepareJournalBoundTenantFileStage exposes every anonymous-inode transition
// only after a durable journal has bound the exact stage path. No pathname is
// linked until payload, ownership, mode, and ACL have all been synced and
// read back through the descriptor. Thus a power loss can leave either no
// stage or a complete semantic stage, never a named partially-authored inode.
func prepareJournalBoundTenantFileStage(ctx context.Context, intent tenantFileIntent, hook tenantFileFaultHook) (tenantFileState, error) {
	return prepareTenantFileStageMode(ctx, intent, hook, true)
}

func prepareTenantFileStageMode(ctx context.Context, intent tenantFileIntent, hook tenantFileFaultHook, journalBound bool) (tenantFileState, error) {
	if exists, err := tenantPathExists(intent.Stage); err != nil {
		return tenantFileState{}, err
	} else if exists {
		return tenantFileState{}, errors.New("tenant file stage already exists")
	}
	parentFD, err := openTenantFileDirectory(intent.ProtectedRoot, filepath.Dir(intent.Stage))
	if err != nil {
		return tenantFileState{}, fmt.Errorf("open protected tenant stage directory: %w", err)
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return tenantFileState{}, fmt.Errorf("create anonymous tenant file stage: %w", err)
	}
	file := os.NewFile(uintptr(fd), "anonymous-tenant-file-stage")
	if file == nil {
		_ = unix.Close(fd)
		return tenantFileState{}, errors.New("adopt tenant file stage")
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer closeFile()
	if journalBound {
		if err := tenantFileHook(hook, "stage-anonymous-created:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	// Establish the exact disposable work state before any payload byte. This
	// state is also the only named partial-stage form recovery is authorized to
	// remove when a valid journal binds the pathname.
	if err := file.Chmod(0o600); err != nil {
		return tenantFileState{}, err
	}
	if err := file.Chown(0, 0); err != nil {
		return tenantFileState{}, err
	}
	if err := clearTenantFileACL(fd); err != nil {
		return tenantFileState{}, err
	}
	if err := file.Sync(); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-work-synced:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := writeTenantFileStagePayload(file, intent, hook, journalBound); err != nil {
		return tenantFileState{}, err
	}
	if err := file.Sync(); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-content-synced:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := file.Chown(int(intent.UID), int(intent.GID)); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-final-owner:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if intent.ACLUser != 0 {
		if err := posixacl.SetExclusiveUserPermissionsFD(fd, intent.ACLUser, 0o4); err != nil {
			return tenantFileState{}, err
		}
	} else if err := clearTenantFileACL(fd); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-final-acl:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := file.Chmod(intent.Mode.Perm()); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-final-mode:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := file.Sync(); err != nil {
		return tenantFileState{}, err
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-final-synced:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := verifyAnonymousTenantFile(fd, intent); err != nil {
		return tenantFileState{}, fmt.Errorf("verify anonymous tenant stage: %w", err)
	}
	if err := unix.Linkat(fd, "", parentFD, filepath.Base(intent.Stage), unix.AT_EMPTY_PATH); err != nil {
		return tenantFileState{}, fmt.Errorf("link anonymous tenant file stage: %w", err)
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-linked:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := verifyLinkedTenantFile(parentFD, filepath.Base(intent.Stage), fd, intent); err != nil {
		return tenantFileState{}, fmt.Errorf("verify linked tenant stage: %w", err)
	}
	if journalBound {
		if err := tenantFileHook(hook, "stage-linked-verified:"+intent.Name); err != nil {
			return tenantFileState{}, err
		}
	}
	if err := unix.Fsync(parentFD); err != nil {
		return tenantFileState{}, err
	}
	if err := tenantFileHook(hook, "stage-durable:"+intent.Name); err != nil {
		return tenantFileState{}, err
	}
	if err := closeFile(); err != nil {
		return tenantFileState{}, err
	}
	state, _, err := inspectTenantFile(intent.Stage, tenantFileMaximumSize)
	if err != nil {
		return tenantFileState{}, err
	}
	matched, err := tenantFileStateMatchesIntent(intent.Stage, state, intent)
	if err != nil || !matched {
		return tenantFileState{}, errors.New("staged tenant file does not match its intended content and metadata")
	}
	return state, nil
}

func writeTenantFileStagePayload(file *os.File, intent tenantFileIntent, hook tenantFileFaultHook, journalBound bool) error {
	if file == nil || len(intent.Payload) == 0 {
		return errors.New("tenant file stage payload writer is invalid")
	}
	if journalBound && hook != nil {
		for index := range intent.Payload {
			written, err := file.Write(intent.Payload[index : index+1])
			if err != nil || written != 1 {
				return errors.New("write journal-bound tenant file stage byte")
			}
			if err := tenantFileHook(hook, fmt.Sprintf("stage-write-byte:%s:%d", intent.Name, index+1)); err != nil {
				return err
			}
		}
		return nil
	}
	for offset := 0; offset < len(intent.Payload); {
		written, err := file.Write(intent.Payload[offset:])
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		offset += written
	}
	return nil
}

func verifyAnonymousTenantFile(fd int, intent tenantFileIntent) error {
	return verifyTenantFileDescriptor(fd, intent, 0)
}

func verifyLinkedTenantFile(parentFD int, name string, fd int, intent tenantFileIntent) error {
	if parentFD < 0 || name == "" || name == "." || strings.ContainsRune(name, filepath.Separator) {
		return errors.New("linked tenant file pathname is invalid")
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return errors.New("inspect linked tenant file descriptor")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		return errors.New("linked tenant file pathname does not name its anonymous inode")
	}
	if err := verifyTenantFileDescriptor(fd, intent, 1); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &opened); err != nil {
		return errors.New("reinspect linked tenant file descriptor")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		return errors.New("linked tenant file pathname changed during verification")
	}
	return nil
}

func verifyTenantFileDescriptor(fd int, intent tenantFileIntent, expectedLinks uint64) error {
	if fd < 0 || len(intent.Payload) == 0 || len(intent.Payload) > tenantFileMaximumSize || (expectedLinks != 0 && expectedLinks != 1) {
		return errors.New("tenant file descriptor verification is invalid")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Nlink != expectedLinks || before.Mode&0o7777 != uint32(intent.Mode.Perm()) ||
		before.Uid != intent.UID || before.Gid != intent.GID || before.Size != int64(len(intent.Payload)) {
		return errors.New("tenant file descriptor metadata differs from its intent")
	}
	payload := make([]byte, len(intent.Payload))
	for offset := 0; offset < len(payload); {
		read, err := unix.Pread(fd, payload[offset:], int64(offset))
		if err != nil {
			return fmt.Errorf("read back tenant file descriptor: %w", err)
		}
		if read <= 0 {
			return io.ErrUnexpectedEOF
		}
		offset += read
	}
	if !bytes.Equal(payload, intent.Payload) {
		return errors.New("tenant file descriptor payload differs from its intent")
	}
	aclPayload, err := readTenantFileACL(fd)
	if err != nil {
		return err
	}
	if intent.ACLUser == 0 {
		if len(aclPayload) != 0 {
			return errors.New("tenant file descriptor contains an unexpected ACL")
		}
	} else if len(aclPayload) == 0 {
		return errors.New("tenant config descriptor omits its ACL")
	} else if err := posixacl.VerifyExclusiveUserPermissionsFD(fd, intent.ACLUser, 0o4); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameTenantFileStat(before, after) {
		return errors.New("tenant file descriptor changed during verification")
	}
	return nil
}

func probeTenantFileAnonymousJournal(protectedRoot string) error {
	rootFD, err := openTenantProtectedRoot(protectedRoot)
	if err != nil {
		return fmt.Errorf("open tenant journal protected root: %w", err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat(rootFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("tenant file transactions require O_TMPFILE on %s: %w", protectedRoot, err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || stat.Uid != 0 {
		return errors.New("anonymous tenant journal capability returned an unsafe inode")
	}
	return nil
}

func probeTenantFileAnonymousCapabilities(plan tenantFileSetPlan) error {
	seen := make(map[string]bool, len(plan.Entries))
	for _, entry := range plan.Entries {
		if seen[entry.ProtectedRoot] {
			continue
		}
		seen[entry.ProtectedRoot] = true
		if err := probeTenantFileAnonymousJournal(entry.ProtectedRoot); err != nil {
			return err
		}
	}
	return nil
}

func writeTenantFileJournal(path string, journal tenantFileJournal, hook tenantFileFaultHook) error {
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > tenantJournalMaximumSize {
		return errors.New("tenant file transaction journal is too large")
	}
	parent := filepath.Dir(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open tenant file journal directory: %w", err)
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != 0 || parentStat.Mode&0o022 != 0 {
		return errors.New("tenant file journal directory is unsafe")
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create anonymous tenant file transaction journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), "anonymous-tenant-file-journal")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt anonymous tenant file transaction journal")
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer closeFile()
	if err := tenantFileHook(hook, "journal-anonymous-created"); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := clearTenantFileACL(fd); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "journal-anonymous-write-started"); err != nil {
		return err
	}
	for offset := 0; offset < len(payload); {
		written, err := file.Write(payload[offset:])
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		offset += written
	}
	if err := tenantFileHook(hook, "journal-anonymous-written"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "journal-anonymous-synced"); err != nil {
		return err
	}
	if err := unix.Linkat(fd, "", parentFD, filepath.Base(path), unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("link anonymous tenant file transaction journal: %w", err)
	}
	if err := tenantFileHook(hook, "journal-linked"); err != nil {
		return err
	}
	if err := verifyLinkedTenantJournal(parentFD, filepath.Base(path), fd, payload); err != nil {
		return fmt.Errorf("verify linked tenant file transaction journal: %w", err)
	}
	if err := tenantFileHook(hook, "journal-linked-verified"); err != nil {
		return err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return err
	}
	return tenantFileHook(hook, "journal-durable")
}

func verifyLinkedTenantJournal(parentFD int, name string, fd int, payload []byte) error {
	return verifyLinkedProtectedJournal(parentFD, name, fd, payload, tenantJournalMaximumSize)
}

func verifyLinkedProtectedJournal(parentFD int, name string, fd int, payload []byte, maximum int) error {
	if parentFD < 0 || fd < 0 || name == "" || name == "." || strings.ContainsRune(name, filepath.Separator) ||
		maximum <= 0 || len(payload) == 0 || len(payload) > maximum {
		return errors.New("linked tenant journal verification is invalid")
	}
	var before, named unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
		before.Mode&0o7777 != 0o600 || before.Uid != 0 || before.Gid != 0 || before.Size != int64(len(payload)) {
		return errors.New("linked tenant journal descriptor metadata is unsafe")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(before, named) {
		return errors.New("linked tenant journal pathname does not name its anonymous inode")
	}
	readback := make([]byte, len(payload))
	for offset := 0; offset < len(readback); {
		read, err := unix.Pread(fd, readback[offset:], int64(offset))
		if err != nil {
			return fmt.Errorf("read back linked tenant journal: %w", err)
		}
		if read <= 0 {
			return io.ErrUnexpectedEOF
		}
		offset += read
	}
	if !bytes.Equal(readback, payload) {
		return errors.New("linked tenant journal content differs from its durable intent")
	}
	if acl, err := readTenantFileACL(fd); err != nil || len(acl) != 0 {
		return errors.New("linked tenant journal ACL is unsafe")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameTenantFileStat(before, after) {
		return errors.New("linked tenant journal descriptor changed during verification")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(after, named) {
		return errors.New("linked tenant journal pathname changed during verification")
	}
	return nil
}

func loadTenantFileJournal(path string, plan tenantFileSetPlan) (tenantFileJournal, error) {
	state, payload, err := inspectTenantFile(path, tenantJournalMaximumSize)
	if err != nil {
		return tenantFileJournal{}, fmt.Errorf("inspect tenant file transaction journal: %w", err)
	}
	if !state.Exists || state.Mode != 0o600 || state.UID != 0 || state.GID != 0 || state.ACLSHA256 != "" {
		return tenantFileJournal{}, errors.New("tenant file transaction journal metadata is unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal tenantFileJournal
	if err := decoder.Decode(&journal); err != nil {
		return tenantFileJournal{}, errors.New("tenant file transaction journal is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return tenantFileJournal{}, errors.New("tenant file transaction journal contains trailing data")
	}
	if err := validateTenantFileJournal(journal, plan); err != nil {
		return tenantFileJournal{}, err
	}
	return journal, nil
}

func validateTenantFileJournal(journal tenantFileJournal, plan tenantFileSetPlan) error {
	if journal.SchemaVersion != tenantFileJournalSchema || journal.TenantID != plan.TenantID || len(journal.Entries) != len(plan.Entries) {
		return errors.New("tenant file transaction journal identity is invalid")
	}
	for index, entry := range journal.Entries {
		expected := plan.Entries[index]
		if entry.Name != expected.Name || entry.Target != expected.Target || entry.Stage != expected.Stage ||
			entry.Mode != uint32(expected.Mode.Perm()) || entry.UID != expected.UID || entry.GID != expected.GID ||
			entry.ACLUser != expected.ACLUser ||
			len(entry.Payload) == 0 || len(entry.Payload) > tenantFileMaximumSize {
			return fmt.Errorf("tenant file transaction journal entry %d is invalid", index)
		}
		if expected.Name == tenantFileConfig {
			if entry.ACLUser == 0 {
				return errors.New("tenant config transaction journal omits its ACL identity")
			}
		} else if entry.ACLUser != 0 {
			return errors.New("tenant drop-in transaction journal contains an unexpected ACL identity")
		}
		if err := entry.Before.validate(); err != nil {
			return fmt.Errorf("tenant file transaction pre-state is invalid: %w", err)
		}
		if entry.Before.Exists && (entry.Before.Mode != entry.Mode || entry.Before.UID != entry.UID || entry.Before.GID != entry.GID) {
			return errors.New("tenant file transaction pre-state ownership is invalid")
		}
		if err := entry.Desired.validate(); err != nil || entry.Desired != desiredTenantFileJournalState(entry.Payload, os.FileMode(entry.Mode), entry.UID, entry.GID) {
			return errors.New("tenant file transaction desired state is invalid")
		}
	}
	if plan.ValidateJournal != nil {
		if err := plan.ValidateJournal(journal.Entries); err != nil {
			return fmt.Errorf("tenant file transaction payload relationship is invalid: %w", err)
		}
	}
	return nil
}

func desiredTenantFileJournalState(payload []byte, mode os.FileMode, uid, gid uint32) tenantFileState {
	return tenantFileState{
		Exists: true, SHA256: tenantPayloadSHA256(payload), Mode: uint32(mode.Perm()),
		UID: uid, GID: gid, Size: int64(len(payload)),
	}
}

func tenantFileStateMatchesJournalDesired(path string, state tenantFileState, entry tenantFileJournalEntry) (bool, error) {
	desired := entry.Desired
	if !state.Exists || state.SHA256 != desired.SHA256 || state.Mode != desired.Mode || state.UID != desired.UID || state.GID != desired.GID || state.Size != desired.Size {
		return false, nil
	}
	if entry.ACLUser == 0 {
		return state.ACLSHA256 == "", nil
	}
	if state.ACLSHA256 == "" {
		return false, nil
	}
	if err := posixacl.VerifyExclusiveUserPermissions(path, entry.ACLUser, 0o4); err != nil {
		return false, nil
	}
	return true, nil
}

func (state tenantFileState) validate() error {
	if !state.Exists {
		if state != (tenantFileState{}) {
			return errors.New("absent tenant file state contains metadata")
		}
		return nil
	}
	if !validTenantFileSHA256(state.SHA256) || state.Mode == 0 || state.Mode > 0o7777 || state.Size <= 0 || state.Size > tenantFileMaximumSize ||
		(state.ACLSHA256 != "" && !validTenantFileSHA256(state.ACLSHA256)) {
		return errors.New("tenant file state metadata is invalid")
	}
	return nil
}

func reconcileTenantFileJournal(ctx context.Context, plan tenantFileSetPlan, journal tenantFileJournal, hook tenantFileFaultHook) error {
	if err := validateTenantFileJournal(journal, plan); err != nil {
		return err
	}
	for index, entry := range journal.Entries {
		if err := reconcileTenantFileJournalEntry(ctx, plan.Entries[index], entry, hook); err != nil {
			return fmt.Errorf("reconcile tenant %s file: %w", entry.Name, err)
		}
	}
	for _, entry := range journal.Entries {
		state, _, err := inspectTenantFile(entry.Target, tenantFileMaximumSize)
		matched, matchErr := tenantFileStateMatchesJournalDesired(entry.Target, state, entry)
		if err != nil || matchErr != nil || !matched {
			return errors.New("tenant file transaction did not converge to its desired state")
		}
		if exists, err := tenantPathExists(entry.Stage); err != nil || exists {
			return errors.New("tenant file transaction left a staged file")
		}
	}
	syncedParents := make(map[string]bool)
	for _, entry := range journal.Entries {
		parent := filepath.Dir(entry.Target)
		if syncedParents[parent] {
			continue
		}
		if err := syncTenantFileDirectory(parent); err != nil {
			return err
		}
		syncedParents[parent] = true
	}
	if err := os.Remove(plan.JournalPath); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "journal-removed"); err != nil {
		return err
	}
	if err := syncTenantFileDirectory(filepath.Dir(plan.JournalPath)); err != nil {
		return err
	}
	return tenantFileHook(hook, "transaction-complete")
}

func reconcileTenantFileJournalEntry(ctx context.Context, intent tenantFileIntent, entry tenantFileJournalEntry, hook tenantFileFaultHook) error {
	if intent.Name != entry.Name || intent.Target != entry.Target || intent.Stage != entry.Stage {
		return errors.New("tenant file journal entry is not bound to its validated intent")
	}
	target, _, err := inspectTenantFile(entry.Target, tenantFileMaximumSize)
	if err != nil {
		return err
	}
	targetDesired, err := tenantFileStateMatchesJournalDesired(entry.Target, target, entry)
	if err != nil {
		return err
	}
	if targetDesired {
		return removeKnownTenantStage(entry, hook)
	}
	if target != entry.Before {
		return errors.New("tenant file changed outside its transaction pre-state (CAS mismatch)")
	}
	stage, _, stageErr := inspectTenantFile(entry.Stage, tenantFileMaximumSize)
	if stageErr != nil {
		removed, removeErr := removeJournalBoundPartialStage(intent, entry, hook)
		if removeErr != nil {
			return fmt.Errorf("inspect or clear journal-bound partial tenant stage: %w", removeErr)
		}
		if !removed {
			return stageErr
		}
		stage = tenantFileState{}
	}
	stageDesired, matchErr := tenantFileStateMatchesJournalDesired(entry.Stage, stage, entry)
	if matchErr != nil {
		return matchErr
	}
	if stage.Exists && !stageDesired {
		if stage != entry.Before {
			removed, removeErr := removeJournalBoundPartialStage(intent, entry, hook)
			if removeErr != nil {
				return fmt.Errorf("clear journal-bound partial tenant stage: %w", removeErr)
			}
			if !removed {
				return errors.New("tenant file stage is not the intended new file, displaced pre-state, or an exact journal-bound work inode")
			}
			stage = tenantFileState{}
		} else {
			if err := os.Remove(entry.Stage); err != nil {
				return err
			}
			if err := syncTenantFileDirectory(filepath.Dir(entry.Stage)); err != nil {
				return err
			}
			stage = tenantFileState{}
		}
	}
	if !stage.Exists {
		journalIntent := tenantFileIntent{
			Name: entry.Name, ProtectedRoot: intent.ProtectedRoot, Target: entry.Target, Stage: entry.Stage, Payload: entry.Payload,
			Mode: os.FileMode(entry.Mode), UID: entry.UID, GID: entry.GID, ACLUser: entry.ACLUser,
		}
		stage, err = prepareJournalBoundTenantFileStage(ctx, journalIntent, hook)
		if err != nil {
			return err
		}
	}
	stageDesired, matchErr = tenantFileStateMatchesJournalDesired(entry.Stage, stage, entry)
	if matchErr != nil || !stageDesired {
		return errors.New("recreated tenant file stage differs from the durable journal")
	}

	if entry.Before.Exists {
		if err := unix.Renameat2(unix.AT_FDCWD, entry.Stage, unix.AT_FDCWD, entry.Target, unix.RENAME_EXCHANGE); err != nil {
			return fmt.Errorf("exchange tenant file with staged replacement: %w", err)
		}
	} else if err := unix.Renameat2(unix.AT_FDCWD, entry.Stage, unix.AT_FDCWD, entry.Target, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish initially absent tenant file: %w", err)
	}
	if err := tenantFileHook(hook, "file-published:"+entry.Name); err != nil {
		return err
	}

	published, _, publishedErr := inspectTenantFile(entry.Target, tenantFileMaximumSize)
	publishedDesired, matchErr := tenantFileStateMatchesJournalDesired(entry.Target, published, entry)
	if publishedErr != nil || matchErr != nil || !publishedDesired {
		return errors.New("published tenant file does not match the durable journal")
	}
	if entry.Before.Exists {
		displaced, _, displacedErr := inspectTenantFile(entry.Stage, tenantFileMaximumSize)
		if displacedErr != nil || displaced != entry.Before {
			rollbackErr := unix.Renameat2(unix.AT_FDCWD, entry.Stage, unix.AT_FDCWD, entry.Target, unix.RENAME_EXCHANGE)
			_ = syncTenantFileDirectory(filepath.Dir(entry.Target))
			return fmt.Errorf("tenant file compare-and-swap displaced an unexpected pre-state; rollback error: %v", rollbackErr)
		}
	}
	if err := syncTenantFileDirectory(filepath.Dir(entry.Target)); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "file-publish-durable:"+entry.Name); err != nil {
		return err
	}
	return removeKnownTenantStage(entry, hook)
}

// removeJournalBoundPartialStage removes only the exact reserved pathname
// authenticated by a durable, fully validated journal and its validated
// protected-root intent. The disposable work state is deliberately unique:
// root:root 0600, no ACL, one regular-file link. Its bytes are irrelevant,
// because a power loss may persist arbitrary blocks. Any partial final
// metadata is rejected instead of guessed or deleted.
func removeJournalBoundPartialStage(intent tenantFileIntent, entry tenantFileJournalEntry, hook tenantFileFaultHook) (bool, error) {
	if intent.Name != entry.Name || intent.Stage != entry.Stage || !cleanTenantFilePath(intent.ProtectedRoot) ||
		!cleanTenantFilePath(entry.Stage) || filepath.Base(entry.Stage) == "." || len(entry.Payload) == 0 || len(entry.Payload) > tenantFileMaximumSize {
		return false, errors.New("journal-bound tenant stage identity is invalid")
	}
	parentFD, err := openTenantFileDirectory(intent.ProtectedRoot, filepath.Dir(entry.Stage))
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat2(parentFD, filepath.Base(entry.Stage), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: tenantDirectoryResolve,
	})
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("open journal-bound tenant stage without following links")
	}
	file := os.NewFile(uintptr(fd), entry.Stage)
	if file == nil {
		_ = unix.Close(fd)
		return false, errors.New("adopt journal-bound tenant stage")
	}
	defer file.Close()
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return false, errors.New("inspect journal-bound tenant stage")
	}
	if err := unix.Fstatat(parentFD, filepath.Base(entry.Stage), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		return false, errors.New("journal-bound tenant stage pathname changed")
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || opened.Uid != 0 || opened.Gid != 0 || opened.Mode&0o7777 != 0o600 {
		return false, errors.New("journal-bound partial tenant stage is not in its exact disposable work state")
	}
	if acl, err := readTenantFileACL(fd); err != nil || len(acl) != 0 {
		return false, errors.New("journal-bound partial tenant stage work ACL is unsafe")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameTenantFileStat(opened, after) {
		return false, errors.New("journal-bound partial tenant stage changed while inspected")
	}
	if err := unix.Fstatat(parentFD, filepath.Base(entry.Stage), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(after, named) {
		return false, errors.New("journal-bound partial tenant stage pathname changed before removal")
	}
	if err := unix.Unlinkat(parentFD, filepath.Base(entry.Stage), 0); err != nil {
		return false, err
	}
	if err := tenantFileHook(hook, "stage-recreate-partial-removed:"+entry.Name); err != nil {
		return false, err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return false, err
	}
	if err := tenantFileHook(hook, "stage-recreate-partial-removal-durable:"+entry.Name); err != nil {
		return false, err
	}
	return true, nil
}

func removeKnownTenantStage(entry tenantFileJournalEntry, hook tenantFileFaultHook) error {
	stage, _, err := inspectTenantFile(entry.Stage, tenantFileMaximumSize)
	if err != nil {
		return err
	}
	if !stage.Exists {
		// A previous process may have unlinked this stage and crashed before
		// syncing its parent. Persist the observed absence before allowing the
		// durable journal to be removed.
		return syncTenantFileDirectory(filepath.Dir(entry.Stage))
	}
	desired, matchErr := tenantFileStateMatchesJournalDesired(entry.Stage, stage, entry)
	if matchErr != nil {
		return matchErr
	}
	if stage != entry.Before && !desired {
		return errors.New("tenant file transaction stage contains unexpected state")
	}
	if err := os.Remove(entry.Stage); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "stage-removed:"+entry.Name); err != nil {
		return err
	}
	if err := syncTenantFileDirectory(filepath.Dir(entry.Stage)); err != nil {
		return err
	}
	return tenantFileHook(hook, "stage-removal-durable:"+entry.Name)
}

func inspectTenantFile(path string, maximum int64) (tenantFileState, []byte, error) {
	if !cleanTenantFilePath(path) || maximum <= 0 {
		return tenantFileState{}, nil, errors.New("tenant file inspection path or bound is invalid")
	}
	var named unix.Stat_t
	if err := unix.Lstat(path, &named); errors.Is(err, unix.ENOENT) {
		return tenantFileState{}, nil, nil
	} else if err != nil {
		return tenantFileState{}, nil, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFREG || named.Nlink != 1 || named.Size <= 0 || named.Size > maximum {
		return tenantFileState{}, nil, errors.New("tenant file is not a bounded single-link regular file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return tenantFileState{}, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return tenantFileState{}, nil, errors.New("adopt inspected tenant file")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !sameTenantFileStat(named, before) {
		return tenantFileState{}, nil, errors.New("tenant file changed while it was opened")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum || int64(len(payload)) != before.Size {
		return tenantFileState{}, nil, errors.New("tenant file changed while it was read")
	}
	aclPayload, err := readTenantFileACL(fd)
	if err != nil {
		return tenantFileState{}, nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameTenantFileStat(before, after) {
		return tenantFileState{}, nil, errors.New("tenant file metadata changed while it was read")
	}
	state := tenantFileState{
		Exists: true, SHA256: tenantPayloadSHA256(payload), Mode: before.Mode & 0o7777,
		UID: before.Uid, GID: before.Gid, Size: before.Size,
	}
	if len(aclPayload) != 0 {
		state.ACLSHA256 = tenantPayloadSHA256(aclPayload)
	}
	return state, payload, nil
}

func sameTenantFileStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Nlink == right.Nlink &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size &&
		left.Mtim.Sec == right.Mtim.Sec && left.Mtim.Nsec == right.Mtim.Nsec &&
		left.Ctim.Sec == right.Ctim.Sec && left.Ctim.Nsec == right.Ctim.Nsec
}

func readTenantFileACL(fd int) ([]byte, error) {
	size, err := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect tenant file ACL size: %w", err)
	}
	if size <= 0 || size > 64*1024 {
		return nil, errors.New("tenant file ACL is oversized")
	}
	payload := make([]byte, size)
	read, err := unix.Fgetxattr(fd, "system.posix_acl_access", payload)
	if err != nil || read != size {
		return nil, errors.New("tenant file ACL changed while it was read")
	}
	return payload, nil
}

func clearTenantFileACL(fd int) error {
	err := unix.Fremovexattr(fd, "system.posix_acl_access")
	if err == nil || errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("clear inherited tenant file ACL: %w", err)
}

func syncTenantFileDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func tenantFileHook(hook tenantFileFaultHook, point string) error {
	if hook == nil {
		return nil
	}
	if err := hook(point); err != nil {
		return fmt.Errorf("tenant file transaction interrupted at %s: %w", point, err)
	}
	return nil
}

func tenantPayloadSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validTenantFileSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
