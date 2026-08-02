package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

const (
	tenantFileBatchJournalSchema = 1
	tenantFileBatchJournalName   = ".workagent-tenant-batch.transaction.json"
	// tenantFileBatchJournalMaximum is the aggregate full-catalog transaction
	// limit, not a per-member allowance. Every successful catalog generation
	// must fit its complete canonical intent (all members, payloads, paths,
	// Before states, and Desired states) in this single durable marker.
	tenantFileBatchJournalMaximum = 64 * 1024 * 1024
)

type tenantFileBatchJournal struct {
	SchemaVersion int                     `json:"schema_version"`
	PortalSHA256  string                  `json:"portal_sha256"`
	SystemdRoot   string                  `json:"systemd_root"`
	Members       []tenantFileBatchMember `json:"members"`
}

type tenantFileBatchMember struct {
	Tenant  config.Tenant            `json:"tenant"`
	Entries []tenantFileJournalEntry `json:"entries"`
}

func tenantFileBatchJournalPath(portal config.Portal) string {
	return filepath.Join(portal.Paths.TenantConfigs, tenantFileBatchJournalName)
}

func makeTenantFileBatchJournal(portal config.Portal, systemdRoot string, publications []tenantFilePublication) (tenantFileBatchJournal, error) {
	portalPayload, err := json.Marshal(portal)
	if err != nil {
		return tenantFileBatchJournal{}, err
	}
	journal := tenantFileBatchJournal{
		SchemaVersion: tenantFileBatchJournalSchema,
		PortalSHA256:  tenantPayloadSHA256(portalPayload),
		SystemdRoot:   systemdRoot,
	}
	ordered := append([]tenantFilePublication(nil), publications...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].tenant.TenantID < ordered[j].tenant.TenantID })
	for _, publication := range ordered {
		member := tenantFileBatchMember{Tenant: publication.tenant}
		for _, intent := range publication.plan.Entries {
			before, _, err := inspectTenantFile(intent.Target, tenantFileMaximumSize)
			if err != nil {
				return tenantFileBatchJournal{}, fmt.Errorf("inspect tenant %s batch pre-state: %w", intent.Name, err)
			}
			if before.Exists && (before.Mode != uint32(intent.Mode.Perm()) || before.UID != intent.UID || before.GID != intent.GID) {
				return tenantFileBatchJournal{}, fmt.Errorf("tenant %s batch pre-state metadata is unsafe", intent.Name)
			}
			member.Entries = append(member.Entries, tenantFileJournalEntry{
				Name: intent.Name, Target: intent.Target, Stage: intent.Stage,
				Payload: append([]byte(nil), intent.Payload...), Mode: uint32(intent.Mode.Perm()),
				UID: intent.UID, GID: intent.GID, ACLUser: intent.ACLUser,
				Before: before, Desired: desiredTenantFileJournalState(intent.Payload, intent.Mode, intent.UID, intent.GID),
			})
		}
		journal.Members = append(journal.Members, member)
	}
	if err := validateTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		return tenantFileBatchJournal{}, err
	}
	return journal, nil
}

func validateTenantFileBatchJournal(portal config.Portal, systemdRoot string, journal tenantFileBatchJournal) error {
	if journal.SchemaVersion != tenantFileBatchJournalSchema || !validTenantFileSHA256(journal.PortalSHA256) ||
		!cleanTenantFilePath(systemdRoot) || journal.SystemdRoot != systemdRoot || len(journal.Members) == 0 || len(journal.Members) > 10000 {
		return errors.New("tenant batch transaction journal identity is invalid")
	}
	portalPayload, err := json.Marshal(portal)
	if err != nil || journal.PortalSHA256 != tenantPayloadSHA256(portalPayload) {
		return errors.New("tenant batch transaction journal is bound to a different Portal catalog")
	}
	for index, member := range journal.Members {
		tenant := member.Tenant
		if index > 0 && journal.Members[index-1].Tenant.TenantID >= tenant.TenantID {
			return errors.New("tenant batch transaction journal order is invalid")
		}
		if err := tenant.Validate(); err != nil {
			return fmt.Errorf("tenant batch transaction contains an invalid tenant: %w", err)
		}
		if err := ValidateTenantBinding(portal, tenant); err != nil {
			return fmt.Errorf("tenant batch transaction binding is invalid: %w", err)
		}
		publication, err := prepareTenantFilePublication(portal, tenant, systemdRoot)
		if err != nil {
			return fmt.Errorf("derive tenant batch transaction member: %w", err)
		}
		local := tenantFileJournal{
			SchemaVersion: tenantFileJournalSchema,
			TenantID:      tenant.TenantID,
			Entries:       member.Entries,
		}
		if err := validateTenantFileJournal(local, publication.plan); err != nil {
			return fmt.Errorf("tenant batch transaction member %s is invalid: %w", tenant.TenantID, err)
		}
		for entryIndex, entry := range member.Entries {
			if !bytes.Equal(entry.Payload, publication.plan.Entries[entryIndex].Payload) {
				return fmt.Errorf("tenant batch transaction member %s payload %d differs from its canonical tenant intent", tenant.TenantID, entryIndex)
			}
		}
	}
	if _, err := encodeTenantFileBatchJournal(journal, tenantFileBatchJournalMaximum); err != nil {
		return err
	}
	return nil
}

func writeTenantFileBatchJournal(portal config.Portal, systemdRoot string, journal tenantFileBatchJournal) error {
	return writeTenantFileBatchJournalWithHook(portal, systemdRoot, journal, nil)
}

func writeTenantFileBatchJournalWithHook(portal config.Portal, systemdRoot string, journal tenantFileBatchJournal, hook tenantFileFaultHook) error {
	if err := validateTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		return err
	}
	payload, err := encodeTenantFileBatchJournal(journal, tenantFileBatchJournalMaximum)
	if err != nil {
		return err
	}
	rootFD, err := openTenantProtectedRoot(portal.Paths.TenantConfigs)
	if err != nil {
		return fmt.Errorf("open tenant batch journal root: %w", err)
	}
	defer unix.Close(rootFD)
	if err := unix.Fstatat(rootFD, tenantFileBatchJournalName, &unix.Stat_t{}, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return errors.New("tenant batch transaction journal already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect tenant batch transaction journal: %w", err)
	}
	fd, err := unix.Openat(rootFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create anonymous tenant batch transaction journal: %w", err)
	}
	if err := tenantFileHook(hook, "batch-journal-anonymous-created"); err != nil {
		_ = unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), "anonymous-tenant-batch-journal")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt anonymous tenant batch transaction journal")
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := clearTenantFileACL(fd); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "batch-journal-write-started"); err != nil {
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
	if err := tenantFileHook(hook, "batch-journal-anonymous-written"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "batch-journal-anonymous-synced"); err != nil {
		return err
	}
	if err := unix.Linkat(fd, "", rootFD, tenantFileBatchJournalName, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("link anonymous tenant batch transaction journal: %w", err)
	}
	if err := tenantFileHook(hook, "batch-journal-linked"); err != nil {
		return err
	}
	if err := verifyLinkedProtectedJournal(rootFD, tenantFileBatchJournalName, fd, payload, tenantFileBatchJournalMaximum); err != nil {
		return fmt.Errorf("verify linked tenant batch transaction journal: %w", err)
	}
	if err := tenantFileHook(hook, "batch-journal-linked-verified"); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	return tenantFileHook(hook, "batch-journal-durable")
}

func encodeTenantFileBatchJournal(journal tenantFileBatchJournal, maximum int) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("tenant batch transaction aggregate limit is invalid")
	}
	payload, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > maximum {
		return nil, fmt.Errorf("complete tenant catalog transaction is %d bytes and exceeds the %d-byte aggregate limit", len(payload), maximum)
	}
	return payload, nil
}

func loadTenantFileBatchJournal(portal config.Portal, systemdRoot string) (tenantFileBatchJournal, bool, error) {
	path := tenantFileBatchJournalPath(portal)
	state, payload, err := inspectTenantFile(path, tenantFileBatchJournalMaximum)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tenantFileBatchJournal{}, false, nil
		}
		return tenantFileBatchJournal{}, false, err
	}
	if !state.Exists {
		return tenantFileBatchJournal{}, false, nil
	}
	if state.Mode != 0o600 || state.UID != 0 || state.GID != 0 || state.ACLSHA256 != "" {
		return tenantFileBatchJournal{}, true, errors.New("tenant batch transaction journal metadata is unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal tenantFileBatchJournal
	if err := decoder.Decode(&journal); err != nil {
		return tenantFileBatchJournal{}, true, errors.New("tenant batch transaction journal is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return tenantFileBatchJournal{}, true, errors.New("tenant batch transaction journal contains trailing data")
	}
	if err := validateTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		return tenantFileBatchJournal{}, true, err
	}
	return journal, true, nil
}

func removeTenantFileBatchJournal(portal config.Portal, systemdRoot string, expected tenantFileBatchJournal) error {
	return removeTenantFileBatchJournalWithHook(portal, systemdRoot, expected, nil)
}

func removeTenantFileBatchJournalWithHook(portal config.Portal, systemdRoot string, expected tenantFileBatchJournal, hook tenantFileFaultHook) error {
	if err := validateTenantFileBatchJournal(portal, systemdRoot, expected); err != nil {
		return fmt.Errorf("validate tenant batch transaction before commit: %w", err)
	}
	rootFD, err := openTenantProtectedRoot(portal.Paths.TenantConfigs)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, tenantFileBatchJournalName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: tenantDirectoryResolve,
	})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Nlink != 1 || opened.Mode&0o7777 != 0o600 || opened.Uid != 0 || opened.Gid != 0 ||
		opened.Size <= 0 || opened.Size > tenantFileBatchJournalMaximum {
		return errors.New("tenant batch transaction journal descriptor metadata is unsafe before commit")
	}
	if err := unix.Fstatat(rootFD, tenantFileBatchJournalName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		return errors.New("tenant batch transaction journal pathname changed before removal")
	}
	payload := make([]byte, opened.Size)
	for offset := 0; offset < len(payload); {
		read, err := unix.Pread(fd, payload[offset:], int64(offset))
		if err != nil {
			return fmt.Errorf("read tenant batch transaction journal before commit: %w", err)
		}
		if read <= 0 {
			return io.ErrUnexpectedEOF
		}
		offset += read
	}
	if acl, err := readTenantFileACL(fd); err != nil || len(acl) != 0 {
		return errors.New("tenant batch transaction journal ACL is unsafe before commit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var actual tenantFileBatchJournal
	if err := decoder.Decode(&actual); err != nil {
		return errors.New("tenant batch transaction journal changed before commit")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tenant batch transaction journal contains trailing data before commit")
	}
	if err := validateTenantFileBatchJournal(portal, systemdRoot, actual); err != nil {
		return fmt.Errorf("revalidate tenant batch transaction before commit: %w", err)
	}
	if !sameTenantFileBatchJournal(actual, expected) {
		return errors.New("tenant batch transaction journal differs from the verified intent")
	}
	if err := tenantFileHook(hook, "batch-commit-revalidated"); err != nil {
		return err
	}
	var reopened unix.Stat_t
	if err := unix.Fstat(fd, &reopened); err != nil || !sameTenantFileStat(opened, reopened) {
		return errors.New("tenant batch transaction journal descriptor changed before commit")
	}
	if err := unix.Fstatat(rootFD, tenantFileBatchJournalName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(reopened, named) {
		return errors.New("tenant batch transaction journal pathname changed before commit")
	}
	if err := tenantFileHook(hook, "batch-before-unlink"); err != nil {
		return err
	}
	if err := unix.Fstatat(rootFD, tenantFileBatchJournalName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(reopened, named) {
		return errors.New("tenant batch transaction journal pathname changed at commit")
	}
	if err := unix.Unlinkat(rootFD, tenantFileBatchJournalName, 0); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	return tenantFileHook(hook, "batch-unlink-durable")
}

func reconcileTenantFileBatch(ctx context.Context, portal config.Portal, systemdRoot string, journal tenantFileBatchJournal) error {
	return reconcileTenantFileBatchWithHook(ctx, portal, systemdRoot, journal, nil)
}

func reconcileTenantFileBatchWithHook(ctx context.Context, portal config.Portal, systemdRoot string, journal tenantFileBatchJournal, hook tenantFileFaultHook) error {
	if err := validateTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		return err
	}
	for _, member := range journal.Members {
		if err := tenantFileHook(hook, "batch-before-member:"+member.Tenant.TenantID); err != nil {
			return err
		}
		publication, err := prepareTenantFilePublication(portal, member.Tenant, systemdRoot)
		if err != nil {
			return err
		}
		if err := ensureTenantFileBatchMemberIntentWithHook(publication.plan, member.Entries, hook); err != nil {
			return fmt.Errorf("authenticate tenant batch member %s pre-state: %w", member.Tenant.TenantID, err)
		}
		if err := publishPreparedTenantFilesWithHook(ctx, publication, hook); err != nil {
			return fmt.Errorf("replay tenant batch member %s: %w", publication.tenant.TenantID, err)
		}
		if err := tenantFileHook(hook, "batch-member-converged:"+member.Tenant.TenantID); err != nil {
			return err
		}
	}
	return nil
}

func ensureTenantFileBatchMemberIntentWithHook(plan tenantFileSetPlan, entries []tenantFileJournalEntry, hook tenantFileFaultHook) error {
	local := tenantFileJournal{SchemaVersion: tenantFileJournalSchema, TenantID: plan.TenantID, Entries: entries}
	if err := validateTenantFileJournal(local, plan); err != nil {
		return err
	}
	journalExists, err := tenantPathExists(plan.JournalPath)
	if err != nil {
		return err
	}
	if journalExists {
		existing, err := loadTenantFileJournal(plan.JournalPath, plan)
		if err != nil {
			return err
		}
		if !sameTenantFileJournal(existing, local) {
			return errors.New("local tenant journal differs from its global batch intent")
		}
		return nil
	}
	if err := rejectUnboundTenantFileResidue(plan); err != nil {
		return err
	}
	allBefore, allDesired := true, true
	for _, entry := range entries {
		state, _, err := inspectTenantFile(entry.Target, tenantFileMaximumSize)
		if err != nil {
			return err
		}
		if state != entry.Before {
			allBefore = false
		}
		desired, err := tenantFileStateMatchesJournalDesired(entry.Target, state, entry)
		if err != nil {
			return err
		}
		if !desired {
			allDesired = false
		}
	}
	if allDesired {
		return nil
	}
	if !allBefore {
		return errors.New("tenant batch target is neither its globally recorded pre-state nor complete desired state")
	}
	if err := prepareTenantFileDirectories(plan, unix.Fsync); err != nil {
		return err
	}
	return writeTenantFileJournal(plan.JournalPath, local, hook)
}

func sameTenantFileJournal(left, right tenantFileJournal) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}

func sameTenantFileBatchJournal(left, right tenantFileBatchJournal) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}
