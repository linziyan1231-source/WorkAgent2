//go:build linux

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
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	tenantActivationJournalSchema  = 1
	tenantActivationJournalPath    = "/var/lib/workagent/tenant-activation.json"
	tenantActivationJournalName    = "tenant-activation.json"
	tenantActivationJournalMaximum = 8 * 1024 * 1024
	tenantActivationCatalogMaximum = 10000
)

var tenantActivationRuntimeUserPattern = regexp.MustCompile(`^workagent_[a-z0-9][a-z0-9_-]{0,25}$`)

// tenantActivationJournal is a complete, immutable database-state decision
// record.  The database enabled bits are the linearization point: after this
// record is durable, a caller may commit its one-row database update and then
// invoke ReplayTenantActivation.  A replay never guesses from partial systemd
// state.
type tenantActivationJournal struct {
	SchemaVersion int                               `json:"schema_version"`
	JournalPath   string                            `json:"journal_path"`
	Tenants       []tenantActivationJournalIdentity `json:"tenants"`
}

type tenantActivationJournalIdentity struct {
	TenantID        string `json:"tenant_id"`
	RuntimeUser     string `json:"runtime_user"`
	DataRoot        string `json:"data_root"`
	PreviousEnabled bool   `json:"previous_enabled"`
	DesiredEnabled  bool   `json:"desired_enabled"`
}

// PrepareTenantActivation writes the complete activation intent before the
// caller changes the Portal database.  The caller must serialize the whole
// prepare/database/replay sequence with the global activation lifecycle lock.
// tenantID must identify exactly one member of the supplied full DB catalog.
func PrepareTenantActivation(ctx context.Context, identities []store.PortalUserIdentity, tenantID string, desiredEnabled bool) error {
	return prepareTenantActivationAt(ctx, tenantActivationJournalPath, os.Geteuid(), identities, tenantID, desiredEnabled, nil)
}

// ReplayTenantActivation resolves a pending intent from the current complete
// Portal identity catalog.  If the database still equals the recorded
// previous state, systemd is converged to previous.  If it equals desired,
// systemd is converged to desired.  Every other state is rejected.
func ReplayTenantActivation(ctx context.Context, identities []store.PortalUserIdentity, controller systemdctl.Controller) error {
	return replayTenantActivationAt(ctx, tenantActivationJournalPath, os.Geteuid(), identities, controller, nil)
}

// ConvergeTenantActivationCatalog durably converges systemd to the current
// complete database catalog without changing a database bit.  It first
// resolves any older journal, then records a previous==desired bootstrap
// generation.  This is the migration and blank-host initialization boundary.
func ConvergeTenantActivationCatalog(ctx context.Context, identities []store.PortalUserIdentity, controller systemdctl.Controller) error {
	return convergeTenantActivationCatalogAt(ctx, tenantActivationJournalPath, os.Geteuid(), identities, controller, nil)
}

// AssertTenantActivationClean proves that no durable activation transaction
// is pending.  An unsafe object at the journal pathname is an error, not a
// clean state.
func AssertTenantActivationClean() error {
	return assertTenantActivationCleanAt(tenantActivationJournalPath, os.Geteuid())
}

func prepareTenantActivationAt(ctx context.Context, journalPath string, effectiveUID int, identities []store.PortalUserIdentity, tenantID string, desiredEnabled bool, hook tenantFileFaultHook) error {
	if effectiveUID != 0 {
		return errors.New("tenant activation transactions require root")
	}
	if ctx == nil {
		return errors.New("tenant activation transaction context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal, err := makeTenantActivationJournal(journalPath, identities, tenantID, desiredEnabled, true)
	if err != nil {
		return err
	}
	if err := writeTenantActivationJournal(journalPath, journal, hook); err != nil {
		return fmt.Errorf("record tenant activation transaction: %w", err)
	}
	return nil
}

func replayTenantActivationAt(ctx context.Context, journalPath string, effectiveUID int, identities []store.PortalUserIdentity, controller systemdctl.Controller, hook tenantFileFaultHook) error {
	if effectiveUID != 0 {
		return errors.New("tenant activation transactions require root")
	}
	if ctx == nil || controller == nil {
		return errors.New("tenant activation replay is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal, found, err := loadTenantActivationJournal(journalPath)
	if err != nil {
		return fmt.Errorf("load tenant activation transaction: %w", err)
	}
	if !found {
		return nil
	}
	target, err := resolveTenantActivationTarget(journal, identities)
	if err != nil {
		return fmt.Errorf("resolve tenant activation transaction from Portal database: %w", err)
	}
	if err := convergeTenantActivationSystemd(ctx, target, controller, hook); err != nil {
		return fmt.Errorf("converge tenant activation systemd catalog: %w", err)
	}
	if err := VerifyTenantActivationCatalog(ctx, target, controller); err != nil {
		return fmt.Errorf("prove complete tenant activation catalog before commit: %w", err)
	}
	if err := tenantFileHook(hook, "activation-catalog-verified"); err != nil {
		return err
	}
	if err := removeTenantActivationJournal(journalPath, journal, hook); err != nil {
		return fmt.Errorf("commit tenant activation transaction: %w", err)
	}
	return nil
}

func convergeTenantActivationCatalogAt(ctx context.Context, journalPath string, effectiveUID int, identities []store.PortalUserIdentity, controller systemdctl.Controller, hook tenantFileFaultHook) error {
	if effectiveUID != 0 {
		return errors.New("tenant activation transactions require root")
	}
	if ctx == nil || controller == nil {
		return errors.New("tenant activation catalog convergence is unavailable")
	}
	if _, err := canonicalTenantActivationIdentities(identities); err != nil {
		return err
	}
	// An older decision always has priority over a newly requested bootstrap
	// generation.  Resolving it may itself prove the desired catalog, but a new
	// previous==desired generation still records this invocation's full input.
	if err := replayTenantActivationAt(ctx, journalPath, effectiveUID, identities, controller, hook); err != nil {
		return fmt.Errorf("replay older tenant activation transaction: %w", err)
	}
	journal, err := makeTenantActivationJournal(journalPath, identities, "", false, false)
	if err != nil {
		return err
	}
	if err := writeTenantActivationJournal(journalPath, journal, hook); err != nil {
		return fmt.Errorf("record tenant activation catalog convergence: %w", err)
	}
	if err := replayTenantActivationAt(ctx, journalPath, effectiveUID, identities, controller, hook); err != nil {
		return fmt.Errorf("apply tenant activation catalog convergence: %w", err)
	}
	return nil
}

func assertTenantActivationCleanAt(journalPath string, effectiveUID int) error {
	if effectiveUID != 0 {
		return errors.New("tenant activation transactions require root")
	}
	parentFD, parentStat, err := openTenantActivationParent(journalPath)
	if err != nil {
		return fmt.Errorf("open tenant activation journal parent: %w", err)
	}
	defer unix.Close(parentFD)
	var named unix.Stat_t
	err = unix.Fstatat(parentFD, filepath.Base(journalPath), &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat)
	}
	if err != nil {
		return fmt.Errorf("inspect tenant activation journal: %w", err)
	}
	return errors.New("a tenant activation transaction is pending")
}

func makeTenantActivationJournal(journalPath string, identities []store.PortalUserIdentity, overrideTenantID string, desiredEnabled bool, requireOverride bool) (tenantActivationJournal, error) {
	ordered, err := canonicalTenantActivationIdentities(identities)
	if err != nil {
		return tenantActivationJournal{}, err
	}
	if !validTenantActivationJournalPath(journalPath) {
		return tenantActivationJournal{}, errors.New("tenant activation journal path is invalid")
	}
	journal := tenantActivationJournal{
		SchemaVersion: tenantActivationJournalSchema,
		JournalPath:   journalPath,
		Tenants:       make([]tenantActivationJournalIdentity, 0, len(ordered)),
	}
	foundOverride := false
	for _, identity := range ordered {
		desired := identity.Enabled
		if requireOverride && identity.TenantID == overrideTenantID {
			desired = desiredEnabled
			foundOverride = true
		}
		journal.Tenants = append(journal.Tenants, tenantActivationJournalIdentity{
			TenantID: identity.TenantID, RuntimeUser: identity.RuntimeUser, DataRoot: identity.DataRoot,
			PreviousEnabled: identity.Enabled, DesiredEnabled: desired,
		})
	}
	if requireOverride && (!canonicalTenantFileID(overrideTenantID) || !foundOverride) {
		return tenantActivationJournal{}, errors.New("tenant activation override does not name exactly one catalog member")
	}
	if !requireOverride && overrideTenantID != "" {
		return tenantActivationJournal{}, errors.New("tenant activation bootstrap contains an override")
	}
	if err := validateTenantActivationJournal(journalPath, journal); err != nil {
		return tenantActivationJournal{}, err
	}
	return journal, nil
}

func canonicalTenantActivationIdentities(identities []store.PortalUserIdentity) ([]store.PortalUserIdentity, error) {
	if len(identities) == 0 || len(identities) > tenantActivationCatalogMaximum {
		return nil, errors.New("tenant activation identity catalog has invalid non-empty cardinality")
	}
	ordered := append([]store.PortalUserIdentity(nil), identities...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].TenantID < ordered[j].TenantID })
	seenIDs := make(map[string]bool, len(ordered))
	seenUsers := make(map[string]bool, len(ordered))
	seenRoots := make(map[string]bool, len(ordered))
	for _, identity := range ordered {
		if !validTenantActivationIdentity(identity) || seenIDs[identity.TenantID] || seenUsers[identity.RuntimeUser] || seenRoots[identity.DataRoot] {
			return nil, errors.New("tenant activation identity catalog contains an invalid or duplicate identity")
		}
		seenIDs[identity.TenantID] = true
		seenUsers[identity.RuntimeUser] = true
		seenRoots[identity.DataRoot] = true
	}
	return ordered, nil
}

func validTenantActivationIdentity(identity store.PortalUserIdentity) bool {
	return canonicalTenantFileID(identity.TenantID) && tenantActivationRuntimeUserPattern.MatchString(identity.RuntimeUser) &&
		len(identity.DataRoot) <= 4096 && utf8.ValidString(identity.DataRoot) && !strings.ContainsRune(identity.DataRoot, '\x00') &&
		filepath.IsAbs(identity.DataRoot) && filepath.Clean(identity.DataRoot) == identity.DataRoot && identity.DataRoot != string(filepath.Separator)
}

func validateTenantActivationJournal(journalPath string, journal tenantActivationJournal) error {
	if !validTenantActivationJournalPath(journalPath) || journal.SchemaVersion != tenantActivationJournalSchema || journal.JournalPath != journalPath ||
		len(journal.Tenants) == 0 || len(journal.Tenants) > tenantActivationCatalogMaximum {
		return errors.New("tenant activation journal identity is invalid")
	}
	identities := make([]store.PortalUserIdentity, 0, len(journal.Tenants))
	changed := 0
	for index, member := range journal.Tenants {
		if index > 0 && journal.Tenants[index-1].TenantID >= member.TenantID {
			return errors.New("tenant activation journal identity order is invalid")
		}
		if member.PreviousEnabled != member.DesiredEnabled {
			changed++
		}
		identities = append(identities, store.PortalUserIdentity{
			TenantID: member.TenantID, RuntimeUser: member.RuntimeUser, DataRoot: member.DataRoot,
		})
	}
	if changed > 1 {
		return errors.New("tenant activation journal changes more than one database row")
	}
	if _, err := canonicalTenantActivationIdentities(identities); err != nil {
		return err
	}
	if _, err := encodeTenantActivationJournal(journal); err != nil {
		return err
	}
	return nil
}

func validTenantActivationJournalPath(path string) bool {
	return cleanTenantFilePath(path) && filepath.Base(path) == tenantActivationJournalName
}

func encodeTenantActivationJournal(journal tenantActivationJournal) ([]byte, error) {
	payload, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) == 0 || len(payload) > tenantActivationJournalMaximum {
		return nil, errors.New("tenant activation journal exceeds its complete-catalog size bound")
	}
	return payload, nil
}

func writeTenantActivationJournal(journalPath string, journal tenantActivationJournal, hook tenantFileFaultHook) error {
	if err := validateTenantActivationJournal(journalPath, journal); err != nil {
		return err
	}
	payload, err := encodeTenantActivationJournal(journal)
	if err != nil {
		return err
	}
	parentFD, parentStat, err := openTenantActivationParent(journalPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	name := filepath.Base(journalPath)
	if err := unix.Fstatat(parentFD, name, &unix.Stat_t{}, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return errors.New("tenant activation journal already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect tenant activation journal: %w", err)
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create anonymous tenant activation journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), "anonymous-tenant-activation-journal")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt anonymous tenant activation journal")
	}
	defer file.Close()
	if err := tenantFileHook(hook, "activation-journal-anonymous-created"); err != nil {
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
	for offset := 0; offset < len(payload); {
		written, writeErr := file.Write(payload[offset:])
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		offset += written
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "activation-journal-anonymous-synced"); err != nil {
		return err
	}
	// linkat(AT_EMPTY_PATH) is the O_TMPFILE publication operation.  Like
	// RENAME_NOREPLACE it is atomic and fails with EEXIST rather than replacing
	// an existing journal, while avoiding a second visible temporary pathname.
	if err := unix.Linkat(fd, "", parentFD, name, unix.AT_EMPTY_PATH); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("tenant activation journal appeared concurrently")
		}
		return fmt.Errorf("publish tenant activation journal without replacement: %w", err)
	}
	if err := verifyLinkedProtectedJournal(parentFD, name, fd, payload, tenantActivationJournalMaximum); err != nil {
		return fmt.Errorf("verify published tenant activation journal: %w", err)
	}
	if err := revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat); err != nil {
		return err
	}
	if err := tenantFileHook(hook, "activation-journal-linked-verified"); err != nil {
		return err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize tenant activation journal parent: %w", err)
	}
	return tenantFileHook(hook, "activation-journal-durable")
}

func loadTenantActivationJournal(journalPath string) (tenantActivationJournal, bool, error) {
	if !validTenantActivationJournalPath(journalPath) {
		return tenantActivationJournal{}, false, errors.New("tenant activation journal path is invalid")
	}
	parentFD, parentStat, err := openTenantActivationParent(journalPath)
	if err != nil {
		return tenantActivationJournal{}, false, err
	}
	defer unix.Close(parentFD)
	fd, opened, found, err := openTenantActivationJournalFD(parentFD, filepath.Base(journalPath))
	if err != nil || !found {
		if err == nil {
			err = revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat)
		}
		return tenantActivationJournal{}, found, err
	}
	defer unix.Close(fd)
	payload, err := readTenantActivationJournalFD(fd, opened)
	if err != nil {
		return tenantActivationJournal{}, true, err
	}
	journal, err := decodeTenantActivationJournal(journalPath, payload)
	if err != nil {
		return tenantActivationJournal{}, true, err
	}
	if err := revalidateTenantActivationJournalFD(parentFD, filepath.Base(journalPath), fd, opened); err != nil {
		return tenantActivationJournal{}, true, err
	}
	if err := revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat); err != nil {
		return tenantActivationJournal{}, true, err
	}
	return journal, true, nil
}

func openTenantActivationJournalFD(parentFD int, name string) (int, unix.Stat_t, bool, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: tenantDirectoryResolve,
	})
	if errors.Is(err, unix.ENOENT) {
		return -1, unix.Stat_t{}, false, nil
	}
	if err != nil {
		return -1, unix.Stat_t{}, true, errors.New("open tenant activation journal without following links")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 ||
		opened.Mode&0o7777 != 0o600 || opened.Uid != 0 || opened.Gid != 0 || opened.Size <= 0 || opened.Size > tenantActivationJournalMaximum {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, true, errors.New("tenant activation journal descriptor metadata is unsafe")
	}
	if acl, aclErr := readTenantFileACL(fd); aclErr != nil || len(acl) != 0 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, true, errors.New("tenant activation journal ACL is unsafe")
	}
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, true, errors.New("tenant activation journal pathname changed while opening")
	}
	return fd, opened, true, nil
}

func readTenantActivationJournalFD(fd int, opened unix.Stat_t) ([]byte, error) {
	payload := make([]byte, opened.Size)
	for offset := 0; offset < len(payload); {
		read, err := unix.Pread(fd, payload[offset:], int64(offset))
		if err != nil {
			return nil, fmt.Errorf("read tenant activation journal: %w", err)
		}
		if read <= 0 {
			return nil, io.ErrUnexpectedEOF
		}
		offset += read
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameTenantFileStat(opened, after) {
		return nil, errors.New("tenant activation journal changed while reading")
	}
	return payload, nil
}

func decodeTenantActivationJournal(journalPath string, payload []byte) (tenantActivationJournal, error) {
	if len(payload) == 0 || len(payload) > tenantActivationJournalMaximum {
		return tenantActivationJournal{}, errors.New("tenant activation journal size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal tenantActivationJournal
	if err := decoder.Decode(&journal); err != nil {
		return tenantActivationJournal{}, errors.New("tenant activation journal JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return tenantActivationJournal{}, errors.New("tenant activation journal contains trailing JSON")
	}
	if err := validateTenantActivationJournal(journalPath, journal); err != nil {
		return tenantActivationJournal{}, err
	}
	canonical, err := encodeTenantActivationJournal(journal)
	if err != nil || !bytes.Equal(payload, canonical) {
		return tenantActivationJournal{}, errors.New("tenant activation journal is not canonical JSON")
	}
	return journal, nil
}

func resolveTenantActivationTarget(journal tenantActivationJournal, identities []store.PortalUserIdentity) ([]store.PortalUserIdentity, error) {
	if err := validateTenantActivationJournal(journal.JournalPath, journal); err != nil {
		return nil, err
	}
	ordered, err := canonicalTenantActivationIdentities(identities)
	if err != nil {
		return nil, err
	}
	if len(ordered) != len(journal.Tenants) {
		return nil, errors.New("Portal activation catalog cardinality differs from the durable intent")
	}
	allPrevious, allDesired := true, true
	for index, current := range ordered {
		recorded := journal.Tenants[index]
		if current.TenantID != recorded.TenantID || current.RuntimeUser != recorded.RuntimeUser || current.DataRoot != recorded.DataRoot {
			return nil, errors.New("Portal activation catalog identity differs from the durable intent")
		}
		if current.Enabled != recorded.PreviousEnabled {
			allPrevious = false
		}
		if current.Enabled != recorded.DesiredEnabled {
			allDesired = false
		}
	}
	if !allPrevious && !allDesired {
		return nil, errors.New("Portal activation catalog is neither the complete previous nor complete desired database state")
	}
	targetDesired := allDesired
	target := make([]store.PortalUserIdentity, len(ordered))
	copy(target, ordered)
	for index := range target {
		if targetDesired {
			target[index].Enabled = journal.Tenants[index].DesiredEnabled
		} else {
			target[index].Enabled = journal.Tenants[index].PreviousEnabled
		}
	}
	return target, nil
}

func convergeTenantActivationSystemd(ctx context.Context, identities []store.PortalUserIdentity, controller systemdctl.Controller, hook tenantFileFaultHook) error {
	ordered, err := canonicalTenantActivationIdentities(identities)
	if err != nil {
		return err
	}
	if ctx == nil || controller == nil {
		return errors.New("tenant activation systemd convergence is unavailable")
	}
	for _, identity := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		socketUnit := "workagent-userhost@" + identity.TenantID + ".socket"
		serviceUnit := "workagent-userhost@" + identity.TenantID + ".service"
		if identity.Enabled {
			// Persistent enablement is intentional; replay must never start an
			// enabled socket or service as a side effect.
			if err := controller.Action(ctx, "enable", socketUnit); err != nil {
				return fmt.Errorf("persistently enable tenant socket %s: %w", socketUnit, err)
			}
			properties, err := controller.Properties(ctx, socketUnit, "LoadState", "UnitFileState")
			if err != nil {
				return fmt.Errorf("inspect enabled tenant socket %s: %w", socketUnit, err)
			}
			if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "enabled" {
				return fmt.Errorf("tenant socket %s is not loaded and persistently enabled", socketUnit)
			}
		} else {
			if err := controller.Action(ctx, "disable", "--now", socketUnit); err != nil {
				return fmt.Errorf("disable and stop tenant socket %s: %w", socketUnit, err)
			}
			if err := controller.Action(ctx, "stop", serviceUnit); err != nil {
				return fmt.Errorf("stop tenant service %s: %w", serviceUnit, err)
			}
			if err := verifyDisabledTenantActivation(ctx, identity.TenantID, controller); err != nil {
				return err
			}
		}
		if err := tenantFileHook(hook, "activation-tenant-converged:"+identity.TenantID); err != nil {
			return err
		}
	}
	return nil
}

func verifyDisabledTenantActivation(ctx context.Context, tenantID string, controller systemdctl.Controller) error {
	socketUnit := "workagent-userhost@" + tenantID + ".socket"
	serviceUnit := "workagent-userhost@" + tenantID + ".service"
	socket, err := controller.Properties(ctx, socketUnit, "LoadState", "UnitFileState", "ActiveState")
	if err != nil {
		return fmt.Errorf("inspect disabled tenant socket %s: %w", socketUnit, err)
	}
	service, err := controller.Properties(ctx, serviceUnit, "LoadState", "ActiveState", "SubState", "MainPID")
	if err != nil {
		return fmt.Errorf("inspect stopped tenant service %s: %w", serviceUnit, err)
	}
	if socket["LoadState"] != "loaded" || socket["UnitFileState"] != "disabled" || socket["ActiveState"] != "inactive" ||
		service["LoadState"] != "loaded" || service["ActiveState"] != "inactive" || service["SubState"] != "dead" || service["MainPID"] != "0" {
		return fmt.Errorf("disabled tenant %s still has persistent or active systemd state", tenantID)
	}
	return nil
}

func removeTenantActivationJournal(journalPath string, expected tenantActivationJournal, hook tenantFileFaultHook) error {
	if err := validateTenantActivationJournal(journalPath, expected); err != nil {
		return err
	}
	parentFD, parentStat, err := openTenantActivationParent(journalPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	name := filepath.Base(journalPath)
	fd, opened, found, err := openTenantActivationJournalFD(parentFD, name)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("tenant activation journal disappeared before commit")
	}
	defer unix.Close(fd)
	payload, err := readTenantActivationJournalFD(fd, opened)
	if err != nil {
		return err
	}
	actual, err := decodeTenantActivationJournal(journalPath, payload)
	if err != nil {
		return err
	}
	actualPayload, actualErr := encodeTenantActivationJournal(actual)
	expectedPayload, expectedErr := encodeTenantActivationJournal(expected)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualPayload, expectedPayload) {
		return errors.New("tenant activation journal differs from the verified intent")
	}
	if err := tenantFileHook(hook, "activation-commit-revalidated"); err != nil {
		return err
	}
	if err := revalidateTenantActivationJournalFD(parentFD, name, fd, opened); err != nil {
		return err
	}
	if err := revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat); err != nil {
		return err
	}
	// Faults are injected before unlink so every reported test failure retains
	// the authenticated decision record for a later replay.
	if err := tenantFileHook(hook, "activation-before-unlink"); err != nil {
		return err
	}
	if err := revalidateTenantActivationJournalFD(parentFD, name, fd, opened); err != nil {
		return err
	}
	if err := revalidateTenantActivationParent(parentFD, filepath.Dir(journalPath), parentStat); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, name, 0); err != nil {
		return fmt.Errorf("unlink tenant activation journal: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize tenant activation journal removal: %w", err)
	}
	// There is deliberately no fallible hook or other operation after the
	// durable unlink.  Every injectable/recoverable failure is observed while
	// the authenticated journal pathname still exists.
	return nil
}

func revalidateTenantActivationJournalFD(parentFD int, name string, fd int, expected unix.Stat_t) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameTenantFileStat(expected, opened) {
		return errors.New("tenant activation journal descriptor changed before commit")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameTenantFileStat(opened, named) {
		return errors.New("tenant activation journal pathname changed before commit")
	}
	return nil
}

func openTenantActivationParent(journalPath string) (int, unix.Stat_t, error) {
	if !validTenantActivationJournalPath(journalPath) {
		return -1, unix.Stat_t{}, errors.New("tenant activation journal path is invalid")
	}
	parent := filepath.Dir(journalPath)
	fd, err := openTenantProtectedRoot(parent)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || unsafeTenantDirectory(stat) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("tenant activation journal parent is unsafe")
	}
	return fd, stat, nil
}

func revalidateTenantActivationParent(parentFD int, parentPath string, expected unix.Stat_t) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(parentFD, &opened); err != nil || opened.Dev != expected.Dev || opened.Ino != expected.Ino ||
		opened.Mode != expected.Mode || opened.Uid != expected.Uid || opened.Gid != expected.Gid || unsafeTenantDirectory(opened) {
		return errors.New("tenant activation journal parent descriptor changed")
	}
	if err := unix.Lstat(parentPath, &named); err != nil || named.Dev != opened.Dev || named.Ino != opened.Ino ||
		named.Mode != opened.Mode || named.Uid != opened.Uid || named.Gid != opened.Gid {
		return errors.New("tenant activation journal parent pathname changed")
	}
	return nil
}
