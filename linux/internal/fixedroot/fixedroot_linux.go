//go:build linux

// Package fixedroot installs the immutable, signed control and shared release
// trees.  It deliberately has no copy or delete operation: a caller prepares a
// complete sibling tree, and this package only performs durable, journaled
// renames after the caller has reverified the signature and proved that every
// consumer is drained.
package fixedroot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

const (
	ControlPath = "/opt/workagent/control"
	SharedPath  = "/opt/workagent/shared"

	journalSchema       = 1
	maximumJournalBytes = 64 * 1024
)

const (
	actionInitial  = "initial-install"
	actionUpgrade  = "exchange-upgrade"
	actionRollback = "exchange-rollback"

	statusPending  = "pending"
	statusComplete = "complete"
)

const (
	stepInitialInstalled  = "initial-installed"
	stepCurrentExchanged  = "current-exchanged"
	stepPreviousExchanged = "previous-exchanged"
	stepPreviousArchived  = "previous-archived"
	stepRollbackExchanged = "rollback-exchanged"
)

// VerifyFunc must perform the complete signed-release verification for root
// and return the signed manifest's release ID. Candidate is true only for the
// staged release admitted by an install journal; callers must then enforce the
// current exact component baseline. Historical current, previous, and archive
// trees remain signature-, scope-, and consumer-contract-bound without being
// retroactively compared with today's component versions. The verifier is
// invoked while the lifecycle catalog is exclusively locked and after the
// drain proof.
type VerifyFunc func(ctx context.Context, root string, candidate bool) (releaseID string, err error)

// DrainFunc must fail unless every consumer of destination is stopped and
// drained.  The package calls it while holding the exclusive lifecycle catalog
// lock, before it verifies or moves any release tree.
type DrainFunc func(ctx context.Context, destination string) error

type InstallOptions struct {
	Destination            string
	StagedRoot             string
	ExpectedCurrentRelease string
}

type RollbackOptions struct {
	Destination             string
	ExpectedCurrentRelease  string
	ExpectedPreviousRelease string
}

type Result struct {
	Destination     string `json:"destination"`
	Operation       string `json:"operation,omitempty"`
	CurrentRelease  string `json:"current_release,omitempty"`
	PreviousPath    string `json:"previous_path,omitempty"`
	PreviousRelease string `json:"previous_release,omitempty"`
	ArchivedPath    string `json:"archived_path,omitempty"`
	ArchivedRelease string `json:"archived_release,omitempty"`
	JournalFound    bool   `json:"journal_found"`
	Recovered       bool   `json:"recovered"`
}

// StagePath returns the only accepted production staging name for a release.
// The caller must create the complete signed tree at this path before Install.
func StagePath(destination, releaseID string) (string, error) {
	target, err := productionInstaller().resolveTarget(destination)
	if err != nil {
		return "", err
	}
	if err := release.ValidateReleaseID(releaseID); err != nil {
		return "", err
	}
	return filepath.Join(target.parent, target.stagePrefix+releaseID), nil
}

func PreviousPath(destination string) (string, error) {
	target, err := productionInstaller().resolveTarget(destination)
	if err != nil {
		return "", err
	}
	return filepath.Join(target.parent, target.previousLeaf), nil
}

// Install atomically installs a first fixed root or exchanges an existing root
// with a verified sibling.  Existing roots require an exact expected release
// ID; an initial installation requires the expectation to be empty.
func Install(ctx context.Context, options InstallOptions, verify VerifyFunc, drain DrainFunc) (Result, error) {
	return productionInstaller().install(ctx, options, verify, drain)
}

// Rollback exchanges the current and immediately previous signed trees.  Both
// expected identities are mandatory, making retries idempotent and stale
// operator requests fail closed.
func Rollback(ctx context.Context, options RollbackOptions, verify VerifyFunc, drain DrainFunc) (Result, error) {
	return productionInstaller().rollback(ctx, options, verify, drain)
}

// Reconcile finishes a journaled operation interrupted after any durable
// rename.  It never guesses: every pathname must match one of the transaction's
// complete device/inode/release-ID states.
func Reconcile(ctx context.Context, destination string, verify VerifyFunc, drain DrainFunc) (Result, error) {
	return productionInstaller().reconcile(ctx, destination, false, verify, drain)
}

// ReconcileInitial recovers only a journaled first control-root install. It is
// the bootstrap-safe form used before Portal and tenant configuration exists;
// the journal action is checked under both lifecycle locks before any rename.
func ReconcileInitial(ctx context.Context, destination string, verify VerifyFunc, drain DrainFunc) (Result, error) {
	if destination != ControlPath {
		return Result{}, errors.New("initial fixed-root reconciliation is restricted to the control root")
	}
	return productionInstaller().reconcile(ctx, destination, true, verify, drain)
}

type lockHandle interface {
	Close() error
}

type target struct {
	destination   string
	parent        string
	leaf          string
	stagePrefix   string
	previousLeaf  string
	journalLeaf   string
	archivePrefix string
}

type installer struct {
	parent                     string
	expectedUID                uint32
	expectedGID                uint32
	requireProductionAncestors bool
	effectiveUID               func() int
	acquire                    func(context.Context) (lockHandle, error)
	acquireChannel             func(string) (lockHandle, error)
	now                        func() time.Time
	random                     io.Reader
	afterMutation              func(string) error
}

func productionInstaller() *installer {
	return &installer{
		parent: "/opt/workagent", expectedUID: 0, expectedGID: 0,
		requireProductionAncestors: true,
		effectiveUID:               os.Geteuid,
		acquire: func(ctx context.Context) (lockHandle, error) {
			return lifecyclelock.AcquireCatalogExclusive(ctx)
		},
		acquireChannel: func(destination string) (lockHandle, error) {
			return lifecyclelock.AcquireFixedChannelExclusive(destination)
		},
		now: time.Now, random: rand.Reader,
	}
}

func (i *installer) resolveTarget(destination string) (target, error) {
	if i == nil || i.parent == "" || !filepath.IsAbs(i.parent) || filepath.Clean(i.parent) != i.parent {
		return target{}, errors.New("fixed-root installer configuration is invalid")
	}
	if destination == "" || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || filepath.Dir(destination) != i.parent {
		return target{}, errors.New("fixed-root destination is not an allowed canonical path")
	}
	leaf := filepath.Base(destination)
	if leaf != "control" && leaf != "shared" {
		return target{}, errors.New("fixed-root destination must be the exact control or shared path")
	}
	return target{
		destination: destination, parent: i.parent, leaf: leaf,
		stagePrefix:   "." + leaf + ".stage-",
		previousLeaf:  "." + leaf + ".previous",
		journalLeaf:   "." + leaf + ".install-journal.json",
		archivePrefix: "." + leaf + ".archive-",
	}, nil
}

func (i *installer) install(ctx context.Context, options InstallOptions, verify VerifyFunc, drain DrainFunc) (result Result, resultErr error) {
	target, err := i.resolveTarget(options.Destination)
	if err != nil {
		return Result{}, err
	}
	stageLeaf, err := target.validateStagePath(options.StagedRoot)
	if err != nil {
		return Result{}, err
	}
	if options.ExpectedCurrentRelease != "" {
		if err := release.ValidateReleaseID(options.ExpectedCurrentRelease); err != nil {
			return Result{}, errors.New("expected current fixed-root release ID is invalid")
		}
	}
	return i.withLockedParent(ctx, target, verify, drain, func(parentFD int) (Result, error) {
		priorJournal, found, err := i.loadJournal(parentFD, target)
		if err != nil {
			return Result{}, err
		}
		if found {
			priorStatus := priorJournal.Status
			priorResult, err := i.reconcileJournal(ctx, parentFD, target, priorJournal, verify)
			if err != nil {
				return Result{}, err
			}
			if (priorJournal.Action == actionInitial || priorJournal.Action == actionUpgrade) &&
				priorJournal.StageLeaf == stageLeaf && priorJournal.expectedCurrent() == options.ExpectedCurrentRelease {
				stage, err := i.inspectOptionalTree(ctx, parentFD, target, stageLeaf, verify, false)
				if err != nil {
					return Result{}, err
				}
				if priorStatus == statusPending || stage == nil {
					priorResult.Recovered = priorStatus == statusPending
					return priorResult, nil
				}
			}
		}

		candidate, err := i.inspectRequiredTree(ctx, parentFD, target, stageLeaf, verify, true)
		if err != nil {
			return Result{}, fmt.Errorf("verify staged fixed-root release: %w", err)
		}
		if candidate.ReleaseID != strings.TrimPrefix(stageLeaf, target.stagePrefix) {
			return Result{}, errors.New("signed staged release ID does not match its reserved staging path")
		}
		current, err := i.inspectOptionalTree(ctx, parentFD, target, target.leaf, verify, false)
		if err != nil {
			return Result{}, fmt.Errorf("verify current fixed-root release: %w", err)
		}
		previous, err := i.inspectOptionalTree(ctx, parentFD, target, target.previousLeaf, verify, false)
		if err != nil {
			return Result{}, fmt.Errorf("verify previous fixed-root release: %w", err)
		}
		if current == nil {
			if options.ExpectedCurrentRelease != "" {
				return Result{}, errors.New("fixed-root initial install has a stale expected current release")
			}
			if previous != nil {
				return Result{}, errors.New("fixed-root previous tree exists while the current tree is missing")
			}
		} else {
			if options.ExpectedCurrentRelease == "" || current.ReleaseID != options.ExpectedCurrentRelease {
				return Result{}, errors.New("fixed-root current release does not match the compare-and-swap expectation")
			}
			if current.ReleaseID == candidate.ReleaseID {
				return Result{}, errors.New("fixed-root upgrade candidate has the current release ID")
			}
		}
		transactionID, archiveLeaf, err := i.uniqueTransaction(parentFD, target, previous != nil)
		if err != nil {
			return Result{}, err
		}
		action := actionUpgrade
		if current == nil {
			action = actionInitial
		}
		journal := transactionJournal{
			SchemaVersion: journalSchema, Status: statusPending, Phase: "prepared",
			TransactionID: transactionID, TargetLeaf: target.leaf, Action: action,
			StageLeaf: stageLeaf, ArchiveLeaf: archiveLeaf,
			Candidate: candidate, CurrentBefore: current, PreviousBefore: previous,
		}
		if err := journal.validate(target); err != nil {
			return Result{}, err
		}
		if err := i.writeJournal(parentFD, target, &journal); err != nil {
			return Result{}, fmt.Errorf("persist fixed-root install journal: %w", err)
		}
		return i.reconcileJournal(ctx, parentFD, target, journal, verify)
	})
}

func (i *installer) rollback(ctx context.Context, options RollbackOptions, verify VerifyFunc, drain DrainFunc) (Result, error) {
	target, err := i.resolveTarget(options.Destination)
	if err != nil {
		return Result{}, err
	}
	if release.ValidateReleaseID(options.ExpectedCurrentRelease) != nil || release.ValidateReleaseID(options.ExpectedPreviousRelease) != nil || options.ExpectedCurrentRelease == options.ExpectedPreviousRelease {
		return Result{}, errors.New("fixed-root rollback requires distinct valid expected current and previous release IDs")
	}
	return i.withLockedParent(ctx, target, verify, drain, func(parentFD int) (Result, error) {
		priorJournal, found, err := i.loadJournal(parentFD, target)
		if err != nil {
			return Result{}, err
		}
		if found {
			priorStatus := priorJournal.Status
			priorResult, err := i.reconcileJournal(ctx, parentFD, target, priorJournal, verify)
			if err != nil {
				return Result{}, err
			}
			if priorJournal.Action == actionRollback && priorJournal.CurrentBefore != nil && priorJournal.PreviousBefore != nil &&
				priorJournal.CurrentBefore.ReleaseID == options.ExpectedCurrentRelease && priorJournal.PreviousBefore.ReleaseID == options.ExpectedPreviousRelease {
				priorResult.Recovered = priorStatus == statusPending
				return priorResult, nil
			}
		}

		current, err := i.inspectRequiredTree(ctx, parentFD, target, target.leaf, verify, false)
		if err != nil {
			return Result{}, fmt.Errorf("verify current fixed-root release: %w", err)
		}
		previous, err := i.inspectRequiredTree(ctx, parentFD, target, target.previousLeaf, verify, false)
		if err != nil {
			return Result{}, fmt.Errorf("verify previous fixed-root release: %w", err)
		}
		if current.ReleaseID != options.ExpectedCurrentRelease || previous.ReleaseID != options.ExpectedPreviousRelease {
			return Result{}, errors.New("fixed-root rollback releases do not match the compare-and-swap expectations")
		}
		transactionID, _, err := i.uniqueTransaction(parentFD, target, false)
		if err != nil {
			return Result{}, err
		}
		journal := transactionJournal{
			SchemaVersion: journalSchema, Status: statusPending, Phase: "prepared",
			TransactionID: transactionID, TargetLeaf: target.leaf, Action: actionRollback,
			CurrentBefore: current, PreviousBefore: previous,
		}
		if err := journal.validate(target); err != nil {
			return Result{}, err
		}
		if err := i.writeJournal(parentFD, target, &journal); err != nil {
			return Result{}, fmt.Errorf("persist fixed-root rollback journal: %w", err)
		}
		return i.reconcileJournal(ctx, parentFD, target, journal, verify)
	})
}

func (i *installer) reconcile(ctx context.Context, destination string, requireInitial bool, verify VerifyFunc, drain DrainFunc) (Result, error) {
	target, err := i.resolveTarget(destination)
	if err != nil {
		return Result{}, err
	}
	return i.withLockedParent(ctx, target, verify, drain, func(parentFD int) (Result, error) {
		journal, found, err := i.loadJournal(parentFD, target)
		if err != nil {
			return Result{}, err
		}
		if !found {
			if requireInitial {
				return Result{}, errors.New("initial fixed-root reconciliation requires a pending first-install journal")
			}
			return Result{Destination: destination}, nil
		}
		if requireInitial && (journal.Action != actionInitial || journal.Status != statusPending || journal.CurrentBefore != nil || journal.PreviousBefore != nil) {
			return Result{}, errors.New("initial fixed-root reconciliation requires a pending first-install journal")
		}
		wasPending := journal.Status == statusPending
		result, err := i.reconcileJournal(ctx, parentFD, target, journal, verify)
		if err == nil {
			result.Recovered = wasPending
		}
		return result, err
	})
}

func (i *installer) withLockedParent(ctx context.Context, target target, verify VerifyFunc, drain DrainFunc, operation func(parentFD int) (Result, error)) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("fixed-root operation context is required")
	}
	if i == nil || i.effectiveUID == nil || i.effectiveUID() != 0 {
		return Result{}, errors.New("fixed-root operations require effective UID 0")
	}
	if verify == nil || drain == nil || operation == nil || i.acquire == nil || i.acquireChannel == nil || i.now == nil || i.random == nil {
		return Result{}, errors.New("fixed-root verifier, drain proof, and installer dependencies are required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	guard, err := i.acquire(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("acquire fixed-root lifecycle lock: %w", err)
	}
	if guard == nil {
		return Result{}, errors.New("fixed-root lifecycle lock acquisition returned no guard")
	}
	parentFD, err := i.openParent(target)
	if err != nil {
		return Result{}, errors.Join(err, guard.Close())
	}
	if err := drain(ctx, target.destination); err != nil {
		return Result{}, errors.Join(fmt.Errorf("fixed-root consumer drain proof failed: %w", err), unix.Close(parentFD), guard.Close())
	}
	channelGuard, err := i.acquireChannel(target.destination)
	if err != nil {
		return Result{}, errors.Join(fmt.Errorf("acquire fixed-root consumer channel: %w", err), unix.Close(parentFD), guard.Close())
	}
	if channelGuard == nil {
		return Result{}, errors.Join(errors.New("fixed-root consumer channel acquisition returned no guard"), unix.Close(parentFD), guard.Close())
	}
	result, operationErr := operation(parentFD)
	closeErr := errors.Join(unix.Close(parentFD), channelGuard.Close(), guard.Close())
	return result, errors.Join(operationErr, closeErr)
}

func (t target) validateStagePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != t.parent {
		return "", errors.New("fixed-root stage must be a canonical sibling of the destination")
	}
	leaf := filepath.Base(path)
	if !strings.HasPrefix(leaf, t.stagePrefix) {
		return "", errors.New("fixed-root stage does not use the reserved staging prefix")
	}
	identity := strings.TrimPrefix(leaf, t.stagePrefix)
	if err := release.ValidateReleaseID(identity); err != nil {
		return "", errors.New("fixed-root stage suffix is invalid")
	}
	if leaf == t.leaf || leaf == t.previousLeaf || leaf == t.journalLeaf || strings.HasPrefix(leaf, t.archivePrefix) {
		return "", errors.New("fixed-root stage aliases a reserved transaction path")
	}
	return leaf, nil
}

func (i *installer) openParent(target target) (int, error) {
	if i.requireProductionAncestors {
		if target.parent != "/opt/workagent" || target.destination != ControlPath && target.destination != SharedPath {
			return -1, errors.New("production fixed-root paths are not exact")
		}
		return i.openProductionParent()
	}
	info, err := os.Lstat(target.parent)
	if err != nil {
		return -1, fmt.Errorf("inspect fixed-root parent: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != i.expectedUID || stat.Gid != i.expectedGID || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return -1, errors.New("fixed-root parent ownership or mode is unsafe")
	}
	fd, err := unix.Open(target.parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Dev != uint64(stat.Dev) || opened.Ino != stat.Ino || opened.Uid != i.expectedUID || opened.Gid != i.expectedGID || opened.Mode&0o7022 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("fixed-root parent changed while it was opened")
	}
	return fd, nil
}

const ancestorResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

func (i *installer) openProductionParent() (int, error) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	optFD, err := unix.Openat2(rootFD, "opt", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: ancestorResolve,
	})
	if err != nil {
		return -1, fmt.Errorf("securely open fixed-root /opt ancestor: %w", err)
	}
	defer unix.Close(optFD)
	if err := i.validateProtectedDirectoryFD(optFD); err != nil {
		return -1, fmt.Errorf("fixed-root /opt ancestor is unsafe: %w", err)
	}
	parentFD, err := unix.Openat2(optFD, "workagent", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: ancestorResolve,
	})
	if err != nil {
		return -1, fmt.Errorf("securely open fixed-root parent: %w", err)
	}
	if err := i.validateProtectedDirectoryFD(parentFD); err != nil {
		_ = unix.Close(parentFD)
		return -1, fmt.Errorf("fixed-root parent is unsafe: %w", err)
	}
	return parentFD, nil
}

func (i *installer) validateProtectedDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != i.expectedUID || stat.Gid != i.expectedGID || stat.Mode&0o7022 != 0 {
		return errors.New("protected directory ownership or mode is invalid")
	}
	return nil
}

type treeRecord struct {
	ReleaseID string `json:"release_id"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
}

func (r *treeRecord) validate() error {
	if r == nil || r.Device == 0 || r.Inode == 0 || release.ValidateReleaseID(r.ReleaseID) != nil {
		return errors.New("fixed-root journal tree identity is invalid")
	}
	return nil
}

func sameTree(left, right *treeRecord) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Device == right.Device && left.Inode == right.Inode && left.ReleaseID == right.ReleaseID
}

func distinctTrees(records ...*treeRecord) bool {
	seen := make(map[[2]uint64]bool)
	for _, record := range records {
		if record == nil {
			continue
		}
		key := [2]uint64{record.Device, record.Inode}
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

type transactionJournal struct {
	SchemaVersion  int         `json:"schema_version"`
	Status         string      `json:"status"`
	Phase          string      `json:"phase"`
	TransactionID  string      `json:"transaction_id"`
	TargetLeaf     string      `json:"target_leaf"`
	Action         string      `json:"action"`
	StageLeaf      string      `json:"stage_leaf,omitempty"`
	ArchiveLeaf    string      `json:"archive_leaf,omitempty"`
	Candidate      *treeRecord `json:"candidate,omitempty"`
	CurrentBefore  *treeRecord `json:"current_before,omitempty"`
	PreviousBefore *treeRecord `json:"previous_before,omitempty"`
	UpdatedAt      string      `json:"updated_at"`
}

func (j transactionJournal) expectedCurrent() string {
	if j.CurrentBefore == nil {
		return ""
	}
	return j.CurrentBefore.ReleaseID
}

func (j transactionJournal) validate(target target) error {
	if j.SchemaVersion != journalSchema || (j.Status != statusPending && j.Status != statusComplete) ||
		j.TargetLeaf != target.leaf || len(j.TransactionID) != 32 {
		return errors.New("fixed-root journal header is invalid")
	}
	if _, err := hex.DecodeString(j.TransactionID); err != nil || strings.ToLower(j.TransactionID) != j.TransactionID {
		return errors.New("fixed-root journal transaction ID is invalid")
	}
	if j.Status == statusComplete && j.Phase != "complete" || j.Status == statusPending && j.Phase == "complete" {
		return errors.New("fixed-root journal phase is invalid")
	}
	if j.UpdatedAt != "" {
		updated, err := time.Parse(time.RFC3339Nano, j.UpdatedAt)
		if err != nil || updated.UTC() != updated {
			return errors.New("fixed-root journal timestamp is invalid")
		}
	}
	if !distinctTrees(j.Candidate, j.CurrentBefore, j.PreviousBefore) {
		return errors.New("fixed-root journal aliases release-tree inodes")
	}
	switch j.Action {
	case actionInitial:
		if j.Phase != "prepared" && j.Phase != stepInitialInstalled && j.Phase != "complete" {
			return errors.New("fixed-root initial-install journal phase is invalid")
		}
		if j.Candidate.validate() != nil || j.CurrentBefore != nil || j.PreviousBefore != nil || j.ArchiveLeaf != "" {
			return errors.New("fixed-root initial-install journal is invalid")
		}
		if _, err := target.validateStagePath(filepath.Join(target.parent, j.StageLeaf)); err != nil {
			return err
		}
		if j.Candidate.ReleaseID != strings.TrimPrefix(j.StageLeaf, target.stagePrefix) {
			return errors.New("fixed-root initial-install candidate does not match its stage name")
		}
	case actionUpgrade:
		if j.Phase != "prepared" && j.Phase != stepCurrentExchanged && j.Phase != stepPreviousExchanged && j.Phase != stepPreviousArchived && j.Phase != "complete" {
			return errors.New("fixed-root upgrade journal phase is invalid")
		}
		if j.Candidate.validate() != nil || j.CurrentBefore.validate() != nil {
			return errors.New("fixed-root upgrade journal is incomplete")
		}
		if _, err := target.validateStagePath(filepath.Join(target.parent, j.StageLeaf)); err != nil {
			return err
		}
		if j.Candidate.ReleaseID != strings.TrimPrefix(j.StageLeaf, target.stagePrefix) {
			return errors.New("fixed-root upgrade candidate does not match its stage name")
		}
		if j.PreviousBefore == nil && (j.ArchiveLeaf != "" || j.Phase == stepPreviousArchived) || j.PreviousBefore != nil && (j.PreviousBefore.validate() != nil || j.ArchiveLeaf != target.archivePrefix+j.TransactionID) {
			return errors.New("fixed-root upgrade archive journal is invalid")
		}
	case actionRollback:
		if j.Phase != "prepared" && j.Phase != stepRollbackExchanged && j.Phase != "complete" {
			return errors.New("fixed-root rollback journal phase is invalid")
		}
		if j.StageLeaf != "" || j.ArchiveLeaf != "" || j.Candidate != nil || j.CurrentBefore.validate() != nil || j.PreviousBefore.validate() != nil {
			return errors.New("fixed-root rollback journal is invalid")
		}
	default:
		return errors.New("fixed-root journal action is invalid")
	}
	return nil
}

func (i *installer) uniqueTransaction(parentFD int, target target, needArchive bool) (string, string, error) {
	for attempts := 0; attempts < 8; attempts++ {
		payload := make([]byte, 16)
		if _, err := io.ReadFull(i.random, payload); err != nil {
			return "", "", err
		}
		transactionID := hex.EncodeToString(payload)
		archiveLeaf := ""
		if needArchive {
			archiveLeaf = target.archivePrefix + transactionID
			present, err := pathExistsAt(parentFD, archiveLeaf)
			if err != nil {
				return "", "", err
			}
			if present {
				continue
			}
		}
		return transactionID, archiveLeaf, nil
	}
	return "", "", errors.New("could not allocate a unique fixed-root transaction ID")
}

func pathExistsAt(parentFD int, leaf string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (i *installer) inspectRequiredTree(ctx context.Context, parentFD int, target target, leaf string, verify VerifyFunc, candidate bool) (*treeRecord, error) {
	record, err := i.inspectOptionalTree(ctx, parentFD, target, leaf, verify, candidate)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, os.ErrNotExist
	}
	return record, nil
}

const treeResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

func (i *installer) inspectOptionalTree(ctx context.Context, parentFD int, target target, leaf string, verify VerifyFunc, candidate bool) (*treeRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validLeaf(leaf) {
		return nil, errors.New("fixed-root tree leaf is invalid")
	}
	var named unix.Stat_t
	err := unix.Fstatat(parentFD, leaf, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&0o7777 != 0o555 || named.Uid != i.expectedUID || named.Gid != i.expectedGID {
		return nil, errors.New("fixed-root release directory ownership or mode is unsafe")
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return nil, err
	}
	if named.Dev != parentStat.Dev {
		return nil, errors.New("fixed-root release directory crosses a filesystem boundary")
	}
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: treeResolve})
	if err != nil {
		return nil, errors.New("fixed-root release directory is not a real same-filesystem sibling")
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Mode&0o7777 != 0o555 || opened.Uid != i.expectedUID || opened.Gid != i.expectedGID {
		return nil, errors.New("fixed-root release directory changed while it was opened")
	}
	if err := i.validateTree(ctx, fd, opened.Dev, candidate); err != nil {
		return nil, err
	}
	rootPath := filepath.Join(target.parent, leaf)
	releaseID, err := verify(ctx, rootPath, candidate)
	if err != nil {
		return nil, fmt.Errorf("signed fixed-root verification failed: %w", err)
	}
	if err := release.ValidateReleaseID(releaseID); err != nil {
		return nil, errors.New("fixed-root verifier returned an invalid release ID")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != opened.Dev || after.Ino != opened.Ino || after.Mode != opened.Mode || after.Uid != opened.Uid || after.Gid != opened.Gid {
		return nil, errors.New("fixed-root release changed during signed verification")
	}
	return &treeRecord{ReleaseID: releaseID, Device: opened.Dev, Inode: opened.Ino}, nil
}

func (i *installer) validateTree(ctx context.Context, rootFD int, rootDevice uint64, sync bool) error {
	duplicate, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "fixed-root-release")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !validLeaf(name) {
			return errors.New("fixed-root release contains an invalid entry name")
		}
		var named unix.Stat_t
		if err := unix.Fstatat(rootFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if named.Dev != rootDevice || named.Uid != i.expectedUID || named.Gid != i.expectedGID || named.Mode&0o7000 != 0 {
			return errors.New("fixed-root release entry ownership, device, or special mode is unsafe")
		}
		switch named.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if named.Mode&0o777 != 0o555 {
				return errors.New("fixed-root release directory mode is not 0555")
			}
			childFD, err := unix.Openat2(rootFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: treeResolve})
			if err != nil {
				return errors.New("fixed-root release child directory is unsafe")
			}
			var opened unix.Stat_t
			err = unix.Fstat(childFD, &opened)
			if err == nil && (opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode != named.Mode || opened.Uid != named.Uid || opened.Gid != named.Gid) {
				err = errors.New("fixed-root release child directory changed while it was opened")
			}
			if err == nil {
				err = i.validateTree(ctx, childFD, rootDevice, sync)
			}
			if err == nil && sync {
				err = unix.Fsync(childFD)
			}
			closeErr := unix.Close(childFD)
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		case unix.S_IFREG:
			mode := named.Mode & 0o777
			if (mode != 0o444 && mode != 0o555) || named.Nlink != 1 {
				return errors.New("fixed-root release file mode or link count is unsafe")
			}
			fileFD, err := unix.Openat2(rootFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: treeResolve})
			if err != nil {
				return errors.New("fixed-root release file is unsafe")
			}
			var opened unix.Stat_t
			err = unix.Fstat(fileFD, &opened)
			if err == nil && (opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode != named.Mode || opened.Uid != named.Uid || opened.Gid != named.Gid || opened.Nlink != 1) {
				err = errors.New("fixed-root release file changed while it was opened")
			}
			if err == nil && sync {
				err = unix.Fsync(fileFD)
			}
			closeErr := unix.Close(fileFD)
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		default:
			return errors.New("fixed-root release contains a symlink or special file")
		}
	}
	if sync {
		return unix.Fsync(rootFD)
	}
	return nil
}

func validLeaf(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "/\\\x00")
}

type observedState struct {
	current  *treeRecord
	stage    *treeRecord
	previous *treeRecord
	archive  *treeRecord
}

func (i *installer) observeJournalState(ctx context.Context, parentFD int, target target, journal transactionJournal, verify VerifyFunc) (observedState, error) {
	current, err := i.inspectOptionalTree(ctx, parentFD, target, target.leaf, verify, false)
	if err != nil {
		return observedState{}, err
	}
	var stage *treeRecord
	if journal.StageLeaf != "" {
		stage, err = i.inspectOptionalTree(ctx, parentFD, target, journal.StageLeaf, verify, false)
		if err != nil {
			return observedState{}, err
		}
	}
	previous, err := i.inspectOptionalTree(ctx, parentFD, target, target.previousLeaf, verify, false)
	if err != nil {
		return observedState{}, err
	}
	var archive *treeRecord
	if journal.ArchiveLeaf != "" {
		archive, err = i.inspectOptionalTree(ctx, parentFD, target, journal.ArchiveLeaf, verify, false)
		if err != nil {
			return observedState{}, err
		}
	}
	state := observedState{current: current, stage: stage, previous: previous, archive: archive}
	if journal.Candidate == nil || journal.Status == statusComplete {
		return state, nil
	}
	// A crash may leave the admitted candidate under any transaction pathname.
	// First verify every tree as signed historical evidence, then locate the
	// journal-bound candidate by release ID and inode and reverify that exact
	// pathname with current admission enabled. This preserves rollback across
	// component-version upgrades without allowing a newly staged candidate to
	// bypass today's baseline during recovery.
	type candidateLocation struct {
		leaf   string
		record *treeRecord
	}
	locations := []candidateLocation{
		{leaf: target.leaf, record: state.current},
		{leaf: journal.StageLeaf, record: state.stage},
		{leaf: target.previousLeaf, record: state.previous},
		{leaf: journal.ArchiveLeaf, record: state.archive},
	}
	matchedLeaf := ""
	for _, location := range locations {
		if location.leaf == "" || !sameTree(location.record, journal.Candidate) {
			continue
		}
		if matchedLeaf != "" {
			return observedState{}, errors.New("journaled fixed-root candidate aliases multiple transaction paths")
		}
		matchedLeaf = location.leaf
	}
	if matchedLeaf == "" {
		return observedState{}, errors.New("journaled fixed-root candidate is absent from every transaction path")
	}
	admitted, err := i.inspectRequiredTree(ctx, parentFD, target, matchedLeaf, verify, true)
	if err != nil {
		return observedState{}, fmt.Errorf("reverify journaled candidate admission: %w", err)
	}
	if !sameTree(admitted, journal.Candidate) {
		return observedState{}, errors.New("journaled fixed-root candidate changed during admission verification")
	}
	return state, nil
}

func stateMatches(actual observedState, current, stage, previous, archive *treeRecord) bool {
	return sameTree(actual.current, current) && sameTree(actual.stage, stage) && sameTree(actual.previous, previous) && sameTree(actual.archive, archive)
}

func (i *installer) reconcileJournal(ctx context.Context, parentFD int, target target, journal transactionJournal, verify VerifyFunc) (Result, error) {
	if err := journal.validate(target); err != nil {
		return Result{}, err
	}
	for transitions := 0; transitions < 6; transitions++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := i.observeJournalState(ctx, parentFD, target, journal, verify)
		if err != nil {
			return Result{}, fmt.Errorf("verify journaled fixed-root state: %w", err)
		}
		complete := false
		switch journal.Action {
		case actionInitial:
			switch {
			case stateMatches(state, nil, journal.Candidate, nil, nil):
				err = i.renameNoReplace(parentFD, journal.StageLeaf, target.leaf, journal.Candidate, stepInitialInstalled)
				if err == nil {
					journal.Phase = stepInitialInstalled
				}
			case stateMatches(state, journal.Candidate, nil, nil, nil):
				complete = true
			default:
				err = errors.New("fixed-root initial-install journal does not match any recoverable state")
			}
		case actionUpgrade:
			if journal.PreviousBefore == nil {
				switch {
				case stateMatches(state, journal.CurrentBefore, journal.Candidate, nil, nil):
					err = i.renameExchange(parentFD, journal.StageLeaf, target.leaf, journal.Candidate, journal.CurrentBefore, stepCurrentExchanged)
					if err == nil {
						journal.Phase = stepCurrentExchanged
					}
				case stateMatches(state, journal.Candidate, journal.CurrentBefore, nil, nil):
					err = i.renameNoReplace(parentFD, journal.StageLeaf, target.previousLeaf, journal.CurrentBefore, stepPreviousExchanged)
					if err == nil {
						journal.Phase = stepPreviousExchanged
					}
				case stateMatches(state, journal.Candidate, nil, journal.CurrentBefore, nil):
					complete = true
				default:
					err = errors.New("fixed-root upgrade journal does not match any recoverable state")
				}
			} else {
				switch {
				case stateMatches(state, journal.CurrentBefore, journal.Candidate, journal.PreviousBefore, nil):
					err = i.renameExchange(parentFD, journal.StageLeaf, target.leaf, journal.Candidate, journal.CurrentBefore, stepCurrentExchanged)
					if err == nil {
						journal.Phase = stepCurrentExchanged
					}
				case stateMatches(state, journal.Candidate, journal.CurrentBefore, journal.PreviousBefore, nil):
					err = i.renameExchange(parentFD, journal.StageLeaf, target.previousLeaf, journal.CurrentBefore, journal.PreviousBefore, stepPreviousExchanged)
					if err == nil {
						journal.Phase = stepPreviousExchanged
					}
				case stateMatches(state, journal.Candidate, journal.PreviousBefore, journal.CurrentBefore, nil):
					err = i.renameNoReplace(parentFD, journal.StageLeaf, journal.ArchiveLeaf, journal.PreviousBefore, stepPreviousArchived)
					if err == nil {
						journal.Phase = stepPreviousArchived
					}
				case stateMatches(state, journal.Candidate, nil, journal.CurrentBefore, journal.PreviousBefore):
					complete = true
				default:
					err = errors.New("fixed-root rotating upgrade journal does not match any recoverable state")
				}
			}
		case actionRollback:
			switch {
			case stateMatches(state, journal.CurrentBefore, nil, journal.PreviousBefore, nil):
				err = i.renameExchange(parentFD, target.leaf, target.previousLeaf, journal.CurrentBefore, journal.PreviousBefore, stepRollbackExchanged)
				if err == nil {
					journal.Phase = stepRollbackExchanged
				}
			case stateMatches(state, journal.PreviousBefore, nil, journal.CurrentBefore, nil):
				complete = true
			default:
				err = errors.New("fixed-root rollback journal does not match any recoverable state")
			}
		}
		if err != nil {
			return Result{}, err
		}
		if complete {
			journal.Status = statusComplete
			journal.Phase = "complete"
			if err := i.writeJournal(parentFD, target, &journal); err != nil {
				return Result{}, fmt.Errorf("complete fixed-root journal: %w", err)
			}
			return journal.result(target), nil
		}
		if err := i.writeJournal(parentFD, target, &journal); err != nil {
			return Result{}, fmt.Errorf("advance fixed-root journal: %w", err)
		}
	}
	return Result{}, errors.New("fixed-root journal exceeded its bounded recovery transitions")
}

func (j transactionJournal) result(target target) Result {
	result := Result{
		Destination: target.destination, Operation: j.Action,
		PreviousPath: filepath.Join(target.parent, target.previousLeaf), JournalFound: true,
	}
	switch j.Action {
	case actionInitial:
		result.CurrentRelease = j.Candidate.ReleaseID
	case actionUpgrade:
		result.CurrentRelease = j.Candidate.ReleaseID
		result.PreviousRelease = j.CurrentBefore.ReleaseID
		if j.PreviousBefore != nil {
			result.ArchivedPath = filepath.Join(target.parent, j.ArchiveLeaf)
			result.ArchivedRelease = j.PreviousBefore.ReleaseID
		}
	case actionRollback:
		result.CurrentRelease = j.PreviousBefore.ReleaseID
		result.PreviousRelease = j.CurrentBefore.ReleaseID
	}
	return result
}

func (i *installer) renameNoReplace(parentFD int, source, destination string, expected *treeRecord, step string) error {
	if err := assertRootRecord(parentFD, source, expected); err != nil {
		return fmt.Errorf("fixed-root rename source CAS failed: %w", err)
	}
	present, err := pathExistsAt(parentFD, destination)
	if err != nil || present {
		return errors.Join(errors.New("fixed-root rename destination is no longer absent"), err)
	}
	if err := unix.Renameat2(parentFD, source, parentFD, destination, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("atomically install fixed-root directory: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("durably sync fixed-root parent: %w", err)
	}
	if err := assertRootRecord(parentFD, destination, expected); err != nil {
		return fmt.Errorf("fixed-root rename result CAS failed: %w", err)
	}
	if i.afterMutation != nil {
		return i.afterMutation(step)
	}
	return nil
}

func (i *installer) renameExchange(parentFD int, left, right string, expectedLeft, expectedRight *treeRecord, step string) error {
	if err := assertRootRecord(parentFD, left, expectedLeft); err != nil {
		return fmt.Errorf("fixed-root exchange left CAS failed: %w", err)
	}
	if err := assertRootRecord(parentFD, right, expectedRight); err != nil {
		return fmt.Errorf("fixed-root exchange right CAS failed: %w", err)
	}
	if err := unix.Renameat2(parentFD, left, parentFD, right, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("atomically exchange nonempty fixed-root directories (renameat2 RENAME_EXCHANGE is required): %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("durably sync fixed-root parent: %w", err)
	}
	if err := assertRootRecord(parentFD, left, expectedRight); err != nil {
		return fmt.Errorf("fixed-root exchange left result CAS failed: %w", err)
	}
	if err := assertRootRecord(parentFD, right, expectedLeft); err != nil {
		return fmt.Errorf("fixed-root exchange right result CAS failed: %w", err)
	}
	if i.afterMutation != nil {
		return i.afterMutation(step)
	}
	return nil
}

func assertRootRecord(parentFD int, leaf string, expected *treeRecord) error {
	if expected == nil || !validLeaf(leaf) {
		return errors.New("missing fixed-root CAS identity")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Dev != expected.Device || stat.Ino != expected.Inode {
		return errors.New("fixed-root pathname does not identify the expected directory inode")
	}
	return nil
}

func (i *installer) loadJournal(parentFD int, target target) (transactionJournal, bool, error) {
	var named unix.Stat_t
	err := unix.Fstatat(parentFD, target.journalLeaf, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return transactionJournal{}, false, nil
	}
	if err != nil {
		return transactionJournal{}, false, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFREG || named.Mode&0o7777 != 0o600 || named.Uid != i.expectedUID || named.Gid != i.expectedGID || named.Nlink != 1 || named.Size < 1 || named.Size > maximumJournalBytes {
		return transactionJournal{}, false, errors.New("fixed-root journal is not a protected regular file")
	}
	fd, err := unix.Openat2(parentFD, target.journalLeaf, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: treeResolve})
	if err != nil {
		return transactionJournal{}, false, errors.New("fixed-root journal path is unsafe")
	}
	file := os.NewFile(uintptr(fd), target.journalLeaf)
	payload, readErr := io.ReadAll(io.LimitReader(file, maximumJournalBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(payload) > maximumJournalBytes {
		return transactionJournal{}, false, errors.Join(errors.New("fixed-root journal read failed"), readErr, closeErr)
	}
	defer clear(payload)
	var opened unix.Stat_t
	if err := unix.Fstatat(parentFD, target.journalLeaf, &opened, unix.AT_SYMLINK_NOFOLLOW); err != nil || opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode != named.Mode || opened.Uid != named.Uid || opened.Gid != named.Gid || opened.Nlink != 1 || opened.Size != named.Size {
		return transactionJournal{}, false, errors.New("fixed-root journal changed while it was read")
	}
	var journal transactionJournal
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return transactionJournal{}, false, errors.New("fixed-root journal JSON is invalid")
	}
	if journal.UpdatedAt == "" {
		return transactionJournal{}, false, errors.New("fixed-root journal timestamp is missing")
	}
	if err := journal.validate(target); err != nil {
		return transactionJournal{}, false, err
	}
	return journal, true, nil
}

func (i *installer) writeJournal(parentFD int, target target, journal *transactionJournal) error {
	if journal == nil {
		return errors.New("fixed-root journal value is missing")
	}
	journal.UpdatedAt = i.now().UTC().Format(time.RFC3339Nano)
	if err := journal.validate(target); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	defer clear(payload)
	if len(payload) > maximumJournalBytes {
		return errors.New("fixed-root journal exceeds its size bound")
	}
	randomBytes := make([]byte, 12)
	if _, err := io.ReadFull(i.random, randomBytes); err != nil {
		return err
	}
	temporary := "." + target.journalLeaf + ".tmp-" + hex.EncodeToString(randomBytes)
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if err := file.Chown(int(i.expectedUID), int(i.expectedGID)); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, target.journalLeaf); err != nil {
		return err
	}
	remove = false
	if err := unix.Fsync(parentFD); err != nil {
		return err
	}
	var persisted unix.Stat_t
	if err := unix.Fstatat(parentFD, target.journalLeaf, &persisted, unix.AT_SYMLINK_NOFOLLOW); err != nil || persisted.Mode&unix.S_IFMT != unix.S_IFREG || persisted.Mode&0o7777 != 0o600 || persisted.Uid != i.expectedUID || persisted.Gid != i.expectedGID || persisted.Nlink != 1 || persisted.Size != int64(len(payload)) {
		return errors.New("persisted fixed-root journal metadata is unsafe")
	}
	return nil
}
