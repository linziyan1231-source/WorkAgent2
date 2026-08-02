//go:build linux

package edgepublication

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

// CleanupDriver runs a fail-closed cleanup operation under a fresh bounded
// context. It is injected by the caller because the Caddy fail-closed
// implementation lives in the service-action layer, which must not be
// imported here (internal/lifecyclelock already imports this package).
type CleanupDriver func(func(context.Context) error) error

// CaddyRollback durably disables Caddy under its currently authenticated
// manager contract.
type CaddyRollback func(context.Context, systemdctl.Controller) error

func ReconcilePending(ctx context.Context, controller systemdctl.Controller, withCleanup CleanupDriver, rollbackCaddy CaddyRollback) error {
	if ctx == nil || controller == nil || withCleanup == nil || rollbackCaddy == nil {
		return errors.New("edge-publication reconciler is unavailable")
	}
	discoveryErr := validateDirectories()
	journalSeen, journalDiscoveryErr := artifactEntryPresent(JournalPath)
	permitSeen, permitDiscoveryErr := artifactEntryPresent(PermitPath)
	discoveryErr = errors.Join(discoveryErr, journalDiscoveryErr, permitDiscoveryErr)
	if discoveryErr == nil && !journalSeen && !permitSeen {
		// Absence is admitted only through two stable protected-parent passes.
		if err := validateDirectories(); err == nil {
			journalAgain, journalErr := artifactEntryPresent(JournalPath)
			permitAgain, permitErr := artifactEntryPresent(PermitPath)
			if journalErr == nil && permitErr == nil && !journalAgain && !permitAgain {
				return nil
			}
			discoveryErr = errors.Join(journalErr, permitErr, errorUnless(!journalAgain && !permitAgain, "edge-publication evidence appeared during absence proof"))
		} else {
			discoveryErr = err
		}
	}
	disableErr := withCleanup(func(cleanupContext context.Context) error {
		return rollbackCaddy(cleanupContext, controller)
	})
	if disableErr != nil {
		return errors.Join(errors.New("disable Caddy under its currently authenticated manager contract for edge-publication recovery"), disableErr)
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but manager reload failed; edge evidence was retained: %w", err)
	}
	if err := withCleanup(func(cleanupContext context.Context) error {
		return rollbackCaddy(cleanupContext, controller)
	}); err != nil {
		return fmt.Errorf("Caddy was disabled before reload, but its reloaded fail-closed contract could not be authenticated; edge evidence was retained: %w", err)
	}
	if discoveryErr != nil {
		return fmt.Errorf("Caddy was durably disabled because edge-publication state could not be proved clean; unsafe evidence was retained: %w", discoveryErr)
	}
	if err := validateDirectories(); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but edge-publication parents are unsafe: %w", err)
	}
	journalPresent, journalStat, err := artifactState(JournalPath, true)
	if err != nil {
		return fmt.Errorf("Caddy was durably disabled, but the edge journal is unsafe and was retained: %w", err)
	}
	permitPresent, permitStat, err := artifactState(PermitPath, true)
	if err != nil {
		return fmt.Errorf("Caddy was durably disabled, but the edge permit is unsafe and was retained: %w", err)
	}
	if !journalPresent && !permitPresent {
		return errors.New("Caddy was durably disabled after edge evidence disappeared during recovery; no artifact was deleted")
	}
	permitFD := -1
	if permitPresent {
		permitFD, err = unix.Open(PermitPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(permitFD)
		var opened unix.Stat_t
		if err := unix.Fstat(permitFD, &opened); err != nil || !sameArtifactStat(opened, permitStat) {
			return errors.Join(errors.New("edge-publication permit changed during recovery"), err)
		}
		if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("edge-publication permit is still owned by another publisher: %w", err)
		}
	}
	journalFD := -1
	if journalPresent {
		journalFD, err = unix.Open(JournalPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open edge-publication journal for recovery: %w", err)
		}
		defer unix.Close(journalFD)
	}
	if err := validateRecoverableEvidence(journalPresent, journalFD, journalStat, permitPresent, permitFD, permitStat); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but invalid edge-publication crash evidence was retained: %w", err)
	}
	if err := validateRecoverableEvidence(journalPresent, journalFD, journalStat, permitPresent, permitFD, permitStat); err != nil {
		return fmt.Errorf("edge-publication crash evidence changed before recovery deletion and was retained: %w", err)
	}
	if journalPresent {
		if err := unix.Unlink(JournalPath); err != nil {
			return err
		}
		if err := fsutil.SyncDirectory(filepath.Dir(JournalPath)); err != nil {
			return err
		}
	}
	if permitPresent {
		if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("edge-publication permit lock changed before final recovery deletion: %w", err)
		}
		if err := validateRecoverableEvidence(false, -1, unix.Stat_t{}, true, permitFD, permitStat); err != nil {
			return fmt.Errorf("edge-publication permit changed after journal recovery and was retained: %w", err)
		}
		if err := unix.Unlink(PermitPath); err != nil {
			return err
		}
	}
	return nil
}

func Abort(controller systemdctl.Controller, transaction *Transaction, cause error, withCleanup CleanupDriver, rollbackCaddy CaddyRollback) error {
	if controller == nil || transaction == nil || cause == nil || withCleanup == nil || rollbackCaddy == nil {
		return errors.Join(errors.New("edge-publication abort is unavailable"), cause)
	}
	rollbackErr := withCleanup(func(cleanupContext context.Context) error {
		return rollbackCaddy(cleanupContext, controller)
	})
	if rollbackErr != nil {
		closeErr := transaction.Close()
		return errors.Join(errors.New("edge publication failed and Caddy final state is ambiguous; crash evidence was retained"), cause, rollbackErr, closeErr)
	}
	commitErr := transaction.Commit()
	if commitErr == nil {
		return errors.Join(errors.New("edge publication failed; Caddy was durably disabled and crash evidence was cleared"), cause)
	}
	closeErr := transaction.Close()
	reconcileErr := withCleanup(func(cleanupContext context.Context) error {
		return ReconcilePending(cleanupContext, controller, withCleanup, rollbackCaddy)
	})
	if reconcileErr == nil {
		return errors.Join(errors.New("edge publication failed; Caddy was durably disabled and residual crash evidence was reconciled"), cause, commitErr, closeErr)
	}
	return errors.Join(errors.New("edge publication failed after Caddy was disabled, but residual crash evidence could not be cleared"), cause, commitErr, closeErr, reconcileErr)
}

func FailClosedAfterCommitError(controller systemdctl.Controller, transaction *Transaction, commitErr error, withCleanup CleanupDriver, rollbackCaddy CaddyRollback) error {
	if controller == nil || transaction == nil || commitErr == nil || withCleanup == nil || rollbackCaddy == nil {
		return errors.Join(errors.New("edge-publication commit failure handler is unavailable"), commitErr)
	}
	// Commit deliberately retains the permit lock on every error before its
	// final volatile unlink. Keep the blocking watcher alive until Caddy has
	// first been proved disabled, then release the lock and reconcile whatever
	// durable or volatile evidence remains.
	rollbackErr := withCleanup(func(cleanupContext context.Context) error {
		return rollbackCaddy(cleanupContext, controller)
	})
	closeErr := transaction.Close()
	reconcileErr := withCleanup(func(cleanupContext context.Context) error {
		return ReconcilePending(cleanupContext, controller, withCleanup, rollbackCaddy)
	})
	if rollbackErr == nil && reconcileErr == nil {
		return errors.Join(errors.New("edge proof succeeded but its durable commit failed; Caddy was disabled and crash evidence was reconciled"), commitErr, closeErr)
	}
	return errors.Join(errors.New("edge proof succeeded but its durable commit failed; Caddy or crash-evidence final state is ambiguous"), commitErr, closeErr, rollbackErr, reconcileErr)
}

func errorUnless(condition bool, message string) error {
	if condition {
		return nil
	}
	return errors.New(message)
}
