package userhost

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"aionuiportal/internal/ipc"
	"aionuiportal/internal/projectfs"
	"aionuiportal/internal/winutil"
	"golang.org/x/sys/windows"
)

type sharedFileRecord struct {
	Relative string
	Size     int64
	SHA256   [sha256.Size]byte
}

type sharedTransferJournal struct {
	ProjectID                   string   `json:"project_id"`
	OldOwnerSID                 string   `json:"old_owner_sid"`
	Source                      string   `json:"source"`
	Target                      string   `json:"target"`
	OldMemberSIDs               []string `json:"old_member_sids"`
	PreviousOwnerRootMemberSIDs []string `json:"previous_owner_root_member_sids"`
}

func (h *Host) transferSharedProject(ctx context.Context, request ipc.SharedTransferRequest) (string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) || strings.EqualFold(request.OldOwnerSID, h.cfg.WindowsSID) {
		return "INVALID_SHARED_TRANSFER", errors.New("shared ownership transfer request is invalid")
	}
	if sid, err := windows.StringToSid(request.OldOwnerSID); err != nil || sid == nil || !sid.IsValid() || !strings.EqualFold(sid.String(), request.OldOwnerSID) {
		return "INVALID_SHARED_TRANSFER", errors.New("old owner SID is invalid")
	}
	projectMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.ProjectMemberSIDs)
	if err != nil {
		return "INVALID_SHARED_MEMBERS", err
	}
	oldMembers, err := validateSharedSIDs(request.OldOwnerSID, request.OldProjectMemberSIDs)
	if err != nil {
		return "INVALID_SHARED_MEMBERS", err
	}
	rootMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.OwnerRootMemberSIDs)
	if err != nil {
		return "INVALID_SHARED_MEMBERS", err
	}
	previousRootMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.PreviousOwnerRootMemberSIDs)
	if err != nil {
		return "INVALID_SHARED_MEMBERS", err
	}
	base := filepath.Clean(h.cfg.DataRootBase)
	source := filepath.Join(base, "shared", request.OldOwnerSID, request.ProjectID)
	targetOwnerRoot := filepath.Join(base, "shared", h.cfg.WindowsSID)
	target := filepath.Join(targetOwnerRoot, request.ProjectID)
	if err := requireNormalDirectory(source); err != nil {
		return "SHARED_PROJECT_NOT_FOUND", err
	}
	if err := requireNormalDirectory(targetOwnerRoot); err != nil {
		return "SHARED_ROOT_INVALID", err
	}
	if _, err := os.Lstat(target); err == nil {
		return "SHARED_PROJECT_EXISTS", errors.New("new owner project path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "SHARED_TRANSFER_FAILED", err
	}
	manifest, err := buildSharedManifest(ctx, source, true, h.cfg.VerifyReleaseIntegrity)
	if err != nil {
		return "SHARED_TRANSFER_FAILED", err
	}
	size, err := manifestSize(manifest)
	if err != nil {
		return "SHARED_TRANSFER_FAILED", err
	}
	usage, err := measureStorageUsage(ctx, targetOwnerRoot, sharedStorageLimitBytes)
	if err != nil {
		return "SHARED_USAGE_UNAVAILABLE", err
	}
	if size > usage.RemainingBytes {
		return "SHARED_QUOTA_EXCEEDED", fmt.Errorf("project needs %d bytes but new owner has %d shared bytes remaining", size, usage.RemainingBytes)
	}
	ownerPolicy := winutil.SharedOwnerRootPolicy(h.cfg.WindowsSID, rootMembers)
	previousOwnerPolicy := winutil.SharedOwnerRootPolicy(h.cfg.WindowsSID, previousRootMembers)
	if err := winutil.ApplyACL(targetOwnerRoot, ownerPolicy); err != nil {
		return "SHARED_ACL_FAILED", err
	}
	if err := winutil.VerifyACL(targetOwnerRoot, ownerPolicy); err != nil {
		restoreErr := errors.Join(winutil.ApplyACL(targetOwnerRoot, previousOwnerPolicy), winutil.VerifyACL(targetOwnerRoot, previousOwnerPolicy))
		return "SHARED_ACL_FAILED", errors.Join(err, restoreErr)
	}
	journal := sharedTransferJournal{ProjectID: request.ProjectID, OldOwnerSID: request.OldOwnerSID, Source: source, Target: target, OldMemberSIDs: oldMembers, PreviousOwnerRootMemberSIDs: previousRootMembers}
	if err := h.writeSharedTransferJournal(journal); err != nil {
		restoreErr := errors.Join(winutil.ApplyACL(targetOwnerRoot, previousOwnerPolicy), winutil.VerifyACL(targetOwnerRoot, previousOwnerPolicy))
		return "SHARED_TRANSFER_FAILED", errors.Join(err, restoreErr)
	}
	if err := os.Rename(source, target); err != nil {
		return "SHARED_TRANSFER_FAILED", errors.Join(err, h.rollbackSharedProjectTransfer(journal))
	}
	movedManifest, err := buildSharedManifest(ctx, target, true, h.cfg.VerifyReleaseIntegrity)
	if err != nil || !sameSharedManifest(manifest, movedManifest) {
		if err == nil {
			err = errors.New("shared project changed while ownership transfer was being prepared")
		}
		return "SHARED_TRANSFER_CHANGED", errors.Join(err, h.rollbackSharedProjectTransfer(journal))
	}
	movedUsage, err := measureStorageUsage(ctx, targetOwnerRoot, sharedStorageLimitBytes)
	if err != nil || movedUsage.UsedBytes > movedUsage.LimitBytes {
		if err == nil {
			err = errors.New("shared project transfer exceeded the new owner's shared quota")
		}
		return "SHARED_QUOTA_EXCEEDED", errors.Join(err, h.rollbackSharedProjectTransfer(journal))
	}
	newPolicy := winutil.SharedProjectPolicy(h.cfg.WindowsSID, projectMembers)
	if err := winutil.ApplyTreeACL(target, newPolicy); err != nil {
		return "SHARED_ACL_FAILED", errors.Join(err, h.rollbackSharedProjectTransfer(journal))
	}
	if err := winutil.VerifyTreeACL(target, newPolicy); err != nil {
		return "SHARED_ACL_FAILED", errors.Join(err, h.rollbackSharedProjectTransfer(journal))
	}
	return "", nil
}

func (h *Host) finishSharedProjectTransfer(request ipc.SharedTransferRequest) (string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) {
		return "INVALID_SHARED_TRANSFER", errors.New("shared ownership transfer finalization is invalid")
	}
	journal, err := h.readSharedTransferJournal(request.ProjectID)
	if err != nil {
		return "SHARED_TRANSFER_FAILED", err
	}
	if request.Commit {
		if err := requireNormalDirectory(journal.Target); err != nil {
			return "SHARED_TRANSFER_FAILED", err
		}
		return "", os.Remove(h.sharedTransferJournalPath(request.ProjectID))
	}
	if err := h.rollbackSharedProjectTransfer(journal); err != nil {
		return "SHARED_TRANSFER_FAILED", err
	}
	return "", nil
}

func (h *Host) rollbackSharedProjectTransfer(journal sharedTransferJournal) error {
	targetExists := requireNormalDirectory(journal.Target) == nil
	sourceExists := requireNormalDirectory(journal.Source) == nil
	if targetExists == sourceExists {
		return errors.New("shared transfer rollback requires exactly one project location")
	}
	if targetExists {
		if err := os.Rename(journal.Target, journal.Source); err != nil {
			return err
		}
	}
	oldPolicy := winutil.SharedProjectPolicy(journal.OldOwnerSID, journal.OldMemberSIDs)
	if err := winutil.ApplyTreeACL(journal.Source, oldPolicy); err != nil {
		return err
	}
	if err := winutil.VerifyTreeACL(journal.Source, oldPolicy); err != nil {
		return err
	}
	targetOwnerRoot := filepath.Dir(journal.Target)
	previousOwnerPolicy := winutil.SharedOwnerRootPolicy(h.cfg.WindowsSID, journal.PreviousOwnerRootMemberSIDs)
	if err := winutil.ApplyACL(targetOwnerRoot, previousOwnerPolicy); err != nil {
		return err
	}
	if err := winutil.VerifyACL(targetOwnerRoot, previousOwnerPolicy); err != nil {
		return err
	}
	return os.Remove(h.sharedTransferJournalPath(journal.ProjectID))
}

func (h *Host) sharedTransferJournalPath(projectID string) string {
	return filepath.Join(h.dirs.Data, "shared-project-transactions", projectID+".transfer.json")
}

func (h *Host) writeSharedTransferJournal(journal sharedTransferJournal) error {
	directory := filepath.Dir(h.sharedTransferJournalPath(journal.ProjectID))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := requireNormalDirectory(directory); err != nil {
		return err
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	temporary := h.sharedTransferJournalPath(journal.ProjectID) + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, h.sharedTransferJournalPath(journal.ProjectID)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (h *Host) readSharedTransferJournal(projectID string) (sharedTransferJournal, error) {
	encoded, err := os.ReadFile(h.sharedTransferJournalPath(projectID))
	if err != nil {
		return sharedTransferJournal{}, err
	}
	var journal sharedTransferJournal
	if json.Unmarshal(encoded, &journal) != nil || journal.ProjectID != projectID || !validSharedProjectID(projectID) || strings.EqualFold(journal.OldOwnerSID, h.cfg.WindowsSID) {
		return sharedTransferJournal{}, errors.New("shared ownership transfer journal is invalid")
	}
	base := filepath.Clean(h.cfg.DataRootBase)
	if !samePath(journal.Source, filepath.Join(base, "shared", journal.OldOwnerSID, projectID)) || !samePath(journal.Target, filepath.Join(base, "shared", h.cfg.WindowsSID, projectID)) {
		return sharedTransferJournal{}, errors.New("shared ownership transfer journal escaped stable roots")
	}
	if _, err := validateSharedSIDs(h.cfg.WindowsSID, journal.PreviousOwnerRootMemberSIDs); err != nil {
		return sharedTransferJournal{}, errors.New("shared ownership transfer journal contains invalid previous root members")
	}
	return journal, nil
}

func (h *Host) updateSharedProjectACL(request ipc.SharedProjectRequest) (ipc.SharedProjectResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) || h.cfg.ConfigVersion != 2 || !validSharedProjectID(request.ProjectID) {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_PROJECT", errors.New("shared project ACL request is invalid")
	}
	projectMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.ProjectMemberSIDs)
	if err != nil {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_MEMBERS", err
	}
	rootMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.OwnerRootMemberSIDs)
	if err != nil {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_MEMBERS", err
	}
	ownerRoot := filepath.Join(filepath.Clean(h.cfg.DataRootBase), "shared", h.cfg.WindowsSID)
	projectRoot := filepath.Join(ownerRoot, request.ProjectID)
	if err := requireNormalDirectory(ownerRoot); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ROOT_INVALID", err
	}
	if err := requireNormalDirectory(projectRoot); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_NOT_FOUND", err
	}
	if err := removeManagedSharedSkillLinks(projectRoot); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_INVALID", err
	}
	ownerPolicy := winutil.SharedOwnerRootPolicy(h.cfg.WindowsSID, rootMembers)
	if err := winutil.ApplyACL(ownerRoot, ownerPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	projectPolicy := winutil.SharedProjectPolicy(h.cfg.WindowsSID, projectMembers)
	if err := winutil.ApplyTreeACL(projectRoot, projectPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	if err := winutil.VerifyACL(ownerRoot, ownerPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	if err := winutil.VerifyTreeACL(projectRoot, projectPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	return ipc.SharedProjectResult{ProjectID: request.ProjectID}, "", nil
}

func removeManagedSharedSkillLinks(projectRoot string) error {
	for _, relative := range []string{filepath.Join(".codex", "skills"), filepath.Join(".kimi", "skills"), filepath.Join(".claude", "skills")} {
		directory := filepath.Join(projectRoot, relative)
		parent := filepath.Dir(directory)
		parentInfo, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || windowsReparse(parentInfo) {
			return fmt.Errorf("managed shared skill parent must be a normal directory: %s", parent)
		}
		directoryInfo, err := os.Lstat(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || windowsReparse(directoryInfo) {
			return fmt.Errorf("managed shared skill directory must be a normal directory: %s", directory)
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return fmt.Errorf("inspect managed shared skill directory %s: %w", directory, err)
		}
		for _, entry := range entries {
			currentParent, err := os.Lstat(parent)
			if err != nil || !currentParent.IsDir() || currentParent.Mode()&os.ModeSymlink != 0 || windowsReparse(currentParent) {
				return fmt.Errorf("managed shared skill parent changed during cleanup: %s", parent)
			}
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("inspect managed shared skill entry %s: %w", path, err)
			}
			if info.Mode()&os.ModeSymlink == 0 && !windowsReparse(info) {
				continue
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove managed shared skill link %s: %w", path, err)
			}
		}
	}
	return nil
}

func (h *Host) provisionSharedProject(ctx context.Context, request ipc.SharedProjectRequest) (ipc.SharedProjectResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_UNAVAILABLE", errors.New("shared project request did not match this healthy UserHost instance")
	}
	if h.cfg.ConfigVersion != 2 || h.cfg.DataRootBase == "" || !validSharedProjectID(request.ProjectID) {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_PROJECT", errors.New("shared project requires a stable project id and data root")
	}
	if request.SourceKind != "new" && request.SourceKind != "copy" && request.SourceKind != "migrate" {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_PROJECT", errors.New("shared project source kind is invalid")
	}
	projectMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.ProjectMemberSIDs)
	if err != nil {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_MEMBERS", err
	}
	rootMembers, err := validateSharedSIDs(h.cfg.WindowsSID, request.OwnerRootMemberSIDs)
	if err != nil {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_MEMBERS", err
	}
	base := filepath.Clean(h.cfg.DataRootBase)
	sharedRoot := filepath.Join(base, "shared")
	ownerRoot := filepath.Join(sharedRoot, h.cfg.WindowsSID)
	if err := requireNormalDirectory(base); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ROOT_INVALID", err
	}
	if err := requireNormalDirectory(sharedRoot); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ROOT_INVALID", err
	}
	if err := requireNormalDirectory(ownerRoot); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ROOT_INVALID", err
	}
	ownerPolicy := winutil.SharedOwnerRootPolicy(h.cfg.WindowsSID, rootMembers)
	if err := winutil.ApplyACL(ownerRoot, ownerPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", fmt.Errorf("apply shared owner-root ACL: %w", err)
	}
	if err := winutil.VerifyACL(ownerRoot, ownerPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", fmt.Errorf("verify shared owner-root ACL: %w", err)
	}
	target := filepath.Join(ownerRoot, request.ProjectID)
	if _, err := os.Lstat(target); err == nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_EXISTS", errors.New("shared project directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
	}

	var source string
	var sourceManifest []sharedFileRecord
	var sourceConversationIDs []string
	if request.SourceKind != "new" {
		if !validSharedProjectID(request.SourceProjectID) {
			return ipc.SharedProjectResult{}, "INVALID_SOURCE_PROJECT", errors.New("source project id is invalid")
		}
		resolved, code, err := resolveProjectState(h.dirs.Workspace, request.SourceProjectID)
		if err != nil {
			return ipc.SharedProjectResult{}, code, err
		}
		source = resolved.Path
		if err := winutil.VerifyDescendantACL(source, winutil.PrivateTreePolicy(h.cfg.WindowsSID)); err != nil {
			return ipc.SharedProjectResult{}, "SOURCE_PROJECT_INVALID", fmt.Errorf("verify private source project: %w", err)
		}
		sourceManifest, err = buildSharedManifest(ctx, source, true, h.cfg.VerifyReleaseIntegrity)
		if err != nil {
			return ipc.SharedProjectResult{}, "SOURCE_PROJECT_INVALID", err
		}
		sourceConversationIDs, err = projectConversationIDs(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), source)
		if err != nil {
			return ipc.SharedProjectResult{}, "PROJECT_IN_USE", err
		}
		if len(sourceConversationIDs) > 0 {
			active, err := h.activeProjectConversations(ctx, sourceConversationIDs)
			if err != nil {
				return ipc.SharedProjectResult{}, "PROJECT_IN_USE", err
			}
			if len(active) > 0 {
				if err := h.stopProjectConversations(ctx, active); err != nil {
					return ipc.SharedProjectResult{}, "PROJECT_IN_USE", err
				}
			}
		}
	}
	sourceBytes, err := manifestSize(sourceManifest)
	if err != nil {
		return ipc.SharedProjectResult{}, "SOURCE_PROJECT_INVALID", err
	}
	current, err := measureStorageUsage(ctx, ownerRoot, sharedStorageLimitBytes)
	if err != nil {
		return ipc.SharedProjectResult{}, "SHARED_USAGE_UNAVAILABLE", err
	}
	// Reserve a small amount for the stable marker and filesystem metadata. This
	// keeps an otherwise-full 20 GiB owner root from failing after the preflight.
	requiredBytes := sourceBytes
	requiredBytes += 4096
	if requiredBytes > current.RemainingBytes {
		return ipc.SharedProjectResult{}, "SHARED_QUOTA_EXCEEDED", fmt.Errorf("shared project needs %d bytes but only %d bytes remain", requiredBytes, current.RemainingBytes)
	}

	staging := filepath.Join(ownerRoot, ".staging-"+request.ProjectID)
	if _, err := os.Lstat(staging); err == nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_BUSY", errors.New("shared project staging directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
	}
	removeStaging := true
	defer func() {
		if removeStaging {
			_ = os.RemoveAll(staging)
		}
	}()
	if request.SourceKind != "new" {
		if err := copySharedManifest(ctx, source, staging, sourceManifest); err != nil {
			return ipc.SharedProjectResult{}, "SHARED_COPY_FAILED", err
		}
		copied, err := buildSharedManifest(ctx, staging, true, h.cfg.VerifyReleaseIntegrity)
		if err != nil || !sameSharedManifest(sourceManifest, copied) {
			return ipc.SharedProjectResult{}, "SHARED_COPY_VERIFY_FAILED", errors.New("shared project copy did not match its source manifest")
		}
		// Re-read the source after the copy. A source that changed while it was
		// being copied must fail instead of publishing a point-in-time mixture.
		currentSource, err := buildSharedManifest(ctx, source, true, h.cfg.VerifyReleaseIntegrity)
		if err != nil || !sameSharedManifest(sourceManifest, currentSource) {
			return ipc.SharedProjectResult{}, "SHARED_COPY_SOURCE_CHANGED", errors.New("shared project source changed during copy")
		}
		if err := os.Remove(filepath.Join(staging, projectfs.MarkerFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ipc.SharedProjectResult{}, "SHARED_COPY_FAILED", err
		}
	}
	if _, err := projectfs.WriteMarker(staging, request.ProjectID); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
	}
	projectPolicy := winutil.SharedProjectPolicy(h.cfg.WindowsSID, projectMembers)
	if err := winutil.ApplyTreeACL(staging, projectPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	if err := winutil.VerifyTreeACL(staging, projectPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	if err := os.Rename(staging, target); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
	}
	removeStaging = false
	rollbackTarget := true
	defer func() {
		if rollbackTarget {
			_ = os.RemoveAll(target)
		}
	}()
	if err := winutil.VerifyTreeACL(target, projectPolicy); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ACL_FAILED", err
	}
	var clonedConversationIDs []string
	rollbackClones := true
	defer func() {
		if rollbackClones {
			h.discardSharedProjectConversationClones(context.Background(), clonedConversationIDs)
		}
	}()
	if request.SourceKind == "migrate" {
		if err := h.prepareSharedMigration(ctx, request.ProjectID, source, target, sourceConversationIDs); err != nil {
			return ipc.SharedProjectResult{}, "SHARED_MIGRATION_FAILED", err
		}
	} else {
		if request.SourceKind == "copy" {
			clonedConversationIDs, err = h.cloneSharedProjectConversations(ctx, sourceConversationIDs, target)
			if err != nil {
				return ipc.SharedProjectResult{}, "SHARED_SESSION_FORK_FAILED", err
			}
		}
		if err := h.writeSharedProvisionJournal(sharedProvisionJournal{
			ProjectID: request.ProjectID, SourceKind: request.SourceKind, Source: source,
			Target: target, ClonedConversationIDs: clonedConversationIDs,
		}); err != nil {
			return ipc.SharedProjectResult{}, "SHARED_PROJECT_FAILED", err
		}
	}
	rollbackClones = false
	rollbackTarget = false
	return ipc.SharedProjectResult{ProjectID: request.ProjectID, SizeBytes: sourceBytes}, "", nil
}

type sharedProvisionJournal struct {
	ProjectID             string   `json:"project_id"`
	SourceKind            string   `json:"source_kind"`
	Source                string   `json:"source,omitempty"`
	Target                string   `json:"target"`
	Tombstone             string   `json:"tombstone,omitempty"`
	ClonedConversationIDs []string `json:"cloned_conversation_ids,omitempty"`
}

func (h *Host) prepareSharedMigration(ctx context.Context, projectID, source, target string, conversationIDs []string) error {
	dbPath := filepath.Join(h.dirs.Data, "aionui-backend.db")
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_txlock=immediate&_pragma=busy_timeout(3000)&_pragma=foreign_keys(1)"
	db, err := sqlOpenSQLite(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tombstone := filepath.Join(filepath.Dir(source), ".shared-migrating-"+projectID)
	if _, err := os.Lstat(tombstone); err == nil {
		return errors.New("a previous shared migration transaction still exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	journal := sharedProvisionJournal{ProjectID: projectID, SourceKind: "migrate", Source: source, Target: target, Tombstone: tombstone}
	if err := h.writeSharedProvisionJournal(journal); err != nil {
		return err
	}
	keepJournal := false
	defer func() {
		if !keepJournal {
			_ = os.Remove(h.sharedProvisionJournalPath(projectID))
		}
	}()
	updates, err := projectConversationUpdates(ctx, tx, source, target)
	if err != nil {
		return err
	}
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE conversations SET extra=? WHERE id=? AND extra=?`, update.newJSON, update.id, update.oldJSON)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return errors.New("project conversation changed during migration")
		}
	}
	if err := os.Rename(source, tombstone); err != nil {
		return fmt.Errorf("isolate verified private source project: %w", err)
	}
	if err := tx.Commit(); err != nil {
		if rollbackErr := os.Rename(tombstone, source); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore migrated project directory: %w", rollbackErr))
		}
		_ = winutil.ApplyTreeACL(source, winutil.PrivateTreePolicy(h.cfg.WindowsSID))
		return err
	}
	for _, conversationID := range conversationIDs {
		if err := h.ensureProjectConversationRuntime(ctx, conversationID); err != nil {
			rollbackErr := h.rollbackSharedProvision(ctx, journal)
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("resume migrated conversation %s: %w", conversationID, err), rollbackErr)
			}
			return fmt.Errorf("resume migrated conversation %s: %w", conversationID, err)
		}
	}
	if len(conversationIDs) > 0 {
		active, activeErr := h.activeProjectConversations(ctx, conversationIDs)
		if activeErr != nil {
			rollbackErr := h.rollbackSharedProvision(ctx, journal)
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("inspect migration resume validation: %w", activeErr), rollbackErr)
			}
			return fmt.Errorf("inspect migration resume validation: %w", activeErr)
		}
		if err := h.stopProjectConversations(ctx, active); err != nil {
			rollbackErr := h.rollbackSharedProvision(ctx, journal)
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("stop migration resume validation: %w", err), rollbackErr)
			}
			return fmt.Errorf("stop migration resume validation: %w", err)
		}
	}
	keepJournal = true
	return nil
}

func (h *Host) finishSharedProjectProvisioning(ctx context.Context, request ipc.SharedProjectRequest) (ipc.SharedProjectResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) {
		return ipc.SharedProjectResult{}, "INVALID_SHARED_PROJECT", errors.New("shared project finalization request is invalid")
	}
	journal, err := h.readSharedProvisionJournal(request.ProjectID)
	if err != nil {
		return ipc.SharedProjectResult{}, "SHARED_TRANSACTION_MISSING", err
	}
	if request.SourceKind != journal.SourceKind {
		return ipc.SharedProjectResult{}, "SHARED_TRANSACTION_MISMATCH", errors.New("shared project transaction did not match its reservation")
	}
	if request.Commit {
		if journal.SourceKind == "migrate" {
			if err := requireNormalDirectory(journal.Tombstone); err != nil {
				return ipc.SharedProjectResult{}, "SHARED_MIGRATION_FAILED", err
			}
			if err := os.RemoveAll(journal.Tombstone); err != nil {
				return ipc.SharedProjectResult{}, "SHARED_MIGRATION_FAILED", fmt.Errorf("delete migrated private source: %w", err)
			}
		} else if journal.SourceKind == "copy" {
			if err := writeSharedCopyNotice(journal.Source, journal.Target); err != nil {
				return ipc.SharedProjectResult{}, "SHARED_COPY_NOTICE_FAILED", err
			}
		}
		_ = os.Remove(h.sharedProvisionJournalPath(request.ProjectID))
		return ipc.SharedProjectResult{ProjectID: request.ProjectID}, "", nil
	}
	if err := h.rollbackSharedProvision(ctx, journal); err != nil {
		return ipc.SharedProjectResult{}, "SHARED_ROLLBACK_FAILED", err
	}
	_ = os.Remove(h.sharedProvisionJournalPath(request.ProjectID))
	return ipc.SharedProjectResult{ProjectID: request.ProjectID}, "", nil
}

func (h *Host) rollbackSharedProvision(ctx context.Context, journal sharedProvisionJournal) error {
	if journal.SourceKind != "migrate" {
		h.discardSharedProjectConversationClones(ctx, journal.ClonedConversationIDs)
		return os.RemoveAll(journal.Target)
	}
	if err := requireNormalDirectory(journal.Target); err != nil {
		return err
	}
	if err := requireNormalDirectory(journal.Tombstone); err != nil {
		return err
	}
	if _, err := os.Lstat(journal.Source); err == nil {
		return errors.New("private source path already exists during shared migration rollback")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dbPath := filepath.Join(h.dirs.Data, "aionui-backend.db")
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_txlock=immediate&_pragma=busy_timeout(3000)&_pragma=foreign_keys(1)"
	db, err := sqlOpenSQLite(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	updates, err := projectConversationUpdates(ctx, tx, journal.Target, journal.Source)
	if err != nil {
		return err
	}
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE conversations SET extra=? WHERE id=? AND extra=?`, update.newJSON, update.id, update.oldJSON)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return errors.New("project conversation changed during migration rollback")
		}
	}
	if err := os.Rename(journal.Tombstone, journal.Source); err != nil {
		return err
	}
	if err := winutil.ApplyTreeACL(journal.Source, winutil.PrivateTreePolicy(h.cfg.WindowsSID)); err != nil {
		_ = os.Rename(journal.Source, journal.Tombstone)
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = os.Rename(journal.Source, journal.Tombstone)
		return err
	}
	return os.RemoveAll(journal.Target)
}

func (h *Host) sharedProvisionJournalPath(projectID string) string {
	return filepath.Join(h.dirs.Data, "shared-project-transactions", projectID+".json")
}

func (h *Host) writeSharedProvisionJournal(journal sharedProvisionJournal) error {
	directory := filepath.Dir(h.sharedProvisionJournalPath(journal.ProjectID))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := requireNormalDirectory(directory); err != nil {
		return err
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	temporary := h.sharedProvisionJournalPath(journal.ProjectID) + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, h.sharedProvisionJournalPath(journal.ProjectID)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (h *Host) readSharedProvisionJournal(projectID string) (sharedProvisionJournal, error) {
	encoded, err := os.ReadFile(h.sharedProvisionJournalPath(projectID))
	if err != nil {
		return sharedProvisionJournal{}, err
	}
	var journal sharedProvisionJournal
	if err := json.Unmarshal(encoded, &journal); err != nil || journal.ProjectID != projectID || !validSharedProjectID(journal.ProjectID) || (journal.SourceKind != "new" && journal.SourceKind != "copy" && journal.SourceKind != "migrate") {
		return sharedProvisionJournal{}, errors.New("shared project transaction journal is invalid")
	}
	ownerRoot := filepath.Join(filepath.Clean(h.cfg.DataRootBase), "shared", h.cfg.WindowsSID)
	if !samePath(filepath.Dir(journal.Target), ownerRoot) || filepath.Base(journal.Target) != projectID {
		return sharedProvisionJournal{}, errors.New("shared project transaction target escaped its owner root")
	}
	if (journal.SourceKind == "copy" || journal.SourceKind == "migrate") && !samePath(filepath.Dir(journal.Source), h.dirs.Workspace) {
		return sharedProvisionJournal{}, errors.New("shared project source escaped the private workspace")
	}
	if journal.SourceKind == "migrate" && !samePath(filepath.Dir(journal.Tombstone), h.dirs.Workspace) {
		return sharedProvisionJournal{}, errors.New("shared project migration journal escaped the private workspace")
	}
	for _, id := range journal.ClonedConversationIDs {
		if !validRuntimeConversationID(id) {
			return sharedProvisionJournal{}, errors.New("shared project transaction contains an invalid cloned conversation")
		}
	}
	return journal, nil
}

func (h *Host) cloneSharedProjectConversations(ctx context.Context, sourceIDs []string, workspace string) ([]string, error) {
	cloned := make([]string, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		if !validRuntimeConversationID(sourceID) {
			h.discardSharedProjectConversationClones(context.Background(), cloned)
			return nil, errors.New("source project contains an invalid conversation id")
		}
		var response struct {
			Success bool `json:"success"`
			Data    struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		path := "/api/internal/conversations/" + url.PathEscape(sourceID) + "/clone-to-workspace"
		err := h.client.sendJSONWithHeader(ctx, http.MethodPost, path, map[string]string{"workspace": workspace}, &response,
			"x-aionui-portal-runtime-control", h.runtimeControlSecret)
		if err != nil || !response.Success || !validRuntimeConversationID(response.Data.ID) {
			h.discardSharedProjectConversationClones(context.Background(), cloned)
			if err == nil {
				err = errors.New("AionCore returned an invalid conversation clone")
			}
			return nil, err
		}
		cloned = append(cloned, response.Data.ID)
	}
	return cloned, nil
}

func (h *Host) discardSharedProjectConversationClones(ctx context.Context, ids []string) {
	for _, id := range ids {
		if !validRuntimeConversationID(id) {
			continue
		}
		path := "/api/internal/conversations/" + url.PathEscape(id) + "/discard-clone"
		_ = h.client.sendJSONWithHeader(ctx, http.MethodPost, path, struct{}{}, nil,
			"x-aionui-portal-runtime-control", h.runtimeControlSecret)
	}
}

func (h *Host) ensureProjectConversationRuntime(ctx context.Context, id string) error {
	if !validRuntimeConversationID(id) {
		return errors.New("invalid project conversation id")
	}
	path := "/api/conversations/" + url.PathEscape(id) + "/runtime/ensure"
	return h.client.sendJSON(ctx, http.MethodPost, path, struct{}{}, nil)
}

func writeSharedCopyNotice(source, target string) error {
	if err := requireNormalDirectory(source); err != nil {
		return err
	}
	path := filepath.Join(source, "AGENTS.md")
	var existing []byte
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().IsDir() || info.Size() > 1024*1024 {
			return errors.New("existing AGENTS.md is not a bounded normal file")
		}
		existing, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	notice := fmt.Sprintf("\n\n## Shared project copy\n\nThis project was copied to `%s`. Continue shared work in the copied project directory.\n", target)
	if strings.Contains(string(existing), notice) {
		return nil
	}
	contents := append(append([]byte(nil), existing...), []byte(notice)...)
	temporary := path + ".shared-copy.tmp"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func validRuntimeConversationID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

var sqlOpenSQLite = openSQLite

func openSQLite(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func validateSharedSIDs(owner string, values []string) ([]string, error) {
	seen := map[string]bool{strings.ToUpper(owner): true}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, err := windows.StringToSid(value)
		if err != nil || parsed == nil || !parsed.IsValid() || !strings.EqualFold(parsed.String(), value) {
			return nil, errors.New("shared project contains an invalid member SID")
		}
		upper := strings.ToUpper(value)
		if upper == strings.ToUpper(winutil.UsersSID) || upper == strings.ToUpper(winutil.EveryoneSID) {
			return nil, errors.New("shared project may not grant a general user group")
		}
		if seen[upper] {
			continue
		}
		seen[upper] = true
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToUpper(result[i]) < strings.ToUpper(result[j]) })
	return result, nil
}

func validSharedProjectID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 24
}

func requireNormalDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || windowsReparse(info) {
		return fmt.Errorf("directory is missing or is a reparse point: %s", path)
	}
	return nil
}

func windowsReparse(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// buildSharedManifest records the relative path and size of every regular
// file below root. When hashContent is false (intranet mode,
// verify_release_integrity off) the SHA256 field is left zeroed and only
// metadata is recorded: sameSharedManifest then compares paths and sizes
// only, which gives up content-level detection of concurrent modifications
// during copy or ownership transfer.
func buildSharedManifest(ctx context.Context, root string, includeMarker, hashContent bool) ([]sharedFileRecord, error) {
	if err := requireNormalDirectory(root); err != nil {
		return nil, err
	}
	var records []sharedFileRecord
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("reparse points are forbidden in shared project input: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if windowsReparse(info) {
			return fmt.Errorf("reparse points are forbidden in shared project input: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular files are forbidden in shared project input: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !includeMarker && strings.EqualFold(relative, projectfs.MarkerFileName) {
			return nil
		}
		var digest [sha256.Size]byte
		if hashContent {
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
			copy(digest[:], hash.Sum(nil))
		}
		records = append(records, sharedFileRecord{Relative: relative, Size: info.Size(), SHA256: digest})
		return nil
	})
	sort.Slice(records, func(i, j int) bool {
		return strings.ToLower(records[i].Relative) < strings.ToLower(records[j].Relative)
	})
	return records, err
}

func manifestSize(records []sharedFileRecord) (uint64, error) {
	var result uint64
	for _, record := range records {
		result += uint64(record.Size)
	}
	return result, nil
}

func copySharedManifest(ctx context.Context, source, target string, records []sharedFileRecord) error {
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		from, to := filepath.Join(source, record.Relative), filepath.Join(target, record.Relative)
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		input, err := os.Open(from)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			input.Close()
			return err
		}
		written, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeOutputErr, closeInputErr := output.Close(), input.Close()
		if copyErr != nil || syncErr != nil || closeOutputErr != nil || closeInputErr != nil || written != record.Size {
			return errors.Join(copyErr, syncErr, closeOutputErr, closeInputErr, fmt.Errorf("copied %d of %d bytes for %s", written, record.Size, record.Relative))
		}
	}
	return nil
}

func sameSharedManifest(left, right []sharedFileRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index].Relative, right[index].Relative) || left[index].Size != right[index].Size || left[index].SHA256 != right[index].SHA256 {
			return false
		}
	}
	return true
}
