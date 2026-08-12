package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aionuiportal/internal/ipc"
	"golang.org/x/sys/windows"
)

type sharedConversationRelocationJournal struct {
	ProjectID   string   `json:"project_id"`
	OldOwnerSID string   `json:"old_owner_sid"`
	NewOwnerSID string   `json:"new_owner_sid"`
	OldPath     string   `json:"old_path"`
	NewPath     string   `json:"new_path"`
	IDs         []string `json:"ids"`
}

func (h *Host) relocateSharedProjectConversations(ctx context.Context, request ipc.SharedConversationRelocateRequest) (string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) || strings.EqualFold(request.OldOwnerSID, request.NewOwnerSID) {
		return "INVALID_SHARED_RELOCATION", errors.New("shared conversation relocation request is invalid")
	}
	for _, value := range []string{request.OldOwnerSID, request.NewOwnerSID} {
		sid, err := windows.StringToSid(value)
		if err != nil || sid == nil || !sid.IsValid() || !strings.EqualFold(sid.String(), value) {
			return "INVALID_SHARED_RELOCATION", errors.New("shared conversation relocation SID is invalid")
		}
	}
	base := filepath.Clean(h.cfg.DataRootBase)
	oldPath := filepath.Join(base, "shared", request.OldOwnerSID, request.ProjectID)
	newPath := filepath.Join(base, "shared", request.NewOwnerSID, request.ProjectID)
	switch request.Phase {
	case "prepare":
		if err := requireNormalDirectory(oldPath); err != nil {
			return "SHARED_RELOCATION_SOURCE_INVALID", err
		}
		if journal, err := h.readSharedConversationRelocation(request.ProjectID); err == nil {
			if sameRelocation(journal, request, oldPath, newPath) {
				return "", nil
			}
			return "SHARED_RELOCATION_BUSY", errors.New("another shared conversation relocation is pending")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "SHARED_RELOCATION_FAILED", err
		}
		ids, err := privateSharedConversationIDs(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), oldPath)
		if err != nil {
			return "SHARED_RELOCATION_FAILED", err
		}
		if err := h.stopAndEvictProjectConversations(ctx, ids); err != nil {
			restoreErr := h.evictAndEnsureProjectConversations(context.Background(), ids)
			return "PROJECT_IN_USE", errors.Join(err, restoreErr)
		}
		journal := sharedConversationRelocationJournal{ProjectID: request.ProjectID, OldOwnerSID: request.OldOwnerSID, NewOwnerSID: request.NewOwnerSID, OldPath: oldPath, NewPath: newPath, IDs: ids}
		if err := h.writeSharedConversationRelocation(journal); err != nil {
			restoreErr := h.evictAndEnsureProjectConversations(context.Background(), ids)
			return "SHARED_RELOCATION_FAILED", errors.Join(err, restoreErr)
		}
		return "", nil
	case "commit":
		journal, err := h.readSharedConversationRelocation(request.ProjectID)
		if err != nil || !sameRelocation(journal, request, oldPath, newPath) {
			return "SHARED_RELOCATION_FAILED", errors.New("shared conversation relocation journal is missing or invalid")
		}
		if err := requireNormalDirectory(newPath); err != nil {
			return "SHARED_RELOCATION_TARGET_INVALID", err
		}
		currentIDs, err := privateSharedConversationIDs(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), oldPath)
		if err != nil {
			return "SHARED_RELOCATION_FAILED", err
		}
		if !sameConversationIDs(currentIDs, journal.IDs) {
			return "SHARED_RELOCATION_CHANGED", errors.New("shared project conversations changed after relocation preparation")
		}
		if err := setConversationWorkspaces(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), journal.IDs, oldPath, newPath, newPath); err != nil {
			return "SHARED_RELOCATION_FAILED", err
		}
		if err := h.evictAndEnsureProjectConversations(ctx, journal.IDs); err != nil {
			compensationContext := context.Background()
			evictErr := h.stopAndEvictProjectConversations(compensationContext, journal.IDs)
			rewriteErr := setConversationWorkspaces(compensationContext, filepath.Join(h.dirs.Data, "aionui-backend.db"), journal.IDs, oldPath, newPath, oldPath)
			return "SHARED_RELOCATION_RESUME_FAILED", errors.Join(err, evictErr, rewriteErr)
		}
		return "", nil
	case "rollback":
		journal, err := h.readSharedConversationRelocation(request.ProjectID)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil || !sameRelocation(journal, request, oldPath, newPath) {
			return "SHARED_RELOCATION_FAILED", errors.New("shared conversation relocation journal is invalid")
		}
		if err := requireNormalDirectory(oldPath); err != nil {
			return "SHARED_RELOCATION_SOURCE_INVALID", err
		}
		if err := setConversationWorkspaces(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), journal.IDs, oldPath, newPath, oldPath); err != nil {
			return "SHARED_RELOCATION_FAILED", err
		}
		if err := h.evictAndEnsureProjectConversations(ctx, journal.IDs); err != nil {
			return "SHARED_RELOCATION_RESUME_FAILED", err
		}
		return "", os.Remove(h.sharedConversationRelocationPath(request.ProjectID))
	case "finish":
		journal, err := h.readSharedConversationRelocation(request.ProjectID)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil || !sameRelocation(journal, request, oldPath, newPath) {
			return "SHARED_RELOCATION_FAILED", errors.New("shared conversation relocation journal is invalid")
		}
		return "", os.Remove(h.sharedConversationRelocationPath(request.ProjectID))
	default:
		return "INVALID_SHARED_RELOCATION", errors.New("shared conversation relocation phase is invalid")
	}
}

func sameConversationIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func privateSharedConversationIDs(ctx context.Context, dbPath, workspace string) ([]string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?mode=ro&_pragma=busy_timeout(3000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT id,extra FROM conversations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return nil, fmt.Errorf("conversation %s has invalid extra JSON", id)
		}
		path, pathOK := extra["workspace"].(string)
		custom, customOK := extra["custom_workspace"].(bool)
		internal, _ := extra["internal_shared_runtime"].(bool)
		if pathOK && customOK && custom && !internal && samePath(path, workspace) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, rows.Err()
}

func setConversationWorkspaces(ctx context.Context, dbPath string, ids []string, oldPath, newPath, target string) error {
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(3000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT extra FROM conversations WHERE id=?`, id).Scan(&raw); err != nil {
			return fmt.Errorf("read conversation %s: %w", id, err)
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return fmt.Errorf("conversation %s has invalid extra JSON", id)
		}
		workspace, ok := extra["workspace"].(string)
		if !ok || (!samePath(workspace, oldPath) && !samePath(workspace, newPath)) {
			return fmt.Errorf("conversation %s escaped the relocation paths", id)
		}
		extra["workspace"] = target
		updated, err := json.Marshal(extra)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE conversations SET extra=? WHERE id=? AND extra=?`, string(updated), id, raw)
		if err != nil {
			return err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return errors.New("conversation changed during shared project relocation")
		}
	}
	return tx.Commit()
}

func (h *Host) stopAndEvictProjectConversations(ctx context.Context, ids []string) error {
	active, err := h.activeProjectConversations(ctx, ids)
	if err != nil {
		return err
	}
	if err := h.stopProjectConversations(ctx, active); err != nil {
		return err
	}
	for _, id := range ids {
		if err := h.evictProjectConversationRuntime(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) evictAndEnsureProjectConversations(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := h.evictProjectConversationRuntime(ctx, id); err != nil {
			return err
		}
		if err := h.ensureProjectConversationRuntime(ctx, id); err != nil {
			return fmt.Errorf("resume relocated conversation %s: %w", id, err)
		}
	}
	return nil
}

func (h *Host) evictProjectConversationRuntime(ctx context.Context, id string) error {
	if !validRuntimeConversationID(id) {
		return errors.New("invalid project conversation id")
	}
	path := "/api/internal/conversations/" + url.PathEscape(id) + "/runtime/evict"
	return h.client.sendJSONWithHeader(ctx, http.MethodPost, path, struct{}{}, nil, "x-aionui-portal-runtime-control", h.runtimeControlSecret)
}

func (h *Host) sharedConversationRelocationPath(projectID string) string {
	return filepath.Join(h.dirs.Data, "shared-project-transactions", projectID+".relocate.json")
}

func (h *Host) writeSharedConversationRelocation(journal sharedConversationRelocationJournal) error {
	directory := filepath.Dir(h.sharedConversationRelocationPath(journal.ProjectID))
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
	temporary := h.sharedConversationRelocationPath(journal.ProjectID) + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, h.sharedConversationRelocationPath(journal.ProjectID)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (h *Host) readSharedConversationRelocation(projectID string) (sharedConversationRelocationJournal, error) {
	encoded, err := os.ReadFile(h.sharedConversationRelocationPath(projectID))
	if err != nil {
		return sharedConversationRelocationJournal{}, err
	}
	var journal sharedConversationRelocationJournal
	if json.Unmarshal(encoded, &journal) != nil || journal.ProjectID != projectID || !validSharedProjectID(projectID) {
		return sharedConversationRelocationJournal{}, errors.New("shared conversation relocation journal is invalid")
	}
	for _, id := range journal.IDs {
		if !validRuntimeConversationID(id) {
			return sharedConversationRelocationJournal{}, errors.New("shared conversation relocation journal has an invalid conversation")
		}
	}
	return journal, nil
}

func sameRelocation(journal sharedConversationRelocationJournal, request ipc.SharedConversationRelocateRequest, oldPath, newPath string) bool {
	return journal.ProjectID == request.ProjectID && strings.EqualFold(journal.OldOwnerSID, request.OldOwnerSID) && strings.EqualFold(journal.NewOwnerSID, request.NewOwnerSID) && samePath(journal.OldPath, oldPath) && samePath(journal.NewPath, newPath)
}
