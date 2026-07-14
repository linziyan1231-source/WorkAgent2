package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"aionuiportal/internal/ipc"
	"aionuiportal/internal/projectfs"
	"aionuiportal/internal/winutil"
	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
)

type projectConversationUpdate struct {
	id      string
	oldJSON string
	newJSON string
}

func (h *Host) renameProject(ctx context.Context, request ipc.ProjectRenameRequest) (ipc.ProjectRenameResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", errors.New("project rename did not match this healthy UserHost instance")
	}
	activity := h.probeActivity(ctx)
	if !activity.Known {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", errors.New("project activity could not be verified")
	}
	if activity.Active {
		return ipc.ProjectRenameResult{}, "PROJECT_IN_USE", errors.New("AionUi has active work and cannot rename a project")
	}
	return renameProjectState(ctx, h.dirs.Workspace, filepath.Join(h.dirs.Data, "aionui-backend.db"), h.cfg.WindowsSID, request.OldName, request.NewName)
}

func renameProjectState(ctx context.Context, workspaceRoot, dbPath, sid, oldName, newName string) (ipc.ProjectRenameResult, string, error) {
	source, sourceOK := projectfs.ResolveChild(workspaceRoot, oldName)
	target, targetOK := projectfs.ResolveChild(workspaceRoot, newName)
	if !sourceOK || !targetOK || source == target {
		return ipc.ProjectRenameResult{}, "INVALID_PROJECT_NAME", errors.New("project names are invalid or unchanged")
	}
	policy := winutil.PrivateTreePolicy(sid)
	if err := winutil.VerifyACL(workspaceRoot, policy); err != nil {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("verify project workspace ACL: %w", err)
	}
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return ipc.ProjectRenameResult{}, "PROJECT_NOT_FOUND", errors.New("project directory does not exist")
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("inspect project directory: %w", err)
	}
	if err := winutil.VerifyDescendantACL(source, policy); err != nil {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("verify project directory ACL: %w", err)
	}
	if !strings.EqualFold(source, target) {
		if _, err := os.Lstat(target); err == nil {
			return ipc.ProjectRenameResult{}, "PROJECT_EXISTS", errors.New("target project already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("inspect target project directory: %w", err)
		}
	}
	dbInfo, err := os.Lstat(dbPath)
	if err != nil || !dbInfo.Mode().IsRegular() || dbInfo.Mode()&os.ModeSymlink != 0 {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("inspect AionCore database: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(3000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("open AionCore database for project rename: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ipc.ProjectRenameResult{}, projectRenameDatabaseErrorCode(err), fmt.Errorf("begin project rename transaction: %w", err)
	}
	defer tx.Rollback()
	columns, err := tableColumns(ctx, tx, "conversations")
	if err != nil || !containsColumn(columns, "id") || !containsColumn(columns, "extra") {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", errors.New("AionCore conversations schema is unsupported")
	}
	updates, err := projectConversationUpdates(ctx, tx, source, target)
	if err != nil {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", err
	}
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE conversations SET extra=? WHERE id=? AND extra=?`, update.newJSON, update.id, update.oldJSON)
		if err != nil {
			return ipc.ProjectRenameResult{}, projectRenameDatabaseErrorCode(err), fmt.Errorf("update project conversation %s: %w", update.id, err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ipc.ProjectRenameResult{}, "PROJECT_IN_USE", errors.New("project conversation changed during rename")
		}
	}
	if err := os.Rename(source, target); err != nil {
		return ipc.ProjectRenameResult{}, projectRenameFilesystemErrorCode(err), fmt.Errorf("rename project directory: %w", err)
	}
	rollbackDirectory := func(cause error) error {
		if rollbackErr := os.Rename(target, source); rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("roll back project directory rename: %w", rollbackErr))
		}
		return cause
	}
	if err := winutil.VerifyDescendantACL(target, policy); err != nil {
		return ipc.ProjectRenameResult{}, "PROJECT_RENAME_FAILED", rollbackDirectory(fmt.Errorf("verify renamed project ACL: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return ipc.ProjectRenameResult{}, projectRenameDatabaseErrorCode(err), rollbackDirectory(fmt.Errorf("commit project rename: %w", err))
	}
	return ipc.ProjectRenameResult{OldPath: source, NewPath: target, UpdatedConversations: len(updates)}, "", nil
}

func projectConversationUpdates(ctx context.Context, tx *sql.Tx, source, target string) ([]projectConversationUpdate, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,extra FROM conversations`)
	if err != nil {
		return nil, fmt.Errorf("read project conversations: %w", err)
	}
	defer rows.Close()
	var updates []projectConversationUpdate
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan project conversation: %w", err)
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return nil, fmt.Errorf("conversation %s has invalid extra JSON", id)
		}
		workspace, workspaceOK := extra["workspace"].(string)
		custom, customOK := extra["custom_workspace"].(bool)
		if !workspaceOK || !customOK || !custom || !samePath(workspace, source) {
			continue
		}
		extra["workspace"] = target
		encoded, err := json.Marshal(extra)
		if err != nil {
			return nil, fmt.Errorf("encode project conversation %s: %w", id, err)
		}
		updates = append(updates, projectConversationUpdate{id: id, oldJSON: raw, newJSON: string(encoded)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read project conversations: %w", err)
	}
	return updates, nil
}

func projectRenameFilesystemErrorCode(err error) string {
	for _, code := range []syscall.Errno{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION} {
		if errors.Is(err, code) {
			return "PROJECT_IN_USE"
		}
	}
	return "PROJECT_RENAME_FAILED"
}

func projectRenameDatabaseErrorCode(err error) string {
	if strings.Contains(strings.ToLower(err.Error()), "database is locked") || strings.Contains(strings.ToLower(err.Error()), "database table is locked") {
		return "PROJECT_IN_USE"
	}
	return "PROJECT_RENAME_FAILED"
}
