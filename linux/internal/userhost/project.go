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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

type projectRenameResult struct {
	Name                 string `json:"name"`
	OldPath              string `json:"old_path"`
	NewPath              string `json:"new_path"`
	UpdatedConversations int    `json:"updated_conversations"`
}

type projectConversationUpdate struct {
	ID      string `json:"id"`
	OldJSON string `json:"old_json"`
	NewJSON string `json:"new_json"`
}

type activeProjectConversation struct {
	id, turnID string
}

type projectRuntime struct {
	State                *string `json:"state"`
	IsProcessing         *bool   `json:"is_processing"`
	PendingConfirmations *int    `json:"pending_confirmations"`
	TurnID               *string `json:"turn_id"`
}

func (h *Host) renameProjectOperation(ctx context.Context, oldName, newName string, force, legacyRoot bool) (projectRenameResult, string, error) {
	h.projectRenameMu.Lock()
	defer h.projectRenameMu.Unlock()
	if !projectfs.ValidProjectName(newName) || (!legacyRoot && (!projectfs.ValidProjectName(oldName) || oldName == newName)) {
		return projectRenameResult{}, "INVALID_PROJECT_NAME", errors.New("project names are invalid or unchanged")
	}
	if !h.cfg.Backend.InternalAuth.Enabled {
		return projectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", errors.New("project database is not configured")
	}
	source := h.workspace.Path()
	if !legacyRoot {
		source = filepath.Join(h.workspace.Path(), oldName)
	}
	relativeDatabase, err := filepath.Rel(h.cfg.DataRoot, h.cfg.Backend.InternalAuth.DatabasePath)
	if err != nil || relativeDatabase == "." || strings.HasPrefix(relativeDatabase, ".."+string(filepath.Separator)) {
		return projectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", errors.New("project database path is invalid")
	}
	conversationIDs, err := projectConversationIDs(ctx, h.dataRoot, relativeDatabase, h.uid, source)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", fmt.Errorf("inspect project conversations: %w", err)
	}
	active, err := h.activeProjectConversations(ctx, conversationIDs)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", fmt.Errorf("inspect project activity: %w", err)
	}
	if len(active) > 0 && !force {
		return projectRenameResult{}, "PROJECT_IN_USE", errors.New("project has active conversations")
	}
	if len(active) > 0 {
		if err := h.stopProjectConversations(ctx, active); err != nil {
			return projectRenameResult{}, "PROJECT_IN_USE", fmt.Errorf("stop active project conversations: %w", err)
		}
	}
	users, err := h.projectFileUsers(source, legacyRoot)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_UNAVAILABLE", fmt.Errorf("inspect project file users: %w", err)
	}
	if len(users) > 0 && !force {
		return projectRenameResult{}, "PROJECT_IN_USE", errors.New("project has active file users")
	}
	if len(users) > 0 {
		if err := h.stopProjectFileUsers(ctx, source, legacyRoot, users); err != nil {
			return projectRenameResult{}, "PROJECT_FORCE_STOP_FAILED", err
		}
	}
	return renameProjectState(ctx, h.workspace, h.dataRoot, relativeDatabase, h.uid, oldName, newName, legacyRoot)
}

func projectConversationIDs(ctx context.Context, dataRoot *projectfs.Root, databaseRelative string, uid uint32, workspace string) ([]string, error) {
	database, held, err := openProjectDatabase(dataRoot, databaseRelative, uid, true)
	if err != nil {
		return nil, err
	}
	defer database.Close()
	defer held.Close()
	rows, err := database.QueryContext(ctx, `SELECT id,extra FROM conversations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		if len(ids) > 10000 {
			return nil, errors.New("project has too many conversations")
		}
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
		if pathOK && customOK && custom && sameProjectPath(path, workspace) {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func (h *Host) activeProjectConversations(ctx context.Context, ids []string) ([]activeProjectConversation, error) {
	active := make([]activeProjectConversation, 0, len(ids))
	for _, id := range ids {
		var response struct {
			Success *bool `json:"success"`
			Data    *struct {
				ID      *string         `json:"id"`
				Runtime *projectRuntime `json:"runtime"`
			} `json:"data"`
		}
		if err := h.backendJSON(ctx, http.MethodGet, "/api/conversations/"+url.PathEscape(id), nil, &response); err != nil || response.Success == nil || !*response.Success || response.Data == nil || response.Data.ID == nil || *response.Data.ID != id {
			return nil, fmt.Errorf("conversation %s runtime is unavailable", id)
		}
		runtime := response.Data.Runtime
		if runtime == nil {
			continue
		}
		if runtime.State == nil || runtime.IsProcessing == nil || runtime.PendingConfirmations == nil || runtime.TurnID == nil || *runtime.PendingConfirmations < 0 {
			return nil, fmt.Errorf("conversation %s runtime is incomplete", id)
		}
		switch *runtime.State {
		case "idle":
			if !*runtime.IsProcessing && *runtime.PendingConfirmations == 0 {
				continue
			}
		case "starting", "running", "cancelling", "waiting_confirmation":
		default:
			return nil, fmt.Errorf("conversation %s runtime state is unknown", id)
		}
		if strings.TrimSpace(*runtime.TurnID) == "" {
			return nil, fmt.Errorf("conversation %s is active without a turn id", id)
		}
		active = append(active, activeProjectConversation{id: id, turnID: *runtime.TurnID})
	}
	return active, nil
}

func (h *Host) stopProjectConversations(ctx context.Context, active []activeProjectConversation) error {
	for _, conversation := range active {
		if err := h.backendJSON(ctx, http.MethodPost, "/api/conversations/"+url.PathEscape(conversation.id)+"/cancel", map[string]string{"turn_id": conversation.turnID}, nil); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	ids := make([]string, 0, len(active))
	for _, conversation := range active {
		ids = append(ids, conversation.id)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining, err := h.activeProjectConversations(ctx, ids)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("project tasks did not stop within 5 seconds")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func renameProjectState(ctx context.Context, workspace, dataRoot *projectfs.Root, databaseRelative string, uid uint32, oldName, newName string, legacyRoot bool) (projectRenameResult, string, error) {
	if !projectfs.ValidProjectName(newName) || (!legacyRoot && (!projectfs.ValidProjectName(oldName) || oldName == newName)) {
		return projectRenameResult{}, "INVALID_PROJECT_NAME", errors.New("project names are invalid or unchanged")
	}
	source := workspace.Path()
	if !legacyRoot {
		source = filepath.Join(workspace.Path(), oldName)
		if err := workspace.ValidateDirectory(oldName, uid); err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
				return projectRenameResult{}, "PROJECT_NOT_FOUND", errors.New("project directory does not exist")
			}
			return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
		}
	}
	target := filepath.Join(workspace.Path(), newName)
	if err := recoverProjectRenameState(ctx, workspace, dataRoot, databaseRelative, uid); err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_RECOVERY_REQUIRED", err
	}
	targetExists, err := workspace.DirectoryExists(newName)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
	}
	if targetExists {
		return projectRenameResult{}, "PROJECT_EXISTS", errors.New("project target already exists")
	}
	database, held, err := openProjectDatabase(dataRoot, databaseRelative, uid, false)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
	}
	defer database.Close()
	defer held.Close()
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return projectRenameResult{}, projectRenameDatabaseErrorCode(err), fmt.Errorf("begin project rename transaction: %w", err)
	}
	defer tx.Rollback()
	columns, err := sqliteTableColumns(ctx, tx, "conversations")
	if err != nil || !containsString(columns, "id") || !containsString(columns, "extra") {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", errors.New("AionCore conversations schema is unsupported")
	}
	updates, err := projectConversationUpdates(ctx, tx, source, target)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
	}
	var preserved map[string]bool
	if legacyRoot {
		preserved, err = managedProjectChildren(ctx, tx, workspace.Path(), source)
		if err != nil {
			return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
		}
	}
	journal, err := newProjectRenameJournal(databaseRelative, oldName, newName, source, target, legacyRoot, updates)
	if err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", err
	}
	if err := writeProjectRenameJournal(dataRoot, journal, workspace); err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", fmt.Errorf("persist project rename journal: %w", err)
	}
	clearJournal := func() error { return dataRoot.RemoveFile(projectRenameJournalPath) }
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE conversations SET extra=? WHERE id=? AND extra=?`, update.NewJSON, update.ID, update.OldJSON)
		if err != nil {
			return projectRenameResult{}, projectRenameDatabaseErrorCode(err), errors.Join(fmt.Errorf("update project conversation %s: %w", update.ID, err), clearJournal())
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return projectRenameResult{}, "PROJECT_IN_USE", errors.Join(errors.New("project conversation changed during rename"), clearJournal())
		}
	}
	var finalize func(bool) error
	if legacyRoot {
		finalize, err = workspace.MoveEntriesToDirectory(newName, preserved)
		if err != nil {
			if exists, stateErr := workspace.DirectoryExists(newName); stateErr == nil && !exists {
				err = errors.Join(err, clearJournal())
			}
			return projectRenameResult{}, projectRenameFilesystemErrorCode(err), err
		}
	} else {
		if err := workspace.RenameDirectory(oldName, newName); err != nil {
			return projectRenameResult{}, projectRenameFilesystemErrorCode(err), errors.Join(err, clearJournal())
		}
		finalize = func(commit bool) error {
			if commit {
				return nil
			}
			return workspace.RenameDirectory(newName, oldName)
		}
	}
	rollback := func(cause error) (projectRenameResult, string, error) {
		if rollbackErr := finalize(false); rollbackErr != nil {
			cause = errors.Join(cause, fmt.Errorf("roll back project directory rename: %w", rollbackErr))
			return projectRenameResult{}, "PROJECT_RENAME_RECOVERY_REQUIRED", cause
		}
		return projectRenameResult{}, "PROJECT_RENAME_FAILED", errors.Join(cause, clearJournal())
	}
	if err := workspace.ValidateDirectory(newName, uid); err != nil {
		return rollback(fmt.Errorf("verify renamed project directory: %w", err))
	}
	if err := tx.Commit(); err != nil {
		_ = finalize(true)
		return projectRenameResult{}, "PROJECT_RENAME_RECOVERY_REQUIRED", fmt.Errorf("commit project rename; durable recovery journal retained: %w", err)
	}
	if err := finalize(true); err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_RECOVERY_REQUIRED", fmt.Errorf("finalize committed project rename: %w", err)
	}
	if err := clearJournal(); err != nil {
		return projectRenameResult{}, "PROJECT_RENAME_RECOVERY_REQUIRED", fmt.Errorf("clear committed project rename journal: %w", err)
	}
	return projectRenameResult{Name: newName, OldPath: source, NewPath: target, UpdatedConversations: len(updates)}, "", nil
}

func openProjectDatabase(root *projectfs.Root, relative string, uid uint32, readOnly bool) (*sql.DB, *os.File, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW
	mode := "rw"
	if readOnly {
		flags, mode = unix.O_RDONLY|unix.O_NOFOLLOW, "ro"
	}
	file, err := root.Open(relative, flags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open AionCore database: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stat.Uid != uid || info.Size() <= 0 || info.Size() > 8*1024*1024*1024 {
		file.Close()
		return nil, nil, errors.New("AionCore database is not a protected tenant-owned regular file")
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(root.Path(), relative)) + "?mode=" + mode + "&_txlock=immediate&_pragma=busy_timeout(3000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	database.SetMaxOpenConns(1)
	pingContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := database.PingContext(pingContext); err != nil {
		database.Close()
		file.Close()
		return nil, nil, err
	}
	pathInfo, err := os.Stat(filepath.Join(root.Path(), relative))
	if err != nil || !os.SameFile(info, pathInfo) {
		database.Close()
		file.Close()
		return nil, nil, errors.New("AionCore database path changed while it was opened")
	}
	return database, file, nil
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
			return nil, err
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return nil, fmt.Errorf("conversation %s has invalid extra JSON", id)
		}
		workspace, workspaceOK := extra["workspace"].(string)
		custom, customOK := extra["custom_workspace"].(bool)
		if !workspaceOK || !customOK || !custom || !sameProjectPath(workspace, source) {
			continue
		}
		extra["workspace"] = target
		encoded, err := json.Marshal(extra)
		if err != nil {
			return nil, err
		}
		updates = append(updates, projectConversationUpdate{ID: id, OldJSON: raw, NewJSON: string(encoded)})
	}
	return updates, rows.Err()
}

func managedProjectChildren(ctx context.Context, tx *sql.Tx, workspaceRoot, source string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,extra FROM conversations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	preserved := make(map[string]bool)
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
		if !pathOK || !customOK || !custom || sameProjectPath(path, source) {
			continue
		}
		relative, err := filepath.Rel(workspaceRoot, filepath.Clean(path))
		if err == nil && relative != "." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !strings.Contains(relative, string(filepath.Separator)) && projectfs.ValidProjectName(relative) {
			preserved[relative] = true
		}
	}
	return preserved, rows.Err()
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func sameProjectPath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func projectRenameDatabaseErrorCode(err error) string {
	value := strings.ToLower(err.Error())
	if strings.Contains(value, "database is locked") || strings.Contains(value, "database table is locked") || strings.Contains(value, "busy") {
		return "PROJECT_IN_USE"
	}
	return "PROJECT_RENAME_FAILED"
}

func projectRenameFilesystemErrorCode(err error) string {
	if errors.Is(err, unix.EEXIST) || errors.Is(err, os.ErrExist) {
		return "PROJECT_EXISTS"
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return "PROJECT_NOT_FOUND"
	}
	if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return "PROJECT_IN_USE"
	}
	return "PROJECT_RENAME_FAILED"
}
