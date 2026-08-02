package userhost

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

const (
	projectRenameJournalPath = "data/project-rename-journal.json"
	projectRenameJournalMax  = 32 * 1024 * 1024
)

type projectRenameJournal struct {
	SchemaVersion    int                         `json:"schema_version"`
	OperationID      string                      `json:"operation_id"`
	CreatedAt        time.Time                   `json:"created_at"`
	DatabaseRelative string                      `json:"database_relative"`
	OldName          string                      `json:"old_name,omitempty"`
	NewName          string                      `json:"new_name"`
	LegacyRoot       bool                        `json:"legacy_root"`
	SourcePath       string                      `json:"source_path"`
	TargetPath       string                      `json:"target_path"`
	Updates          []projectConversationUpdate `json:"updates"`
}

func newProjectRenameJournal(databaseRelative, oldName, newName, source, target string, legacy bool, updates []projectConversationUpdate) (projectRenameJournal, error) {
	journal := projectRenameJournal{
		SchemaVersion: 1, OperationID: uuid.NewString(), CreatedAt: time.Now().UTC(), DatabaseRelative: databaseRelative,
		OldName: oldName, NewName: newName, LegacyRoot: legacy, SourcePath: source, TargetPath: target, Updates: append([]projectConversationUpdate(nil), updates...),
	}
	return journal, nil
}

func (j projectRenameJournal) validate(workspace *projectfs.Root, databaseRelative string) error {
	if j.SchemaVersion != 1 || uuid.Validate(j.OperationID) != nil || j.CreatedAt.IsZero() || j.DatabaseRelative != databaseRelative || !projectfs.ValidProjectName(j.NewName) || len(j.Updates) > 10000 {
		return errors.New("project rename journal metadata is invalid")
	}
	expectedSource := workspace.Path()
	if !j.LegacyRoot {
		if !projectfs.ValidProjectName(j.OldName) || j.OldName == j.NewName {
			return errors.New("project rename journal names are invalid")
		}
		expectedSource = filepath.Join(workspace.Path(), j.OldName)
	} else if j.OldName != "" {
		return errors.New("legacy project rename journal has an old name")
	}
	expectedTarget := filepath.Join(workspace.Path(), j.NewName)
	if j.SourcePath != expectedSource || j.TargetPath != expectedTarget {
		return errors.New("project rename journal paths do not match the workspace")
	}
	seen := make(map[string]bool)
	total := 0
	for _, update := range j.Updates {
		if strings.TrimSpace(update.ID) == "" || seen[update.ID] || update.OldJSON == "" || update.NewJSON == "" {
			return errors.New("project rename journal contains an invalid update")
		}
		seen[update.ID] = true
		total += len(update.ID) + len(update.OldJSON) + len(update.NewJSON)
		if total > projectRenameJournalMax-4096 || !validJournalUpdate(update, expectedSource, expectedTarget) {
			return errors.New("project rename journal update is invalid or too large")
		}
	}
	return nil
}

func validJournalUpdate(update projectConversationUpdate, source, target string) bool {
	var oldValue, newValue map[string]any
	if json.Unmarshal([]byte(update.OldJSON), &oldValue) != nil || json.Unmarshal([]byte(update.NewJSON), &newValue) != nil || oldValue == nil || newValue == nil {
		return false
	}
	oldPath, oldOK := oldValue["workspace"].(string)
	newPath, newOK := newValue["workspace"].(string)
	oldCustom, oldCustomOK := oldValue["custom_workspace"].(bool)
	newCustom, newCustomOK := newValue["custom_workspace"].(bool)
	if !oldOK || !newOK || !oldCustomOK || !newCustomOK || !oldCustom || !newCustom || !sameProjectPath(oldPath, source) || !sameProjectPath(newPath, target) {
		return false
	}
	oldValue["workspace"] = target
	return reflect.DeepEqual(oldValue, newValue)
}

func writeProjectRenameJournal(dataRoot *projectfs.Root, journal projectRenameJournal, workspace *projectfs.Root) error {
	if err := dataRoot.EnsureDirectory("data", 0o700); err != nil {
		return err
	}
	if err := journal.validate(workspace, journal.DatabaseRelative); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if len(payload) > projectRenameJournalMax {
		return errors.New("project rename journal is too large")
	}
	return dataRoot.WriteFileAtomic(projectRenameJournalPath, append(payload, '\n'), 0o600)
}

func loadProjectRenameJournal(dataRoot *projectfs.Root, workspace *projectfs.Root, databaseRelative string, uid uint32) (projectRenameJournal, bool, error) {
	file, err := dataRoot.Open(projectRenameJournalPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return projectRenameJournal{}, false, nil
	}
	if err != nil {
		return projectRenameJournal{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return projectRenameJournal{}, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uid || info.Size() <= 0 || info.Size() > projectRenameJournalMax {
		return projectRenameJournal{}, false, errors.New("project rename journal is unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, projectRenameJournalMax+1))
	if err != nil || len(payload) > projectRenameJournalMax {
		return projectRenameJournal{}, false, errors.New("project rename journal could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal projectRenameJournal
	if err := decoder.Decode(&journal); err != nil {
		return projectRenameJournal{}, false, errors.New("project rename journal is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return projectRenameJournal{}, false, errors.New("project rename journal contains trailing data")
	}
	if err := journal.validate(workspace, databaseRelative); err != nil {
		return projectRenameJournal{}, false, err
	}
	return journal, true, nil
}

func recoverProjectRenameState(ctx context.Context, workspace, dataRoot *projectfs.Root, databaseRelative string, uid uint32) error {
	journal, found, err := loadProjectRenameJournal(dataRoot, workspace, databaseRelative, uid)
	if err != nil || !found {
		return err
	}
	allOld, allNew := true, true
	if len(journal.Updates) > 0 {
		database, held, err := openProjectDatabase(dataRoot, databaseRelative, uid, true)
		if err != nil {
			return err
		}
		defer database.Close()
		defer held.Close()
		for _, update := range journal.Updates {
			var current string
			if err := database.QueryRowContext(ctx, `SELECT extra FROM conversations WHERE id=?`, update.ID).Scan(&current); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return errors.New("project rename recovery found a missing conversation")
				}
				return err
			}
			allOld = allOld && current == update.OldJSON
			allNew = allNew && current == update.NewJSON
		}
		if !allOld && !allNew {
			return errors.New("project rename recovery found mixed database state")
		}
	}
	targetExists, err := workspace.DirectoryExists(journal.NewName)
	if err != nil {
		return err
	}
	if len(journal.Updates) == 0 {
		allNew, allOld = targetExists, !targetExists
	}
	if allNew {
		if !targetExists {
			return errors.New("project rename database committed without its target directory")
		}
		if !journal.LegacyRoot {
			sourceExists, err := workspace.DirectoryExists(journal.OldName)
			if err != nil || sourceExists {
				return errors.New("project rename committed with an ambiguous filesystem state")
			}
		}
		if err := workspace.ValidateDirectory(journal.NewName, uid); err != nil {
			return err
		}
		return dataRoot.RemoveFile(projectRenameJournalPath)
	}
	if !allOld {
		return errors.New("project rename recovery cannot classify database state")
	}
	if journal.LegacyRoot {
		if targetExists {
			if err := workspace.RollbackMovedDirectory(journal.NewName); err != nil {
				return err
			}
		}
	} else {
		sourceExists, err := workspace.DirectoryExists(journal.OldName)
		if err != nil {
			return err
		}
		switch {
		case targetExists && !sourceExists:
			if err := workspace.RenameDirectory(journal.NewName, journal.OldName); err != nil {
				return err
			}
		case sourceExists && !targetExists:
		case sourceExists && targetExists:
			return errors.New("project rename recovery found both source and target directories")
		default:
			return errors.New("project rename recovery found neither source nor target directory")
		}
	}
	return dataRoot.RemoveFile(projectRenameJournalPath)
}
