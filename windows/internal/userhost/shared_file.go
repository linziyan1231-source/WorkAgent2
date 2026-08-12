package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"aionuiportal/internal/ipc"
	"golang.org/x/sys/windows"
)

const maxSharedFileData = 8 * 1024 * 1024

func (h *Host) sharedFile(ctx context.Context, request ipc.SharedFileRequest) (ipc.SharedFileResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) {
		return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared file request is invalid")
	}
	owner, err := windows.StringToSid(strings.TrimSpace(request.OwnerSID))
	if err != nil || owner == nil || !owner.IsValid() || !strings.EqualFold(owner.String(), request.OwnerSID) {
		return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared file owner is invalid")
	}
	root := filepath.Join(filepath.Clean(h.cfg.DataRootBase), "shared", owner.String(), request.ProjectID)
	if err := requireNormalDirectory(root); err != nil {
		return ipc.SharedFileResult{}, "SHARED_PROJECT_NOT_FOUND", err
	}
	relative, err := normalizeSharedRelativePath(request.ProjectID, request.Path)
	if err != nil {
		return ipc.SharedFileResult{}, "INVALID_SHARED_FILE_PATH", err
	}
	target := root
	if relative != "" {
		target = filepath.Join(root, filepath.FromSlash(relative))
	}
	operation := strings.TrimSpace(request.Operation)
	allowMissingFinal := operation == "write"
	if operation != "list" {
		if err := validateSharedPathNoReparse(root, relative, allowMissingFinal); err != nil {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE_PATH", err
		}
	}
	var endpoint string
	var payload map[string]any
	switch operation {
	case "dir":
		endpoint, payload = "/api/fs/dir", map[string]any{"dir": target, "root": root}
	case "list":
		if request.Path != "" || request.Data != "" || request.NewName != "" {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared file list fields are invalid")
		}
		if err := rejectSharedTreeReparse(root); err != nil {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE_PATH", err
		}
		endpoint, payload = "/api/fs/list", map[string]any{"root": root}
	case "metadata", "read", "read-buffer", "image-base64":
		endpoint, payload = "/api/fs/"+operation, map[string]any{"path": target, "workspace": root}
	case "write":
		if relative == "" || len(request.Data) > maxSharedFileData {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared file write is invalid or oversized")
		}
		endpoint, payload = "/api/fs/write", map[string]any{"path": target, "data": request.Data, "workspace": root}
	case "remove":
		if relative == "" {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared project root cannot be removed")
		}
		endpoint, payload = "/api/fs/remove", map[string]any{"path": target, "workspace": root}
	case "rename":
		if relative == "" || !validSharedFileName(request.NewName) {
			return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("shared file rename is invalid")
		}
		endpoint, payload = "/api/fs/rename", map[string]any{"path": target, "new_name": request.NewName, "workspace": root}
	default:
		return ipc.SharedFileResult{}, "INVALID_SHARED_FILE", errors.New("unsupported shared file operation")
	}
	raw, err := h.client.sendJSONData(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return ipc.SharedFileResult{}, "SHARED_FILE_OPERATION_FAILED", err
	}
	if operation == "dir" {
		raw, err = filterSharedDirReparseEntries(raw, target)
		if err != nil {
			return ipc.SharedFileResult{}, "SHARED_FILE_RESPONSE_INVALID", err
		}
	}
	sanitized, err := sanitizeSharedFileJSON(raw, root, "shared://"+request.ProjectID)
	if err != nil {
		return ipc.SharedFileResult{}, "SHARED_FILE_RESPONSE_INVALID", err
	}
	return ipc.SharedFileResult{Data: sanitized}, "", nil
}

func filterSharedDirReparseEntries(raw json.RawMessage, target string) (json.RawMessage, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	kept := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		var metadata struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(entry, &metadata); err != nil || !validSharedFileName(metadata.Name) {
			return nil, errors.New("shared directory response contains an invalid name")
		}
		info, err := os.Lstat(filepath.Join(target, metadata.Name))
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || windowsReparse(info) {
			continue
		}
		kept = append(kept, entry)
	}
	return json.Marshal(kept)
}

func normalizeSharedRelativePath(projectID, value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	prefix := "shared://" + projectID
	if strings.HasPrefix(value, "shared://") {
		if value != prefix && !strings.HasPrefix(value, prefix+"/") {
			return "", errors.New("shared path project does not match authorization")
		}
		value = strings.TrimPrefix(value, prefix)
	}
	value = strings.TrimPrefix(value, "/")
	if value == "" || value == "." {
		return "", nil
	}
	clean := path.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(clean, ":") {
		return "", errors.New("shared path escapes the project")
	}
	for _, segment := range strings.Split(clean, "/") {
		if strings.IndexFunc(segment, unicode.IsControl) >= 0 {
			return "", errors.New("shared path contains an invalid segment")
		}
	}
	return clean, nil
}

func validateSharedPathNoReparse(root, relative string, allowMissingFinal bool) error {
	if err := requireNormalDirectory(root); err != nil {
		return err
	}
	if relative == "" {
		return nil
	}
	current := root
	segments := strings.Split(relative, "/")
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissingFinal && index == len(segments)-1 && errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || windowsReparse(info) {
			return fmt.Errorf("reparse points are forbidden in shared file paths: %s", current)
		}
		if index < len(segments)-1 && !info.IsDir() {
			return errors.New("shared file path traverses a non-directory")
		}
	}
	return nil
}

func rejectSharedTreeReparse(root string) error {
	return filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("reparse points are forbidden in shared projects: %s", name)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if windowsReparse(info) {
			return fmt.Errorf("reparse points are forbidden in shared projects: %s", name)
		}
		return nil
	})
}

func validSharedFileName(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "." && value != ".." && len(value) <= 255 &&
		!strings.ContainsAny(value, `<>:"/\|?*`) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func sanitizeSharedFileJSON(raw json.RawMessage, root, stableRoot string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	sanitized, err := sanitizeSharedFileValue(value, filepath.Clean(root), stableRoot)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sanitized)
}

func sanitizeSharedFileValue(value any, root, stableRoot string) (any, error) {
	switch typed := value.(type) {
	case string:
		if !filepath.IsAbs(typed) {
			return typed, nil
		}
		relative, err := filepath.Rel(root, filepath.Clean(strings.TrimPrefix(typed, `\\?\`)))
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return nil, errors.New("AionCore shared file response exposed a path outside the authorized project")
		}
		if relative == "." {
			return stableRoot, nil
		}
		return stableRoot + "/" + filepath.ToSlash(relative), nil
	case []any:
		result := make([]any, len(typed))
		for index, entry := range typed {
			item, err := sanitizeSharedFileValue(entry, root, stableRoot)
			if err != nil {
				return nil, err
			}
			result[index] = item
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, entry := range typed {
			item, err := sanitizeSharedFileValue(entry, root, stableRoot)
			if err != nil {
				return nil, err
			}
			result[key] = item
		}
		return result, nil
	default:
		return value, nil
	}
}
