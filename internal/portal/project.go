package portal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"aionuiportal/internal/winutil"
)

const maxProjectNameRunes = 100

var reservedWindowsProjectNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {}, "COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {}, "LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Project creation does not accept query parameters")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var request struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Invalid project creation request")
		return
	}
	if !validProjectName(request.Name) {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project name is invalid")
		return
	}

	privateRoot, err := s.userFilesystemRoot(session.User.WindowsSID)
	if err != nil {
		s.internalError(w, "resolve project workspace root", err)
		return
	}
	workspaceRoot := filepath.Join(privateRoot, "workspace")
	policy := winutil.PrivateTreePolicy(session.User.WindowsSID)
	if err := winutil.VerifyACL(workspaceRoot, policy); err != nil {
		s.internalError(w, "verify project workspace ACL", err)
		return
	}

	target := filepath.Join(workspaceRoot, request.Name)
	if !strings.EqualFold(filepath.Dir(target), workspaceRoot) {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project name is invalid")
		return
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			writeProjectError(w, http.StatusConflict, "PROJECT_EXISTS", "A project with this name already exists")
			return
		}
		s.internalError(w, "create project directory", err)
		return
	}
	if err := errors.Join(winutil.ApplyACL(target, policy), winutil.VerifyACL(target, policy)); err != nil {
		rollbackErr := os.Remove(target)
		s.internalError(w, "protect project directory", errors.Join(err, rollbackErr))
		return
	}

	s.auditBestEffort(r.Context(), "portal.project.create", "success", session, r, map[string]any{"name": request.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]string{"path": target}})
}

func validProjectName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > maxProjectNameRunes || strings.HasSuffix(name, ".") {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) || strings.ContainsRune(`<>:"/\|?*`, character) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	_, reserved := reservedWindowsProjectNames[base]
	return !reserved
}

func writeProjectError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"success": false, "code": code, "error": message})
}
