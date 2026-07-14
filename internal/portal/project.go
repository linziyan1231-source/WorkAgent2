package portal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"aionuiportal/internal/instance"
	"aionuiportal/internal/projectfs"
	"aionuiportal/internal/winutil"
)

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createProject(w, r)
	case http.MethodPatch:
		s.renameProject(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
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
	if !projectfs.ValidName(request.Name) {
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

	target, ok := projectfs.ResolveChild(workspaceRoot, request.Name)
	if !ok {
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

func (s *Server) renameProject(w http.ResponseWriter, r *http.Request) {
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
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Project rename does not accept query parameters")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var request struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !projectfs.ValidName(request.Name) {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project rename request is invalid")
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
	oldName, ok := projectfs.NameFromPath(workspaceRoot, request.Path)
	if !ok {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_PATH", "Project path is outside the managed workspace")
		return
	}
	source, _ := projectfs.ResolveChild(workspaceRoot, oldName)
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		writeProjectError(w, http.StatusNotFound, "PROJECT_NOT_FOUND", "Project directory does not exist")
		return
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		s.internalError(w, "inspect project directory", err)
		return
	}
	if err := winutil.VerifyACL(source, policy); err != nil {
		s.internalError(w, "verify project directory ACL", err)
		return
	}
	result, err := s.instances.RenameProject(r.Context(), session.User.WindowsSID, oldName, request.Name)
	if err != nil {
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) {
			switch commandError.Code {
			case "INVALID_PROJECT_NAME":
				writeProjectError(w, http.StatusBadRequest, commandError.Code, "Project name is invalid")
			case "PROJECT_EXISTS", "PROJECT_IN_USE":
				writeProjectError(w, http.StatusConflict, commandError.Code, "Project could not be renamed")
			case "PROJECT_NOT_FOUND":
				writeProjectError(w, http.StatusNotFound, commandError.Code, "Project directory does not exist")
			default:
				writeProjectError(w, http.StatusServiceUnavailable, "PROJECT_RENAME_FAILED", "Project could not be renamed")
			}
			return
		}
		s.logger.Printf("project rename failed sid=%s: %v", session.User.WindowsSID, err)
		writeProjectError(w, http.StatusServiceUnavailable, "PROJECT_RENAME_FAILED", "Project could not be renamed")
		return
	}
	s.auditBestEffort(r.Context(), "portal.project.rename", "success", session, r, map[string]any{
		"old_name": oldName, "new_name": request.Name, "updated_conversations": result.UpdatedConversations,
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": result})
}

func writeProjectError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"success": false, "code": code, "error": message})
}
