package portal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"aionuiportal/internal/instance"
	"aionuiportal/internal/projectfs"
)

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listProjects(w, r)
	case http.MethodPost:
		s.createProject(w, r)
	case http.MethodPatch:
		s.renameProject(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Project list does not accept query parameters")
		return
	}
	result, err := s.instances.ListProjects(r.Context(), session.User.WindowsSID)
	if err != nil {
		writeProjectError(w, http.StatusServiceUnavailable, "PROJECT_LIST_FAILED", "Projects could not be listed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": result})
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

	result, err := s.instances.CreateProject(r.Context(), session.User.WindowsSID, request.Name)
	if err != nil {
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) {
			switch commandError.Code {
			case "INVALID_PROJECT_NAME":
				writeProjectError(w, http.StatusBadRequest, commandError.Code, "Project name is invalid")
			case "PROJECT_EXISTS":
				writeProjectError(w, http.StatusConflict, commandError.Code, "A project with this name already exists")
			default:
				writeProjectError(w, http.StatusServiceUnavailable, "PROJECT_CREATE_FAILED", "Project could not be created")
			}
			return
		}
		s.logger.Printf("project creation failed sid=%s: %v", session.User.WindowsSID, err)
		writeProjectError(w, http.StatusServiceUnavailable, "PROJECT_CREATE_FAILED", "Project could not be created")
		return
	}

	s.auditBestEffort(r.Context(), "portal.project.create", "success", session, r, map[string]any{"name": request.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": result})
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
		Path  string `json:"path"`
		Name  string `json:"name"`
		Force bool   `json:"force"`
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
	oldName, ok := projectfs.NameFromPath(workspaceRoot, request.Path)
	legacyRoot := strings.EqualFold(filepath.Clean(request.Path), filepath.Clean(workspaceRoot))
	if !ok && !legacyRoot {
		writeProjectError(w, http.StatusBadRequest, "INVALID_PROJECT_PATH", "Project path is outside the managed workspace")
		return
	}
	result, err := s.instances.RenameProject(r.Context(), session.User.WindowsSID, oldName, request.Name, request.Force, legacyRoot)
	if err != nil {
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) {
			switch commandError.Code {
			case "INVALID_PROJECT_NAME":
				writeProjectError(w, http.StatusBadRequest, commandError.Code, "Project name is invalid")
			case "PROJECT_EXISTS", "PROJECT_IN_USE":
				writeProjectError(w, http.StatusConflict, commandError.Code, "Project could not be renamed")
			case "PROJECT_FORCE_STOP_FAILED":
				writeProjectError(w, http.StatusConflict, commandError.Code, "Programs using this project could not be safely identified or stopped")
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
		"old_name": oldName, "new_name": request.Name, "force": request.Force, "legacy_root": legacyRoot, "updated_conversations": result.UpdatedConversations,
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": result})
}

func writeProjectError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"success": false, "code": code, "error": message})
}
