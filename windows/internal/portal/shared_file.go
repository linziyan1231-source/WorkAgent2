package portal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/store"
)

func (s *Server) sharedFiles(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 9*1024*1024)
	var request struct {
		ProjectID string `json:"project_id"`
		Operation string `json:"operation"`
		Path      string `json:"path,omitempty"`
		Data      string `json:"data,omitempty"`
		NewName   string `json:"new_name,omitempty"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(request.ProjectID) != 32 || len(request.Path) > 4096 || len(request.NewName) > 255 || len(request.Data) > 8*1024*1024 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_FILE", "Shared file request is invalid")
		return
	}
	allowed := map[string]bool{"dir": true, "list": true, "metadata": true, "read": true, "read-buffer": true, "image-base64": true, "write": true, "remove": true, "rename": true}
	request.Operation = strings.TrimSpace(request.Operation)
	if !allowed[request.Operation] {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_FILE", "Shared file operation is unsupported")
		return
	}
	project, err := s.store.SharedProjectForUser(r.Context(), request.ProjectID, session.User.ID, false)
	if err != nil {
		status := http.StatusNotFound
		if errors.Is(err, store.ErrForbidden) {
			status = http.StatusForbidden
		}
		writeProjectError(w, status, "SHARED_PROJECT_NOT_FOUND", "Shared project was not found")
		return
	}
	if project.State != "active" {
		writeProjectError(w, http.StatusConflict, "SHARED_PROJECT_BUSY", "Shared project files are temporarily unavailable during a transaction")
		return
	}
	result, err := s.instances.SharedFile(r.Context(), session.User.WindowsSID, ipc.SharedFileRequest{
		OwnerSID: project.OwnerSID, ProjectID: project.ID, Operation: request.Operation,
		Path: request.Path, Data: request.Data, NewName: request.NewName,
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) && strings.HasPrefix(commandError.Code, "INVALID_SHARED_FILE") {
			status = http.StatusBadRequest
		}
		writeProjectError(w, status, "SHARED_FILE_FAILED", "Shared file operation failed")
		return
	}
	if request.Operation == "write" || request.Operation == "remove" || request.Operation == "rename" {
		s.auditBestEffort(r.Context(), "portal.shared_file."+request.Operation, "success", session, r, map[string]any{"project_id": project.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": result.Data})
}
