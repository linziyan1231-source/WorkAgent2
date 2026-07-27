package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/ipc"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const maxRuntimeControlResponse = 1024 * 1024

type runtimeControlError struct {
	Status int
	Code   string
}

func (e runtimeControlError) Error() string {
	return fmt.Sprintf("UserHost control returned HTTP %d", e.Status)
}

type runtimeModelStatus struct {
	Applied bool                 `json:"applied"`
	Pending bool                 `json:"pending"`
	State   modelbootstrap.State `json:"state"`
}

func (s *Server) ensureRuntimeOnce(ctx context.Context, userValue store.User) error {
	s.ensures.mu.Lock()
	if existing := s.ensures.calls[userValue.TenantID]; existing != nil {
		s.ensures.mu.Unlock()
		select {
		case <-existing.done:
			return existing.err
		case <-ctx.Done():
			return errors.New("tenant runtime preparation was cancelled")
		}
	}
	call := &runtimeEnsureCall{done: make(chan struct{})}
	s.ensures.calls[userValue.TenantID] = call
	s.ensures.mu.Unlock()

	call.err = s.ensureUserRuntime(ctx, userValue)
	close(call.done)
	s.ensures.mu.Lock()
	delete(s.ensures.calls, userValue.TenantID)
	s.ensures.mu.Unlock()
	return call.err
}

func (s *Server) ensureUserRuntime(ctx context.Context, userValue store.User) error {
	current, err := s.store.UserByID(ctx, userValue.ID)
	if err != nil || !current.Enabled || current.AuthVersion != userValue.AuthVersion {
		return errors.New("tenant account is no longer enabled")
	}
	tenant, runtimeUID, err := s.loadRuntime(userValue)
	if err != nil {
		return err
	}
	if !tenant.Backend.RequireModelBootstrap {
		return s.waitForRuntimeReady(ctx, tenant, runtimeUID)
	}
	desired, err := modelbootstrap.StateFromPolicy(s.policy, s.cfg.CLIProxy.APIBaseURL, userValue.TenantID)
	if err != nil {
		return fmt.Errorf("derive tenant model policy: %w", err)
	}
	var status runtimeModelStatus
	if err := s.runtimeControlJSON(ctx, tenant, runtimeUID, http.MethodGet, "/internal/model-bootstrap", nil, &status); err != nil {
		return fmt.Errorf("read tenant model state: %w", err)
	}
	if (status.Applied || status.Pending) && status.State.Equal(desired) {
		return s.waitForRuntimeReady(ctx, tenant, runtimeUID)
	}
	bundle, err := (cliproxy.Provisioner{Config: s.cfg.CLIProxy}).Provision(ctx, userValue.TenantID, userValue.Username, s.policy)
	if err != nil {
		return fmt.Errorf("provision tenant model policy: %w", err)
	}
	defer bundle.Zero()
	if err := s.runtimeControlJSON(ctx, tenant, runtimeUID, http.MethodPost, "/internal/model-bootstrap", bundle, &status); err != nil {
		return fmt.Errorf("apply tenant model policy: %w", err)
	}
	if !status.Applied || !status.State.Equal(desired) {
		return errors.New("UserHost did not confirm the requested model policy")
	}
	return s.waitForRuntimeReady(ctx, tenant, runtimeUID)
}

func (s *Server) waitForRuntimeReady(ctx context.Context, tenant config.Tenant, runtimeUID uint32) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := s.runtimeControlJSON(ctx, tenant, runtimeUID, http.MethodGet, "/readyz", nil, nil)
		if err == nil {
			return nil
		}
		var controlErr runtimeControlError
		if errors.As(err, &controlErr) && controlErr.Status != http.StatusServiceUnavailable {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("tenant runtime readiness deadline expired")
		case <-ticker.C:
		}
	}
}

func (s *Server) runtimeControlJSON(ctx context.Context, tenant config.Tenant, runtimeUID uint32, method, requestPath string, source, destination any) error {
	var payload []byte
	var body io.Reader
	if source != nil {
		var err error
		payload, err = json.Marshal(source)
		if err != nil {
			return err
		}
		defer clear(payload)
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://userhost"+requestPath, body)
	if err != nil {
		return err
	}
	request.Header.Set("X-WorkAgent-Tenant", tenant.TenantID)
	request.Header.Set("X-WorkAgent-Control", "portal-v1")
	if source != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ipc.DialContext(ctx, tenant.SocketPath, ipc.DialOptions{ExpectedRuntimeUID: runtimeUID, ExpectedSocketUID: tenant.PortalUID, SystemdActivation: tenant.SocketActivation})
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 3 * time.Minute,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("UserHost control connection failed")
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(io.LimitReader(response.Body, maxRuntimeControlResponse+1))
	if err != nil || len(responsePayload) > maxRuntimeControlResponse {
		clear(responsePayload)
		return errors.New("UserHost control response exceeded its limit")
	}
	defer clear(responsePayload)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(responsePayload, &failure)
		return runtimeControlError{Status: response.StatusCode, Code: failure.Code}
	}
	if destination == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(responsePayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("UserHost control response was invalid")
	}
	return nil
}

func (s *Server) runtimeStatus(writer http.ResponseWriter, request *http.Request) {
	userValue := request.Context().Value(userContextKey).(store.User)
	var status map[string]any
	if err := s.callRuntimeControl(request.Context(), userValue, http.MethodGet, "/internal/status", nil, &status); err != nil {
		s.writeRuntimeControlError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) listProjects(writer http.ResponseWriter, request *http.Request) {
	userValue := request.Context().Value(userContextKey).(store.User)
	var result struct {
		Projects []string `json:"projects"`
	}
	if err := s.callRuntimeControl(request.Context(), userValue, http.MethodGet, "/internal/projects", nil, &result); err != nil {
		s.writeRuntimeControlError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) createProject(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Invalid project creation request")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(request, &body, 4*1024); err != nil || !projectfs.ValidProjectName(body.Name) {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project name is invalid")
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	var result map[string]any
	if err := s.callRuntimeControl(request.Context(), userValue, http.MethodPost, "/internal/projects", body, &result); err != nil {
		s.writeCreateProjectError(writer, err)
		return
	}
	if err := s.auditRuntimeMutation(request, userValue, "portal.project.create", map[string]any{"name": body.Name}); err != nil {
		s.internalError(writer, "audit project creation", err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"success": true, "data": result})
}

func (s *Server) renameProject(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Project rename does not accept query parameters")
		return
	}
	var body struct {
		OldName string `json:"old_name"`
		NewName string `json:"new_name"`
	}
	if err := decodeJSON(request, &body, 4*1024); err != nil || !projectfs.ValidProjectName(body.OldName) || !projectfs.ValidProjectName(body.NewName) || body.OldName == body.NewName {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project rename request is invalid")
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	var result map[string]any
	if err := s.callRuntimeControl(request.Context(), userValue, http.MethodPost, "/internal/projects/rename", body, &result); err != nil {
		s.writeRenameProjectError(writer, err)
		return
	}
	if err := s.auditRuntimeMutation(request, userValue, "portal.project.rename", map[string]any{"old_name": body.OldName, "new_name": body.NewName}); err != nil {
		s.internalError(writer, "audit project rename", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": result})
}

func (s *Server) renameProjectCompatibility(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_REQUEST", "Project rename does not accept query parameters")
		return
	}
	var body struct {
		Path  string `json:"path"`
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := decodeJSON(request, &body, 4*1024); err != nil || !projectfs.ValidProjectName(body.Name) {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project rename request is invalid")
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	workspace := filepath.Join(userValue.DataRoot, "workspace")
	clean := filepath.Clean(body.Path)
	legacyRoot := clean == workspace
	if !filepath.IsAbs(clean) || (!legacyRoot && filepath.Dir(clean) != workspace) {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_PATH", "Project path is outside the managed workspace")
		return
	}
	oldName := ""
	if !legacyRoot {
		oldName = filepath.Base(clean)
	}
	if (!legacyRoot && !projectfs.ValidProjectName(oldName)) || oldName == body.Name {
		writeProjectError(writer, http.StatusBadRequest, "INVALID_PROJECT_NAME", "Project rename request is invalid")
		return
	}
	var result map[string]any
	command := map[string]any{"old_name": oldName, "new_name": body.Name, "force": body.Force, "legacy_root": legacyRoot}
	if err := s.callRuntimeControl(request.Context(), userValue, http.MethodPost, "/internal/projects/rename", command, &result); err != nil {
		s.writeRenameProjectError(writer, err)
		return
	}
	if err := s.auditRuntimeMutation(request, userValue, "portal.project.rename", map[string]any{"old_name": oldName, "new_name": body.Name, "force": body.Force, "legacy_root": legacyRoot}); err != nil {
		s.internalError(writer, "audit project rename", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": result})
}

func writeProjectError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"success": false, "code": code, "error": message})
}

func (s *Server) writeCreateProjectError(writer http.ResponseWriter, err error) {
	var controlErr runtimeControlError
	if errors.As(err, &controlErr) {
		switch controlErr.Code {
		case "INVALID_PROJECT_NAME":
			writeProjectError(writer, http.StatusBadRequest, controlErr.Code, "Project name is invalid")
			return
		case "PROJECT_EXISTS":
			writeProjectError(writer, http.StatusConflict, controlErr.Code, "A project with this name already exists")
			return
		}
	}
	s.logger.Printf("project creation failed: %v", err)
	writeProjectError(writer, http.StatusServiceUnavailable, "PROJECT_CREATE_FAILED", "Project could not be created")
}

func (s *Server) writeRenameProjectError(writer http.ResponseWriter, err error) {
	var controlErr runtimeControlError
	if errors.As(err, &controlErr) {
		switch controlErr.Code {
		case "INVALID_PROJECT_NAME":
			writeProjectError(writer, http.StatusBadRequest, controlErr.Code, "Project name is invalid")
			return
		case "PROJECT_EXISTS", "PROJECT_IN_USE":
			writeProjectError(writer, http.StatusConflict, controlErr.Code, "Project could not be renamed")
			return
		case "PROJECT_FORCE_STOP_FAILED":
			writeProjectError(writer, http.StatusConflict, controlErr.Code, "Programs using this project could not be safely identified or stopped")
			return
		case "PROJECT_NOT_FOUND":
			writeProjectError(writer, http.StatusNotFound, controlErr.Code, "Project directory does not exist")
			return
		}
	}
	s.logger.Printf("project rename failed: %v", err)
	writeProjectError(writer, http.StatusServiceUnavailable, "PROJECT_RENAME_FAILED", "Project could not be renamed")
}

func (s *Server) callRuntimeControl(ctx context.Context, userValue store.User, method, requestPath string, source, destination any) error {
	tenant, runtimeUID, err := s.loadRuntime(userValue)
	if err != nil {
		return err
	}
	return s.runtimeControlJSON(ctx, tenant, runtimeUID, method, requestPath, source, destination)
}

func (s *Server) auditRuntimeMutation(request *http.Request, userValue store.User, action string, details map[string]any) error {
	remoteIP, _ := request.Context().Value(remoteIPContextKey).(string)
	return s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: s.now(), Action: action, Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP, Details: details})
}

func (s *Server) writeRuntimeControlError(writer http.ResponseWriter, err error) {
	var controlErr runtimeControlError
	if errors.As(err, &controlErr) {
		switch controlErr.Status {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
			code := controlErr.Code
			switch code {
			case "INVALID_PROJECT_NAME", "PROJECT_NOT_FOUND", "PROJECT_EXISTS", "PROJECT_IN_USE", "PROJECT_FORCE_STOP_FAILED":
			default:
				code = "PROJECT_OPERATION_REJECTED"
			}
			writeJSON(writer, controlErr.Status, map[string]any{"success": false, "code": code})
			return
		}
	}
	s.logger.Printf("tenant control request failed: %v", err)
	writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "RUNTIME_UNAVAILABLE"})
}
