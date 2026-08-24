package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"

	"aionuiportal/internal/instance"
)

var errCollaborationDisabled = errors.New("user collaboration is disabled")

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	if requiresOrigin(r) && !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator accounts do not have an AionUi instance"})
		return
	}
	if err := s.rewriteSharedWorkspaceRequest(r, session.User.ID, session.User.CollaborationEnabled); err != nil {
		if errors.Is(err, errCollaborationDisabled) {
			writeProjectError(w, http.StatusForbidden, "COLLABORATION_DISABLED", err.Error())
			return
		}
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_WORKSPACE", err.Error())
		return
	}
	if r.URL.Path == "/api/fs/browse" {
		root, err := s.userFilesystemRoot(session.User.WindowsSID)
		if err != nil {
			s.internalError(w, "resolve user filesystem root", err)
			return
		}
		if err := constrainFilesystemBrowse(r, root); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "File browsing is limited to your private AionUiPortal directory"})
			return
		}
	}
	webSocket := isUpgrade(r)
	finish, err := s.instances.BeginRequest(session.User.WindowsSID, webSocket)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "User instance is draining"})
		return
	}
	defer finish()
	if _, err := s.instances.Ensure(r.Context(), session.User.WindowsSID); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "User instance is unavailable"})
		return
	}
	route, err := s.instances.Route(r.Context(), session.User.WindowsSID)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, instance.ErrNotHealthy) || errors.Is(err, instance.ErrDraining) {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{"success": false, "message": "User instance is unavailable"})
		return
	}
	if err := s.instances.Touch(r.Context(), session.User.WindowsSID); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "User instance activity could not be recorded"})
		return
	}
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", route.Status.WebPort)}
	internalOrigin := fmt.Sprintf("http://127.0.0.1:%d", route.Status.AionCorePort)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = target.Host
			stripBrowserCredentials(request.Out.Header)
			request.Out.Header.Set("X-WorkAgent-Runtime-Token", route.Auth.RuntimeToken)
			request.Out.Header.Set("Cookie", route.Auth.CookieHeader)
			if route.Auth.CSRFToken != "" {
				request.Out.Header.Set("X-CSRF-Token", route.Auth.CSRFToken)
			}
			request.Out.Header.Set("Origin", internalOrigin)
			request.Out.Header.Del("Referer")
			// Shared-path sanitization needs an inspectable JSON response body.
			request.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("WWW-Authenticate")
			rewriteLoopbackLocation(response.Header, s.public, route.Status.WebPort, route.Status.AionCorePort)
			return s.sanitizeSharedPathsResponse(response, session.User.ID)
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			if !headersWritten(writer) {
				writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "User instance proxy failed"})
			}
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) rewriteSharedWorkspaceRequest(request *http.Request, userID int64, collaborationEnabled bool) error {
	if request.Method != http.MethodPost || (request.URL.Path != "/api/conversations" && request.URL.Path != "/api/conversations/clone") {
		return nil
	}
	if request.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 2*1024*1024+1))
	request.Body.Close()
	if err != nil || len(body) > 2*1024*1024 {
		return errors.New("conversation request is unavailable or oversized")
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return errors.New("conversation request must be valid JSON")
	}
	container := payload
	if request.URL.Path == "/api/conversations/clone" {
		if err := rejectNonCanonicalJSONKey(payload, "conversation"); err != nil {
			return err
		}
		conversation, ok := payload["conversation"].(map[string]any)
		if !ok {
			return replaceRequestJSONBody(request, payload)
		}
		container = conversation
	}
	if err := rejectNonCanonicalJSONKey(container, "extra"); err != nil {
		return err
	}
	extra, ok := container["extra"].(map[string]any)
	if !ok {
		return replaceRequestJSONBody(request, payload)
	}
	workspace, _ := extra["workspace"].(string)
	delete(extra, "custom_workspace")
	delete(extra, "is_project_workspace")
	if dangerousBrowserWorkspace(workspace) {
		return errors.New("workspace path syntax is not allowed at the browser boundary")
	}
	if strings.TrimSpace(workspace) != "" && !filepath.IsAbs(strings.TrimSpace(workspace)) {
		if _, stable := stableSharedProjectRoot(workspace); !stable {
			return errors.New("browser workspace paths must be absolute or use a stable shared id")
		}
	}
	if isInternalSharedWorkspace(workspace, s.cfg.UserDataRoot) {
		return errors.New("browser requests must use a stable shared workspace id")
	}
	projectID, ok := stableSharedProjectRoot(workspace)
	if !ok {
		return replaceRequestJSONBody(request, payload)
	}
	if !collaborationEnabled {
		return errCollaborationDisabled
	}
	if s.cfg.UserDataRoot == "" {
		return errors.New("shared workspaces require the stable data root")
	}
	project, err := s.store.SharedProjectForUser(request.Context(), projectID, userID, false)
	if err != nil || project.State != "active" {
		return errors.New("shared workspace is unavailable")
	}
	extra["workspace"] = filepath.Join(filepath.Clean(s.cfg.UserDataRoot), "shared", project.OwnerSID, project.ID)
	extra["custom_workspace"] = true
	extra["is_project_workspace"] = true
	return replaceRequestJSONBody(request, payload)
}

func rejectNonCanonicalJSONKey(object map[string]any, canonical string) error {
	for key := range object {
		if key != canonical && strings.EqualFold(key, canonical) {
			return fmt.Errorf("conversation request key %q must use canonical spelling %q", key, canonical)
		}
	}
	return nil
}

func replaceRequestJSONBody(request *http.Request, payload any) error {
	// payload was decoded from JSON, so it always marshals back cleanly.
	encoded, _ := json.Marshal(payload)
	request.Body = io.NopCloser(bytes.NewReader(encoded))
	request.ContentLength = int64(len(encoded))
	request.TransferEncoding = nil
	request.Header.Del("Transfer-Encoding")
	request.Header.Del("Content-Length")
	return nil
}

func dangerousBrowserWorkspace(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "shared://") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, `\\?\`) || strings.HasPrefix(lower, `\\.\`) || strings.HasPrefix(lower, "//?/") || strings.HasPrefix(lower, "//./") || strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//") {
		return true
	}
	if strings.HasPrefix(value, `\`) || strings.HasPrefix(value, "/") {
		return true
	}
	if len(value) >= 2 && value[1] == ':' && (len(value) == 2 || (value[2] != '\\' && value[2] != '/')) {
		return true
	}
	for _, segment := range strings.FieldsFunc(value, func(character rune) bool { return character == '\\' || character == '/' }) {
		for index := 0; index+1 < len(segment); index++ {
			if segment[index] != '~' || segment[index+1] < '0' || segment[index+1] > '9' {
				continue
			}
			end := index + 1
			for end < len(segment) && segment[end] >= '0' && segment[end] <= '9' {
				end++
			}
			if end == len(segment) || segment[end] == '.' {
				return true
			}
		}
	}
	return false
}

func isInternalSharedWorkspace(value, dataRoot string) bool {
	value, dataRoot = strings.TrimSpace(value), strings.TrimSpace(dataRoot)
	if value == "" || dataRoot == "" || !filepath.IsAbs(value) {
		return false
	}
	sharedRoot := filepath.Join(filepath.Clean(dataRoot), "shared")
	relative, err := filepath.Rel(sharedRoot, filepath.Clean(value))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func stableSharedProjectRoot(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "shared://") {
		return "", false
	}
	id := strings.TrimPrefix(value, "shared://")
	if len(id) != 32 || strings.ContainsAny(id, `/\\:`) {
		return "", false
	}
	for _, character := range id {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return "", false
		}
	}
	return id, true
}

func (s *Server) sanitizeSharedPathsResponse(response *http.Response, userID int64) error {
	if response.Body == nil || !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return nil
	}
	projects, err := s.store.ListSharedProjects(response.Request.Context(), userID, true)
	if err != nil {
		return fmt.Errorf("resolve authorized shared path mappings: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 32*1024*1024+1))
	response.Body.Close()
	if err != nil || len(body) > 32*1024*1024 {
		return errors.New("AionCore JSON response is unavailable or oversized")
	}
	var payload any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("AionCore returned invalid JSON")
	}
	mappings := make(map[string]string, len(projects))
	for _, project := range projects {
		if project.State == "active" || project.State == "transfer_pending" {
			absolute := filepath.Join(filepath.Clean(s.cfg.UserDataRoot), "shared", project.OwnerSID, project.ID)
			mappings[absolute] = "shared://" + project.ID
		}
	}
	payload = sanitizeSharedPathValue(payload, mappings, filepath.Join(filepath.Clean(s.cfg.UserDataRoot), "shared"))
	// payload was decoded from JSON, so it always marshals back cleanly.
	encoded, _ := json.Marshal(payload)
	response.Body = io.NopCloser(bytes.NewReader(encoded))
	response.ContentLength = int64(len(encoded))
	response.Header.Set("Content-Length", fmt.Sprint(len(encoded)))
	response.Header.Del("Content-Encoding")
	return nil
}

func sanitizeSharedPathValue(value any, mappings map[string]string, sharedRoot string) any {
	switch typed := value.(type) {
	case string:
		for absolute, stable := range mappings {
			typed = replaceFold(typed, absolute, stable)
			typed = replaceFold(typed, filepath.ToSlash(absolute), stable)
		}
		return sanitizeUnknownSharedPath(typed, sharedRoot)
	case []any:
		for index := range typed {
			typed[index] = sanitizeSharedPathValue(typed[index], mappings, sharedRoot)
		}
	case map[string]any:
		for key := range typed {
			typed[key] = sanitizeSharedPathValue(typed[key], mappings, sharedRoot)
		}
	}
	return value
}

func sanitizeUnknownSharedPath(value, sharedRoot string) string {
	for _, prefix := range []string{strings.TrimRight(sharedRoot, `\/`) + `\`, strings.TrimRight(filepath.ToSlash(sharedRoot), "/") + "/"} {
		for {
			index := strings.Index(strings.ToLower(value), strings.ToLower(prefix))
			if index < 0 {
				break
			}
			remainder := value[index+len(prefix):]
			ownerEnd := strings.IndexAny(remainder, `\/`)
			if ownerEnd <= 0 {
				value = value[:index] + "shared://redacted"
				continue
			}
			afterOwner := remainder[ownerEnd+1:]
			projectEnd := strings.IndexAny(afterOwner, `\/`)
			projectID := afterOwner
			if projectEnd >= 0 {
				projectID = afterOwner[:projectEnd]
			}
			if _, ok := stableSharedProjectRoot("shared://" + projectID); !ok {
				consumed := len(prefix) + ownerEnd
				value = value[:index] + "shared://redacted" + value[index+consumed:]
				continue
			}
			consumed := len(prefix) + ownerEnd + 1 + len(projectID)
			value = value[:index] + "shared://" + projectID + value[index+consumed:]
		}
	}
	return value
}

func replaceFold(value, old, replacement string) string {
	if old == "" {
		return value
	}
	for {
		index := strings.Index(strings.ToLower(value), strings.ToLower(old))
		if index < 0 {
			return value
		}
		value = value[:index] + replacement + value[index+len(old):]
	}
}

func constrainFilesystemBrowse(request *http.Request, root string) error {
	if request.Method != http.MethodGet {
		return errors.New("filesystem browse must use GET")
	}
	query := request.URL.Query()
	values, present := query["path"]
	if !present || len(values) != 1 {
		return errors.New("filesystem browse requires one path")
	}
	requested := strings.TrimSpace(values[0])
	if requested == "" {
		query.Set("path", filepath.Join(filepath.Clean(root), "workspace"))
		request.URL.RawQuery = query.Encode()
		return nil
	}
	requested = stripWindowsVerbatimPrefix(requested)
	if !filepath.IsAbs(requested) {
		return errors.New("filesystem browse path must be absolute")
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(requested))
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("filesystem browse path is outside the private root")
	}
	query.Set("path", filepath.Clean(requested))
	request.URL.RawQuery = query.Encode()
	return nil
}

func stripWindowsVerbatimPrefix(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	if strings.HasPrefix(path, `\\?\`) {
		return path[len(`\\?\`):]
	}
	return path
}

func requiresOrigin(r *http.Request) bool {
	if isUpgrade(r) {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.URL.Path == "/ws" || r.URL.Path == "/api/stt/stream"
}

func stripBrowserCredentials(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "x-csrf-token" || lower == "x-api-key" ||
			lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-windows-") ||
			strings.HasPrefix(lower, "x-aionui-portal-") || strings.HasPrefix(lower, "x-chatforward-") ||
			strings.HasPrefix(lower, "x-workagent-") {
			header.Del(name)
		}
	}
}

func rewriteLoopbackLocation(header http.Header, public *url.URL, ports ...int) {
	value := header.Get("Location")
	if value == "" {
		return
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() != "127.0.0.1" {
		return
	}
	allowed := false
	for _, port := range ports {
		if parsed.Port() == fmt.Sprint(port) {
			allowed = true
			break
		}
	}
	if !allowed {
		return
	}
	parsed.Scheme, parsed.Host = public.Scheme, public.Host
	header.Set("Location", parsed.String())
}

type writeTracker interface {
	Written() bool
}

func headersWritten(w http.ResponseWriter) bool {
	if tracker, ok := w.(writeTracker); ok {
		return tracker.Written()
	}
	// net/http does not expose this state. ReverseProxy only calls ErrorHandler
	// before headers for connection failures, so false is the safe default.
	return false
}
