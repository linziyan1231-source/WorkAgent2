package portal

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"

	"aionuiportal/internal/instance"
)

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
			request.Out.Header.Set("Cookie", route.Auth.CookieHeader)
			if route.Auth.CSRFToken != "" {
				request.Out.Header.Set("X-CSRF-Token", route.Auth.CSRFToken)
			}
			request.Out.Header.Set("Origin", internalOrigin)
			request.Out.Header.Del("Referer")
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("WWW-Authenticate")
			rewriteLoopbackLocation(response.Header, s.public, route.Status.WebPort, route.Status.AionCorePort)
			return nil
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
			strings.HasPrefix(lower, "x-aionui-portal-") {
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
