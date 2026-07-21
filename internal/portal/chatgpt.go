package portal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"aionuiportal/internal/chatgptproxy"
	"aionuiportal/internal/config"
	"aionuiportal/internal/store"
)

const maxChatGPTConversationBody = 16 * 1024 * 1024

var chatGPTRootProxyPrefixes = []string{
	"/_next/", "/api/", "/auth/", "/backend-anon/", "/backend-api/", "/cdn-cgi/", "/cdn/", "/c/", "/ces/", "/g/", "/gpts", "/public-api/", "/share/", "/static/",
}

var chatGPTRootProxyExact = map[string]struct{}{
	"/favicon.ico": {}, "/manifest.json": {}, "/robots.txt": {}, "/sw.js": {},
}

func loadChatGPTForwarder(cfg config.Portal) (*url.URL, []byte, error) {
	if cfg.ChatGPTForwarderURL == "" {
		return nil, nil, nil
	}
	target, err := url.Parse(cfg.ChatGPTForwarderURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ChatGPT forwarder URL: %w", err)
	}
	info, err := os.Lstat(cfg.ChatGPTSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect ChatGPT forwarder secret: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("ChatGPT forwarder secret must be a regular non-symlink file")
	}
	secret, err := os.ReadFile(cfg.ChatGPTSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ChatGPT forwarder secret: %w", err)
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) < 32 {
		return nil, nil, errors.New("ChatGPT forwarder secret must contain at least 32 bytes")
	}
	return target, secret, nil
}

func (s *Server) isChatGPTForwarderRequest(r *http.Request) bool {
	if s.chatgptTarget == nil {
		return false
	}
	path := r.URL.Path
	if path == "/chatgpt" || strings.HasPrefix(path, "/chatgpt/") || strings.HasPrefix(path, "/chatgpt-external/") || path == "/chatgpt-llm-web-proxy-shim.js" {
		return true
	}
	if _, exact := chatGPTRootProxyExact[path]; !exact {
		matched := false
		for _, prefix := range chatGPTRootProxyPrefixes {
			if strings.HasPrefix(path, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	referer, err := url.Parse(r.Referer())
	if err != nil {
		return false
	}
	_, allowedOrigin := s.origins[browserOriginKey(referer)]
	return allowedOrigin && (referer.Path == "/chatgpt" || strings.HasPrefix(referer.Path, "/chatgpt/"))
}

func (s *Server) chatGPTProxy(w http.ResponseWriter, r *http.Request) {
	if s.chatgptTarget == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "ChatGPT Web is not configured"})
		return
	}
	if requiresOrigin(r) && !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if s.cfg.ChatGPTMaintenanceMode {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false,
			"code":    "CHATGPT_UPGRADING",
			"message": "聊天模式正在升级中",
		})
		return
	}

	var send chatgptproxy.Send
	reserved := false
	if isChatGPTConversationSendPath(r.URL.Path) && r.Method == http.MethodPost {
		body, readErr := readBoundedBody(r.Body, maxChatGPTConversationBody)
		if readErr != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "ChatGPT conversation request is too large"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		var pro bool
		send, pro, err = chatgptproxy.ParseConversationSend(body, strconv.FormatInt(session.User.ID, 10), s.cfg.ChatGPTProModels)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid ChatGPT Pro request"})
			return
		}
		if pro {
			reservation, reserveErr := s.store.ReserveChatGPTPro(r.Context(), session.User.ID, send.LogicalID, send.Model, send.ThinkingEffort, s.now())
			if reserveErr != nil {
				s.internalError(w, "reserve ChatGPT Pro quota", reserveErr)
				return
			}
			switch reservation.State {
			case store.ChatGPTProQuotaExceeded:
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "error": "chatgpt_pro_quota_exceeded", "message": "ChatGPT Pro weekly quota is exhausted", "used": reservation.Quota.Confirmed + reservation.Quota.Pending, "limit": reservation.Quota.Limit, "reset_at": reservation.Quota.ResetAt.Format(time.RFC3339)})
				return
			case store.ChatGPTProDuplicatePending:
				writeJSON(w, http.StatusConflict, map[string]any{"success": false, "error": "chatgpt_pro_send_pending", "message": "This ChatGPT Pro send is already pending review"})
				return
			case store.ChatGPTProDuplicateComplete:
				writeJSON(w, http.StatusConflict, map[string]any{"success": false, "error": "chatgpt_pro_send_already_processed", "message": "This ChatGPT Pro send was already processed"})
				return
			case store.ChatGPTProReserved:
				reserved = true
			}
		}
	}

	target := *s.chatgptTarget
	if isChatGPTSharedStaticAssetPath(r.URL.Path) {
		// The global Portal middleware defaults to no-store. Static ChatGPT assets
		// are immutable content-hashed files and must keep the forwarder's public
		// cache policy so cold clients do not repeatedly miss the SVG sprite.
		w.Header().Del("Cache-Control")
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			originalHost := request.In.Host
			request.SetURL(&target)
			request.Out.Host = originalHost
			stripChatGPTBrowserCredentials(request.Out.Header)
			request.Out.Header.Set("Accept-Encoding", "identity")
			request.Out.Header.Set("X-Forwarded-Proto", s.public.Scheme)
			for name, value := range chatgptproxy.DelegationHeaders(s.chatgptSecret, session.User.Username, request.Out.Method, request.Out.URL.RequestURI(), s.now()) {
				request.Out.Header.Set(name, value)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("WWW-Authenticate")
			if reserved {
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					s.settleChatGPTPro(session.User.ID, send, store.ProStatusUpstreamRejected, response.StatusCode, false, nil)
				} else if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
					response.Body = newChatGPTTrackedBody(response.Body, response.StatusCode, send, s.cfg.ChatGPTProModels, func(status string, completed bool, models []string) {
						s.settleChatGPTPro(session.User.ID, send, status, response.StatusCode, completed, models)
					})
				} else {
					s.settleChatGPTPro(session.User.ID, send, store.ProStatusUnknown, response.StatusCode, false, nil)
				}
			}
			if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
				return injectChatGPTBridge(response)
			}
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
			if reserved {
				s.settleChatGPTPro(session.User.ID, send, store.ProStatusUpstreamRejected, 0, false, nil)
			}
			if !headersWritten(writer) {
				writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "ChatGPT Web forwarder is unavailable"})
			}
			s.logger.Printf("ChatGPT Web forwarder failed: %v", proxyErr)
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
}

func isChatGPTSharedStaticAssetPath(requestPath string) bool {
	requestPath = strings.TrimPrefix(requestPath, "/chatgpt")
	const prefix = "/cdn/assets/"
	if !strings.HasPrefix(requestPath, prefix) {
		return false
	}
	name := strings.TrimPrefix(requestPath, prefix)
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	lower := strings.ToLower(name)
	for _, suffix := range []string{".avif", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".png", ".svg", ".webp", ".woff", ".woff2"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func stripChatGPTBrowserCredentials(header http.Header) {
	preserved := map[string][]string{
		"Authorization": header.Values("Authorization"),
		"X-CSRF-Token":  header.Values("X-CSRF-Token"),
		"X-API-Key":     header.Values("X-API-Key"),
	}
	stripBrowserCredentials(header)
	for name, values := range preserved {
		for _, value := range values {
			header.Add(name, value)
		}
	}
}

func (s *Server) settleChatGPTPro(userID int64, send chatgptproxy.Send, status string, upstreamStatus int, completed bool, models []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.SettleChatGPTPro(ctx, userID, send.LogicalID, status, upstreamStatus, completed, models, s.now()); err != nil {
		s.logger.Printf("ChatGPT Pro settlement failed status=%s: %v", status, err)
	}
}

func isChatGPTConversationSendPath(path string) bool {
	return path == "/chatgpt/backend-api/f/conversation" || path == "/backend-api/f/conversation"
}

func readBoundedBody(body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()
	content, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("body limit exceeded")
	}
	return content, nil
}

type chatGPTTrackedBody struct {
	body      io.ReadCloser
	inspector *chatgptproxy.SSEInspector
	models    []string
	once      sync.Once
	settle    func(string, bool, []string)
	send      chatgptproxy.Send
}

func newChatGPTTrackedBody(body io.ReadCloser, _ int, send chatgptproxy.Send, models []string, settle func(string, bool, []string)) io.ReadCloser {
	return &chatGPTTrackedBody{body: body, inspector: chatgptproxy.NewSSEInspector(), models: models, settle: settle, send: send}
}

func (b *chatGPTTrackedBody) Read(buffer []byte) (int, error) {
	count, err := b.body.Read(buffer)
	if count > 0 {
		b.inspector.Write(buffer[:count])
	}
	if errors.Is(err, io.EOF) {
		b.finish(false)
	}
	return count, err
}

func (b *chatGPTTrackedBody) Close() error {
	b.finish(true)
	return b.body.Close()
}

func (b *chatGPTTrackedBody) finish(closedEarly bool) {
	b.once.Do(func() {
		outcome, summary := b.inspector.Outcome(b.send.Model, b.models)
		if closedEarly && !summary.Completed {
			outcome = chatgptproxy.OutcomeUnknown
		}
		status := map[string]string{
			chatgptproxy.OutcomeConfirmedPro:      store.ProStatusConfirmed,
			chatgptproxy.OutcomeConfirmedFallback: store.ProStatusFallback,
			chatgptproxy.OutcomeUnknown:           store.ProStatusUnknown,
		}[outcome]
		b.settle(status, summary.Completed, summary.ServedModels)
	})
}

func injectChatGPTBridge(response *http.Response) error {
	content, err := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024+1))
	response.Body.Close()
	if err != nil || len(content) > 16*1024*1024 {
		return errors.New("ChatGPT Web HTML response was invalid")
	}
	const tag = `<script src="/portal-chatgpt-bridge.js"></script>`
	if !bytes.Contains(content, []byte(tag)) {
		lower := bytes.ToLower(content)
		position := bytes.LastIndex(lower, []byte("</body>"))
		if position < 0 {
			position = len(content)
		}
		updated := make([]byte, 0, len(content)+len(tag)+1)
		updated = append(updated, content[:position]...)
		updated = append(updated, []byte(tag)...)
		updated = append(updated, content[position:]...)
		content = updated
	}
	response.Body = io.NopCloser(bytes.NewReader(content))
	response.ContentLength = int64(len(content))
	response.Header.Set("Content-Length", strconv.Itoa(len(content)))
	return nil
}
