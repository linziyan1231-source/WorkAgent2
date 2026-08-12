package portal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/config"
)

const (
	headerChatForwardUserID    = "X-ChatForward-User-ID"
	headerChatForwardTimestamp = "X-ChatForward-Timestamp"
	headerChatForwardSignature = "X-ChatForward-Signature"
)

func loadChatForward(cfg config.Portal) (*url.URL, []byte, error) {
	if cfg.ChatForwardURL == "" {
		return nil, nil, nil
	}
	target, err := url.Parse(cfg.ChatForwardURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ChatForward URL: %w", err)
	}
	info, err := os.Lstat(cfg.ChatForwardSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect ChatForward secret: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("ChatForward secret must be a regular non-symlink file")
	}
	secret, err := os.ReadFile(cfg.ChatForwardSecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ChatForward secret: %w", err)
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) < 32 {
		return nil, nil, errors.New("ChatForward secret must contain at least 32 bytes")
	}
	return target, secret, nil
}

func (s *Server) isChatForwardRequest(r *http.Request) bool {
	return s.chatForwardTarget != nil && (r.URL.Path == "/chatgpt" || strings.HasPrefix(r.URL.Path, "/chatgpt/"))
}

func (s *Server) chatForwardProxy(w http.ResponseWriter, r *http.Request) {
	if requiresOrigin(r) && !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if r.URL.Path == "/chatgpt" {
		http.Redirect(w, r, "/chatgpt/", http.StatusPermanentRedirect)
		return
	}

	target := *s.chatForwardTarget
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(&target)
			request.Out.URL.Path = strings.TrimPrefix(request.Out.URL.Path, "/chatgpt")
			if request.Out.URL.Path == "" {
				request.Out.URL.Path = "/"
			}
			request.Out.URL.RawPath = ""
			request.Out.Host = target.Host
			stripBrowserCredentials(request.Out.Header)
			request.Out.Header.Set("Origin", target.Scheme+"://"+target.Host)
			request.Out.Header.Set("X-Forwarded-Proto", s.public.Scheme)
			request.Out.Header.Set("X-Forwarded-Prefix", "/chatgpt")
			for name, value := range chatForwardDelegationHeaders(s.chatForwardSecret, session.User.ID, request.Out.Method, request.Out.URL.RequestURI(), s.now()) {
				request.Out.Header.Set(name, value)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("WWW-Authenticate")
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
			if !headersWritten(writer) {
				writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "ChatForward is unavailable"})
			}
			s.logger.Printf("ChatForward proxy failed: %v", proxyErr)
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
}

func chatForwardDelegationHeaders(secret []byte, userID int64, method, requestURI string, now time.Time) map[string]string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	user := strconv.FormatInt(userID, 10)
	canonical := strings.Join([]string{strings.ToUpper(method), requestURI, timestamp, user}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return map[string]string{
		headerChatForwardUserID:    user,
		headerChatForwardTimestamp: timestamp,
		headerChatForwardSignature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}
