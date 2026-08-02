package portal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const (
	headerChatForwardUserID    = "X-ChatForward-User-ID"
	headerChatForwardTimestamp = "X-ChatForward-Timestamp"
	headerChatForwardSignature = "X-ChatForward-Signature"
)

type chatForwardBridge struct {
	target    *url.URL
	secret    []byte
	transport *http.Transport
	expected  config.ChatForwardService
}

func newChatForwardBridge(service config.ChatForwardService) (*chatForwardBridge, error) {
	if !service.Enabled {
		return nil, nil
	}
	target, err := url.Parse(service.Endpoint)
	if err != nil {
		return nil, errors.New("ChatForward endpoint is invalid")
	}
	secret, err := readProtectedCredential(service.CredentialFile)
	if err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		clear(secret)
		return nil, errors.New("ChatForward credential must contain at least 32 bytes")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConns = 16
	transport.MaxIdleConnsPerHost = 8
	transport.IdleConnTimeout = 60 * time.Second
	transport.MaxResponseHeaderBytes = 64 * 1024
	return &chatForwardBridge{target: target, secret: secret, transport: transport, expected: service}, nil
}

func (s *Server) chatForwardProxy(writer http.ResponseWriter, request *http.Request) {
	if s.chatForward == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "ChatForward is not configured"})
		return
	}
	if request.URL.Path == "/chatgpt" {
		http.Redirect(writer, request, "/chatgpt/", http.StatusPermanentRedirect)
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	target := *s.chatForward.target
	proxy := &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.SetURL(&target)
			outbound := proxyRequest.Out
			outbound.URL.Path = strings.TrimPrefix(outbound.URL.Path, "/chatgpt")
			if outbound.URL.Path == "" {
				outbound.URL.Path = "/"
			}
			outbound.URL.RawPath = ""
			outbound.Host = target.Host
			stripBrowserCredentials(outbound.Header)
			outbound.Header.Set("Origin", target.Scheme+"://"+target.Host)
			outbound.Header.Set("X-Forwarded-Proto", chatForwardPublicScheme(s.publicOrigin))
			outbound.Header.Set("X-Forwarded-Prefix", "/chatgpt")
			for name, value := range chatForwardDelegationHeaders(s.chatForward.secret, userValue.ID, outbound.Method, outbound.URL.RequestURI(), s.now()) {
				outbound.Header.Set(name, value)
			}
		},
		Transport: s.chatForward.transport,
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("WWW-Authenticate")
			return nil
		},
		ErrorHandler: func(response http.ResponseWriter, _ *http.Request, err error) {
			s.logger.Printf("ChatForward proxy failed stage=upstream_connection")
			writeJSON(response, http.StatusBadGateway, map[string]any{"success": false, "message": "ChatForward is unavailable"})
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(writer, request)
}

func stripBrowserCredentials(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "x-csrf-token" || lower == "x-api-key" || lower == "forwarded" ||
			strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-windows-") || strings.HasPrefix(lower, "x-workagent-") ||
			strings.HasPrefix(lower, "x-aionui-portal-") || strings.HasPrefix(lower, "x-chatforward-") {
			header.Del(name)
		}
	}
}

func chatForwardDelegationHeaders(secret []byte, userID int64, method, requestURI string, now time.Time) map[string]string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	user := strconv.FormatInt(userID, 10)
	canonical := strings.Join([]string{strings.ToUpper(method), requestURI, timestamp, user}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return map[string]string{
		headerChatForwardUserID: user, headerChatForwardTimestamp: timestamp,
		headerChatForwardSignature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}

func (s *Server) checkChatForward(ctx context.Context) error {
	if s.chatForward == nil || s.chatForward.target == nil || len(s.chatForward.secret) < 32 {
		return errors.New("ChatForward is unavailable")
	}
	target := *s.chatForward.target
	target.Path = "/healthz"
	target.RawPath, target.RawQuery, target.Fragment = "", "", ""
	checkContext, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(checkContext, http.MethodGet, target.String(), nil)
	if err != nil {
		return errors.New("ChatForward health request is invalid")
	}
	request.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: s.chatForward.transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("ChatForward health endpoint connection failed")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(payload) > 64*1024 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("ChatForward health endpoint returned HTTP %d or an invalid body", response.StatusCode)
	}
	var health struct {
		OK                      *bool   `json:"ok"`
		ControllerOnline        *bool   `json:"controllerOnline"`
		SourceOnline            *bool   `json:"sourceOnline"`
		MirrorCount             *int    `json:"mirrorCount"`
		ActivePairs             *int    `json:"activePairs"`
		ConnectedPairs          *int    `json:"connectedPairs"`
		MaxPairs                *int    `json:"maxPairs"`
		QuotaProtection         *bool   `json:"quotaProtection"`
		ExtensionProtocol       *string `json:"extensionProtocol"`
		QuotaChecks             *int64  `json:"quotaChecks"`
		SourceAssetProxy        *bool   `json:"sourceAssetProxy"`
		SourceAssetRequests     *int64  `json:"sourceAssetRequests"`
		SourceAssetCacheHits    *int64  `json:"sourceAssetCacheHits"`
		SourceAssetCacheEntries *int64  `json:"sourceAssetCacheEntries"`
		SourceAssetCacheBytes   *int64  `json:"sourceAssetCacheBytes"`
	}
	if err := rejectDuplicateFlatJSONObjectKeys(payload); err != nil {
		return errors.New("ChatForward health report is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&health); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("ChatForward health report is invalid")
	}
	if health.OK == nil || !*health.OK || health.ControllerOnline == nil || !*health.ControllerOnline || health.SourceOnline == nil ||
		health.MirrorCount == nil || health.ActivePairs == nil || health.ConnectedPairs == nil || health.MaxPairs == nil ||
		health.QuotaProtection == nil || health.ExtensionProtocol == nil || health.QuotaChecks == nil || health.SourceAssetProxy == nil ||
		health.SourceAssetRequests == nil || health.SourceAssetCacheHits == nil || health.SourceAssetCacheEntries == nil || health.SourceAssetCacheBytes == nil {
		return errors.New("ChatForward health report omits required release capabilities")
	}
	expected := s.chatForward.expected
	if *health.MaxPairs != expected.MaxPairs || *health.QuotaProtection != expected.QuotaProtection || *health.ExtensionProtocol != expected.ExtensionProtocol || *health.SourceAssetProxy != expected.SourceAssetProxy {
		return errors.New("ChatForward health capabilities do not match the production contract")
	}
	if *health.ActivePairs < 0 || *health.ActivePairs > *health.MaxPairs || *health.MirrorCount != *health.ActivePairs || *health.ConnectedPairs < 0 || *health.ConnectedPairs > *health.ActivePairs ||
		*health.SourceOnline != (*health.ConnectedPairs > 0) ||
		*health.QuotaChecks < 0 || *health.SourceAssetRequests < 0 || *health.SourceAssetCacheHits < 0 || *health.SourceAssetCacheHits > *health.SourceAssetRequests ||
		*health.SourceAssetCacheEntries < 0 || *health.SourceAssetCacheBytes < 0 || *health.SourceAssetCacheBytes > 128*1024*1024 {
		return errors.New("ChatForward health counters are inconsistent")
	}
	return nil
}

func rejectDuplicateFlatJSONObjectKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("JSON value is not an object")
	}
	seen := make(map[string]struct{}, 16)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return errors.New("JSON object key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("JSON object key is duplicated")
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("JSON object value is invalid")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("JSON object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON object has trailing data")
	}
	return nil
}

func chatForwardPublicScheme(publicOrigin string) string {
	parsed, err := url.Parse(publicOrigin)
	if err != nil {
		return "https"
	}
	return parsed.Scheme
}
