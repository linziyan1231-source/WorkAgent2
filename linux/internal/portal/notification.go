package portal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

const (
	maxNotificationResponseBytes = 64 * 1024
	maxNotificationsPerResponse  = 20
	notificationCacheTTL         = 15 * time.Second
	notificationMinFetchInterval = 2 * time.Second
)

type portalNotification struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Message     string `json:"message"`
	PublishedAt string `json:"published_at,omitempty"`
}

type notificationCall struct {
	done  chan struct{}
	items []portalNotification
	err   error
}

type notificationSource struct {
	target *url.URL
	token  []byte
	client *http.Client
	now    func() time.Time

	mu          sync.Mutex
	cache       []portalNotification
	cacheExpiry time.Time
	lastAttempt time.Time
	call        *notificationCall
}

func newNotificationSource(service config.OptionalService) (*notificationSource, error) {
	if !service.Enabled {
		return nil, nil
	}
	target, err := url.Parse(service.Endpoint)
	if err != nil {
		return nil, errors.New("notification endpoint is invalid")
	}
	credential, err := readProtectedCredential(service.CredentialFile)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &notificationSource{target: target, token: credential, client: &http.Client{Transport: transport, Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, now: time.Now}, nil
}

func (s *Server) currentNotifications(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Notification request does not accept query parameters"})
		return
	}
	if s.notifications == nil {
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"notifications": []portalNotification{}}})
		return
	}
	items, err := s.notifications.Fetch(request.Context())
	if err != nil {
		s.logger.Printf("Portal notification request failed stage=source_fetch_failed")
		writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "Notification source is temporarily unavailable"})
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"notifications": items}})
}

func (s *notificationSource) Fetch(ctx context.Context) ([]portalNotification, error) {
	if s == nil || s.target == nil || s.client == nil || len(s.token) == 0 {
		return nil, errors.New("notification source is unavailable")
	}
	now := s.now()
	s.mu.Lock()
	if now.Before(s.cacheExpiry) {
		items := cloneNotifications(s.cache)
		s.mu.Unlock()
		return items, nil
	}
	if s.call != nil {
		call := s.call
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			return cloneNotifications(call.items), call.err
		}
	}
	if !s.lastAttempt.IsZero() && now.Sub(s.lastAttempt) < notificationMinFetchInterval {
		s.mu.Unlock()
		return nil, errors.New("notification source request was rate limited")
	}
	call := &notificationCall{done: make(chan struct{})}
	s.call = call
	s.lastAttempt = now
	s.mu.Unlock()

	call.items, call.err = s.fetchWithRetry(ctx)
	s.mu.Lock()
	if call.err == nil {
		s.cache = cloneNotifications(call.items)
		s.cacheExpiry = s.now().Add(notificationCacheTTL)
	}
	s.call = nil
	close(call.done)
	s.mu.Unlock()
	return cloneNotifications(call.items), call.err
}

func (s *notificationSource) fetchWithRetry(ctx context.Context) ([]portalNotification, error) {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		items, retry, err := s.fetchOnce(ctx)
		if err == nil {
			return items, nil
		}
		last = err
		if !retry || attempt == 1 {
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, last
}

func (s *notificationSource) fetchOnce(ctx context.Context) ([]portalNotification, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.target.String(), nil)
	if err != nil {
		return nil, false, errors.New("create notification request")
	}
	request.Header.Set("Accept", "application/json, text/plain; q=0.8")
	request.Header.Set("Authorization", "Bearer "+string(s.token))
	request.Header.Set("User-Agent", "WorkAgent2-Portal-Notification/1.0")
	response, err := s.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, errors.New("notification source connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		retry := response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout
		return nil, retry, fmt.Errorf("notification source returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxNotificationResponseBytes+1))
	if err != nil || len(body) > maxNotificationResponseBytes {
		return nil, false, errors.New("notification response was unreadable or oversized")
	}
	items, err := parseNotificationPayload(body, response.Header.Get("Content-Type"))
	return items, false, err
}

func parseNotificationPayload(body []byte, contentType string) ([]portalNotification, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return []portalNotification{}, nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err == nil {
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, errors.New("notification source returned multiple JSON values")
		}
		return notificationsFromValue(value)
	} else if strings.Contains(strings.ToLower(contentType), "json") || trimmed[0] == '{' || trimmed[0] == '[' {
		return nil, errors.New("notification source returned malformed JSON")
	}
	message := boundedNotificationText(strings.ToValidUTF8(string(trimmed), "�"), 4000)
	if message == "" {
		return []portalNotification{}, nil
	}
	return []portalNotification{normalizeNotification("", "", message, "")}, nil
}

func notificationsFromValue(value any) ([]portalNotification, error) {
	items, err := notificationItems(value)
	if err != nil {
		return nil, err
	}
	result := make([]portalNotification, 0, min(len(items), maxNotificationsPerResponse))
	seen := make(map[string]bool)
	for _, item := range items {
		if len(result) == maxNotificationsPerResponse {
			break
		}
		notification, ok := notificationFromItem(item)
		if !ok || seen[notification.ID] {
			continue
		}
		seen[notification.ID] = true
		result = append(result, notification)
	}
	return result, nil
}

func notificationItems(value any) ([]any, error) {
	switch typed := value.(type) {
	case []any:
		return typed, nil
	case map[string]any:
		for _, key := range []string{"notifications", "items", "data"} {
			if nested, exists := typed[key]; exists {
				return notificationItems(nested)
			}
		}
		return []any{typed}, nil
	case string:
		return []any{typed}, nil
	case nil:
		return []any{}, nil
	default:
		return nil, errors.New("notification source JSON has an unsupported shape")
	}
}

func notificationFromItem(value any) (portalNotification, bool) {
	switch typed := value.(type) {
	case string:
		message := boundedNotificationText(typed, 4000)
		if message == "" {
			return portalNotification{}, false
		}
		return normalizeNotification("", "", message, ""), true
	case map[string]any:
		message := boundedNotificationText(firstNotificationString(typed, "message", "body", "content", "text"), 4000)
		if message == "" {
			return portalNotification{}, false
		}
		id := boundedNotificationText(firstNotificationScalar(typed, "id", "notification_id", "key"), 200)
		title := boundedNotificationText(firstNotificationString(typed, "title", "subject", "name"), 200)
		published := boundedNotificationText(firstNotificationScalar(typed, "published_at", "created_at", "updated_at", "timestamp", "date"), 100)
		return normalizeNotification(id, title, message, published), true
	default:
		return portalNotification{}, false
	}
}

func firstNotificationString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNotificationScalar(values map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := values[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return value
			}
		case json.Number:
			return value.String()
		case float64:
			return strconv.FormatFloat(value, 'g', -1, 64)
		}
	}
	return ""
}

func boundedNotificationText(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	runes := []rune(value)
	if len(runes) > maxRunes {
		value = string(runes[:maxRunes])
	}
	return value
}

func normalizeNotification(id, title, message, published string) portalNotification {
	if id == "" {
		hash := sha256.Sum256([]byte(title + "\x00" + message + "\x00" + published))
		id = hex.EncodeToString(hash[:12])
	}
	return portalNotification{ID: id, Title: title, Message: message, PublishedAt: published}
}

func cloneNotifications(values []portalNotification) []portalNotification {
	return append([]portalNotification(nil), values...)
}
