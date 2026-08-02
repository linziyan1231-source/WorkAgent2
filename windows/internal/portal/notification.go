package portal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxNotificationResponseBytes = 64 * 1024
	maxNotificationsPerResponse  = 20
)

type portalNotification struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Message     string `json:"message"`
	PublishedAt string `json:"published_at,omitempty"`
}

func newNotificationSource(rawURL string) (*url.URL, *http.Client, error) {
	if rawURL == "" {
		return nil, nil, nil
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse notification source URL: %w", err)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return target, client, nil
}

func (s *Server) currentNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Notification request does not accept query parameters"})
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if s.notificationTarget == nil || s.notificationClient == nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"notifications": []portalNotification{}}})
		return
	}

	notifications, err := s.fetchNotifications(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "Notification source is temporarily unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"notifications": notifications}})
}

func (s *Server) fetchNotifications(ctx context.Context) ([]portalNotification, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.notificationTarget.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json, text/plain; q=0.8")
	request.Header.Set("User-Agent", "WorkAgent-Portal-Notification/1.0")
	response, err := s.notificationClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("notification source returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxNotificationResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxNotificationResponseBytes {
		return nil, errors.New("notification response exceeded size limit")
	}
	return parseNotificationPayload(body, response.Header.Get("Content-Type"))
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
		if err := rejectTrailingJSON(decoder); err != nil {
			return nil, err
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

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("notification source returned multiple JSON values")
	}
	return nil
}

func notificationsFromValue(value any) ([]portalNotification, error) {
	items, err := notificationItems(value)
	if err != nil {
		return nil, err
	}
	result := make([]portalNotification, 0, min(len(items), maxNotificationsPerResponse))
	seen := make(map[string]struct{})
	for _, item := range items {
		if len(result) == maxNotificationsPerResponse {
			break
		}
		notification, ok := notificationFromItem(item)
		if !ok {
			continue
		}
		if _, duplicate := seen[notification.ID]; duplicate {
			continue
		}
		seen[notification.ID] = struct{}{}
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
		message := firstNotificationString(typed, "message", "body", "content", "text")
		message = boundedNotificationText(message, 4000)
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
			return fmt.Sprintf("%v", value)
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
