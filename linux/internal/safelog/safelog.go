package safelog

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	authorizationPattern = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	secretValuePattern   = regexp.MustCompile(`(?i)(authorization|api[_-]?key|token|secret|password|cookie|credential|private[_-]?key)(\s*[=:]\s*)([^\s,;]+)`)
	querySecretPattern   = regexp.MustCompile(`([?&](?:code|state|token|key|secret|password)=)[^&#\s]+`)
)

type Writer struct {
	destination io.Writer
	service     string
	mu          sync.Mutex
	now         func() time.Time
}

func NewWriter(destination io.Writer, service string) *Writer {
	if destination == nil {
		destination = io.Discard
	}
	return &Writer{destination: destination, service: service, now: func() time.Time { return time.Now().UTC() }}
}

func (w *Writer) Write(payload []byte) (int, error) {
	message := strings.TrimSpace(string(payload))
	message = Redact(message)
	encoded, err := json.Marshal(map[string]any{"timestamp": w.now().UTC().Format(time.RFC3339Nano), "service": w.service, "level": "info", "message": message})
	if err != nil {
		return 0, err
	}
	encoded = append(encoded, '\n')
	w.mu.Lock()
	_, writeErr := w.destination.Write(encoded)
	w.mu.Unlock()
	if writeErr != nil {
		return 0, writeErr
	}
	return len(payload), nil
}

func Redact(value string) string {
	value = authorizationPattern.ReplaceAllString(value, `$1 [REDACTED]`)
	value = secretValuePattern.ReplaceAllString(value, `$1$2[REDACTED]`)
	value = querySecretPattern.ReplaceAllString(value, `$1[REDACTED]`)
	return value
}
