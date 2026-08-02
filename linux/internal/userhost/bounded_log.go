package userhost

import (
	"errors"
	"os"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
)

const (
	maximumBackendLogSize = 64 * 1024 * 1024
	backendLogGenerations = 5
	maximumBackendLogLine = 1024 * 1024
)

var sensitiveBackendOutput = regexp.MustCompile(`(?i)(password|authorization|api[-_ ]?key|oauth|cookie|bearer|token|secret)`)

type boundedLogWriter struct {
	file      *os.File
	remaining int64
	pending   []byte
	discard   bool
	mu        sync.Mutex
}

func openBoundedLog(root *projectfs.Root, relative string) (*boundedLogWriter, error) {
	if err := root.RotateFile(relative, maximumBackendLogSize, backendLogGenerations); err != nil {
		return nil, err
	}
	file, err := root.Open(relative, os.O_CREATE|os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumBackendLogSize {
		file.Close()
		return nil, errors.New("tenant backend log is invalid or oversized")
	}
	return &boundedLogWriter{file: file, remaining: maximumBackendLogSize - info.Size()}, nil
}

func (w *boundedLogWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	accepted := len(payload)
	if w.file == nil || w.remaining <= 0 {
		return accepted, nil
	}
	for len(payload) > 0 {
		newline := -1
		for index, value := range payload {
			if value == '\n' {
				newline = index
				break
			}
		}
		if w.discard {
			if newline < 0 {
				return accepted, nil
			}
			w.discard = false
			payload = payload[newline+1:]
			continue
		}
		consume := len(payload)
		complete := false
		if newline >= 0 {
			consume, complete = newline+1, true
		}
		w.pending = append(w.pending, payload[:consume]...)
		payload = payload[consume:]
		if len(w.pending) > maximumBackendLogLine {
			if err := w.writeRedactedLocked([]byte("[REDACTED OVERSIZED OUTPUT]\n")); err != nil {
				return accepted, err
			}
			w.pending = w.pending[:0]
			w.discard = !complete
			continue
		}
		if complete {
			if err := w.flushLineLocked(); err != nil {
				return accepted, err
			}
		}
	}
	return accepted, nil
}

func (w *boundedLogWriter) flushLineLocked() error {
	if len(w.pending) == 0 {
		return nil
	}
	line := string(w.pending)
	w.pending = w.pending[:0]
	if sensitiveBackendOutput.MatchString(line) {
		line = "[REDACTED SENSITIVE OUTPUT]\n"
	} else {
		line = safelog.Redact(line)
	}
	return w.writeRedactedLocked([]byte(line))
}

func (w *boundedLogWriter) writeRedactedLocked(payload []byte) error {
	if w.file == nil || w.remaining <= 0 {
		return nil
	}
	writeLength := int64(len(payload))
	if writeLength > w.remaining {
		writeLength = w.remaining
	}
	written, err := w.file.Write(payload[:writeLength])
	w.remaining -= int64(written)
	return err
}

func (w *boundedLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	if !w.discard {
		if err := w.flushLineLocked(); err != nil {
			_ = w.file.Close()
			w.file = nil
			return err
		}
	}
	err := w.file.Close()
	w.file = nil
	return err
}
