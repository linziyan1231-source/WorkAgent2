package userhost

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var sensitiveOutput = regexp.MustCompile(`(?i)(password|authorization|api[-_ ]?key|oauth|cookie|bearer|token|secret)`)

type privateLog struct {
	mu   sync.Mutex
	file *os.File
}

func openPrivateLog(dir string) (*privateLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "userhost-"+time.Now().UTC().Format("20060102")+".log")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &privateLog{file: file}, nil
}

func (l *privateLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *privateLog) Printf(format string, values ...any) {
	line := fmt.Sprintf(format, values...)
	if sensitiveOutput.MatchString(line) {
		line = "[REDACTED SENSITIVE OUTPUT]"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), line)
	l.file.Sync()
}

func (l *privateLog) CopyRedacted(prefix string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if sensitiveOutput.MatchString(line) {
			line = "[REDACTED SENSITIVE OUTPUT]"
		}
		l.Printf("%s %s", prefix, line)
	}
	if err := scanner.Err(); err != nil {
		l.Printf("%s output read failed: %v", prefix, err)
	}
}
