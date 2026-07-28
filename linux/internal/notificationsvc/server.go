package notificationsvc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const maxPayloadBytes = 64 * 1024

type Config struct {
	ListenAddress  string
	PayloadFile    string
	CredentialFile string
	Logger         *log.Logger
}

type Server struct {
	listener   net.Listener
	payload    string
	credential [32]byte
	logger     *log.Logger
}

type notification struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Message     string `json:"message"`
	PublishedAt string `json:"published_at,omitempty"`
}

type envelope struct {
	Notifications []notification `json:"notifications"`
}

func New(config Config) (*Server, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:25888"
	}
	host, _, err := net.SplitHostPort(config.ListenAddress)
	if err != nil {
		return nil, errors.New("notification listen address is invalid")
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return nil, errors.New("notification listener must use a numeric loopback address")
	}
	payload, err := loadPayload(config.PayloadFile)
	if err != nil {
		return nil, err
	}
	credential, err := loadCredential(config.CredentialFile)
	if err != nil {
		return nil, err
	}
	credentialDigest := sha256.Sum256(credential)
	clear(credential)
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for notifications: %w", err)
	}
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{listener: listener, payload: payload, credential: credentialDigest, logger: logger}, nil
}

func (s *Server) Address() string { return s.listener.Addr().String() }

func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *Server) Serve(server *http.Server) error {
	if s == nil || s.listener == nil {
		return errors.New("notification server is not initialized")
	}
	if server == nil {
		server = &http.Server{}
	}
	server.Handler = s.Handler()
	return server.Serve(s.listener)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /notification", func(writer http.ResponseWriter, request *http.Request) {
		provided := strings.TrimSpace(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		digest := sha256.Sum256([]byte(provided))
		if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(digest[:], s.credential[:]) != 1 {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="notifications"`)
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(writer, s.payload)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(writer, request)
	})
}

func loadPayload(path string) (string, error) {
	if err := protectedRootFile(path, 1, maxPayloadBytes); err != nil {
		return "", fmt.Errorf("notification payload: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("notification payload is unreadable")
	}
	var value envelope
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return "", errors.New("notification payload is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || len(value.Notifications) > 20 {
		return "", errors.New("notification payload has an unsupported shape")
	}
	seen := make(map[string]bool, len(value.Notifications))
	for _, item := range value.Notifications {
		if item.ID == "" || len(item.ID) > 200 || item.Message == "" || len(item.Message) > 4000 || len(item.Title) > 200 || len(item.PublishedAt) > 100 || strings.ContainsAny(item.ID+item.Title+item.Message+item.PublishedAt, "\x00\r") || seen[item.ID] {
			return "", errors.New("notification payload contains an invalid item")
		}
		if item.PublishedAt != "" {
			if _, err := time.Parse(time.RFC3339, item.PublishedAt); err != nil {
				return "", errors.New("notification published_at is invalid")
			}
		}
		seen[item.ID] = true
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("notification payload could not be encoded")
	}
	return string(encoded) + "\n", nil
}

func loadCredential(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("notification credential path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 || info.Size() < 16 || info.Size() > 4096 {
		return nil, errors.New("notification credential is missing or unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("notification credential is unreadable")
	}
	value := []byte(strings.TrimSpace(string(raw)))
	if len(value) < 16 || len(value) > 4096 || strings.ContainsAny(string(value), "\x00\r\n") {
		clear(raw)
		clear(value)
		return nil, errors.New("notification credential is invalid")
	}
	clear(raw)
	return value, nil
}

func protectedRootFile(path string, minimum, maximum int64) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < minimum || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 {
		return errors.New("file is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("file must be owned by root")
	}
	return nil
}
