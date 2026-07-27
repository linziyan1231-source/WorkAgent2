package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
)

type smokeClient struct {
	baseURL   string
	client    *http.Client
	csrf      string
	tlsConfig *tls.Config
}

func main() {
	var baseURL, certificatePath, username, passwordPath, expectedTenant, expectedRelease, projectName string
	var skipWebSocket bool
	flag.StringVar(&baseURL, "base-url", "", "staging HTTPS origin")
	flag.StringVar(&certificatePath, "ca-file", "", "staging CA certificate")
	flag.StringVar(&username, "username", "", "Portal user")
	flag.StringVar(&passwordPath, "password-file", "", "protected password file")
	flag.StringVar(&expectedTenant, "expected-tenant", "", "expected tenant UUID")
	flag.StringVar(&expectedRelease, "expected-release", "", "expected immutable release ID")
	flag.StringVar(&projectName, "project", "smoke-project", "synthetic project name")
	flag.BoolVar(&skipWebSocket, "skip-websocket", false, "skip WebSocket echo for an older rollback fixture")
	flag.Parse()
	if baseURL == "" || certificatePath == "" || username == "" || passwordPath == "" || expectedTenant == "" {
		fatal("all connection and identity flags are required")
	}
	password, err := protectedFile(passwordPath, 1024)
	if err != nil {
		fatal(err.Error())
	}
	defer auth.Zero(password)
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		fatal(err.Error())
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		fatal("CA file contains no certificate")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		fatal(err.Error())
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true}
	client := &smokeClient{baseURL: strings.TrimSuffix(baseURL, "/"), client: &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second}, tlsConfig: transport.TLSClientConfig}
	var ready map[string]any
	if _, err := client.request(http.MethodGet, "/readyz", nil, &ready); err != nil {
		fatal(err.Error())
	}
	var login struct {
		User      map[string]any `json:"user"`
		CSRFToken string         `json:"csrf_token"`
	}
	if _, err := client.request(http.MethodPost, "/api/login", map[string]string{"username": username, "password": string(password)}, &login); err != nil {
		fatal(err.Error())
	}
	client.csrf = login.CSRFToken
	if tenant, _ := login.User["tenant_id"].(string); tenant != expectedTenant {
		fatal("login returned a different tenant")
	}
	var status struct {
		TenantID    string `json:"tenant_id"`
		RuntimeUser string `json:"runtime_user"`
		RuntimeUID  uint32 `json:"runtime_uid"`
		ReleaseID   string `json:"release_id"`
		Ready       bool   `json:"ready"`
	}
	if _, err := client.request(http.MethodGet, "/api/runtime/status", nil, &status); err != nil {
		fatal(err.Error())
	}
	if status.TenantID != expectedTenant || status.RuntimeUID == 0 || !status.Ready {
		fatal("runtime identity or readiness did not match")
	}
	if expectedRelease != "" && status.ReleaseID != expectedRelease {
		fatal("runtime release did not match")
	}
	var projects struct {
		Projects []string `json:"projects"`
	}
	if _, err := client.request(http.MethodGet, "/api/projects", nil, &projects); err != nil {
		fatal(err.Error())
	}
	if !contains(projects.Projects, projectName) {
		if _, err := client.request(http.MethodPost, "/api/projects", map[string]string{"name": projectName}, nil); err != nil {
			fatal(err.Error())
		}
	}
	var backend struct {
		Platform       string `json:"platform"`
		Company        string `json:"company"`
		TenantID       string `json:"tenant_id"`
		Synthetic      bool   `json:"synthetic"`
		ReceivedCookie bool   `json:"received_cookie"`
	}
	if _, err := client.request(http.MethodGet, "/runtime/api/info", nil, &backend); err != nil {
		fatal(err.Error())
	}
	if backend.Platform != "WorkAgent2" || backend.Company != "WorkAgent" || backend.TenantID != expectedTenant || !backend.Synthetic || backend.ReceivedCookie {
		fatal("backend identity did not match")
	}
	if !skipWebSocket {
		if err := client.websocketEcho(); err != nil {
			fatal(err.Error())
		}
	}
	if _, err := client.request(http.MethodPost, "/api/logout", nil, nil); err != nil {
		fatal(err.Error())
	}
	result := map[string]any{"passed": true, "tenant_id": status.TenantID, "runtime_user": status.RuntimeUser, "runtime_uid": status.RuntimeUID, "release_id": status.ReleaseID, "project": projectName}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}

func (s *smokeClient) websocketEcho() error {
	parsed, err := url.Parse(s.baseURL)
	if err != nil {
		return err
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	tlsConfig := s.tlsConfig.Clone()
	tlsConfig.ServerName = parsed.Hostname()
	tlsConfig.NextProtos = []string{"http/1.1"}
	connection, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return err
	}
	defer connection.Close()
	keyBytes := make([]byte, 16)
	mask := make([]byte, 4)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, s.baseURL+"/runtime/ws", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(keyBytes))
	request.Header.Set("Origin", s.baseURL)
	request.Header.Set("User-Agent", "WorkAgent-AI-Staging-Smoke/1.0")
	for _, cookie := range s.client.Jar.Cookies(parsed) {
		request.AddCookie(cookie)
	}
	if err := request.Write(connection); err != nil {
		return err
	}
	buffered := bufio.NewReader(connection)
	response, err := http.ReadResponse(buffered, request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("WebSocket upgrade returned HTTP %d", response.StatusCode)
	}
	payload := []byte("workagent-smoke")
	masked := make([]byte, len(payload))
	for index := range payload {
		masked[index] = payload[index] ^ mask[index%4]
	}
	frame := append([]byte{0x81, 0x80 | byte(len(payload))}, mask...)
	frame = append(frame, masked...)
	if _, err := connection.Write(frame); err != nil {
		return err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(buffered, header); err != nil {
		return err
	}
	if header[0]&0x0f != 1 || header[1]&0x80 != 0 || int(header[1]&0x7f) != len(payload) {
		return errors.New("invalid WebSocket echo frame")
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(buffered, echo); err != nil {
		return err
	}
	if !bytes.Equal(echo, payload) {
		return errors.New("WebSocket echo payload mismatch")
	}
	return nil
}

func (s *smokeClient) request(method, requestPath string, body any, destination any) (int, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, s.baseURL+requestPath, reader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", "WorkAgent-AI-Staging-Smoke/1.0")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", s.baseURL)
		if s.csrf != "" {
			request.Header.Set("X-CSRF-Token", s.csrf)
		}
	}
	response, err := s.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return response.StatusCode, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("%s %s returned HTTP %d", method, requestPath, response.StatusCode)
	}
	if destination != nil && len(payload) != 0 {
		if err := json.Unmarshal(payload, destination); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}

func protectedFile(path string, maximum int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("password file path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maximum {
		return nil, errors.New("password file is not protected")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(strings.TrimSuffix(string(payload), "\n"), "\r")), nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "workagent-smoke:", message)
	os.Exit(1)
}
