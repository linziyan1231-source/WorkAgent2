package ipc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	ProtocolVersion = 2
	maxMessageBytes = 128 * 1024
)

type Request struct {
	ProtocolVersion int                   `json:"protocol_version"`
	Command         string                `json:"command"`
	Nonce           string                `json:"nonce"`
	OAuthStart      *OAuthStartRequest    `json:"oauth_start,omitempty"`
	OAuthComplete   *OAuthCompleteRequest `json:"oauth_complete,omitempty"`
	OAuthCancel     *OAuthCancelRequest   `json:"oauth_cancel,omitempty"`
	ProjectCreate   *ProjectCreateRequest `json:"project_create,omitempty"`
	ProjectRename   *ProjectRenameRequest `json:"project_rename,omitempty"`
}

type OAuthStartRequest struct {
	InstanceID  string `json:"instance_id"`
	ServerURL   string `json:"server_url"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

type OAuthCompleteRequest struct {
	InstanceID string `json:"instance_id"`
	FlowID     string `json:"flow_id"`
	ServerURL  string `json:"server_url"`
	Code       string `json:"code"`
}

type OAuthCancelRequest struct {
	InstanceID string `json:"instance_id"`
	FlowID     string `json:"flow_id"`
	ServerURL  string `json:"server_url"`
}

type OAuthResult struct {
	AuthorizationURL string `json:"authorization_url,omitempty"`
	FlowID           string `json:"flow_id,omitempty"`
}

type ProjectCreateRequest struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
}

type ProjectCreateResult struct {
	Path string `json:"path"`
}

type ProjectRenameRequest struct {
	InstanceID string `json:"instance_id"`
	OldName    string `json:"old_name"`
	NewName    string `json:"new_name"`
	Force      bool   `json:"force"`
	LegacyRoot bool   `json:"legacy_root"`
}

type ProjectRenameResult struct {
	OldPath              string `json:"old_path"`
	NewPath              string `json:"new_path"`
	UpdatedConversations int    `json:"updated_conversations"`
}

type Activity struct {
	Known         bool   `json:"known"`
	Active        bool   `json:"active"`
	Reason        string `json:"reason,omitempty"`
	CheckedAtUnix int64  `json:"checked_at_unix"`
}

type Status struct {
	WindowsSID       string   `json:"windows_sid"`
	State            string   `json:"state"`
	Healthy          bool     `json:"healthy"`
	UserHostPID      uint32   `json:"user_host_pid"`
	WebPID           uint32   `json:"web_pid"`
	AionCorePID      uint32   `json:"aioncore_pid"`
	WebPort          int      `json:"web_port"`
	AionCorePort     int      `json:"aioncore_port"`
	Version          string   `json:"version"`
	ProcessCount     uint32   `json:"process_count"`
	MemoryBytes      uint64   `json:"memory_bytes"`
	CPUPercent       float64  `json:"cpu_percent"`
	LastActivityUnix int64    `json:"last_activity_unix"`
	StartedAtUnix    int64    `json:"started_at_unix"`
	FailureReason    string   `json:"failure_reason,omitempty"`
	Checks           []string `json:"checks,omitempty"`
	Activity         Activity `json:"activity"`
}

type AuthMaterial struct {
	CookieHeader string `json:"cookie_header"`
	CSRFToken    string `json:"csrf_token"`
}

type ModelKeyIDs struct {
	CodexKeyID string `json:"codex_key_id"`
	KimiKeyID  string `json:"kimi_key_id"`
}

type Response struct {
	ProtocolVersion int                  `json:"protocol_version"`
	Nonce           string               `json:"nonce"`
	OK              bool                 `json:"ok"`
	ErrorCode       string               `json:"error_code,omitempty"`
	ErrorMessage    string               `json:"error_message,omitempty"`
	Status          *Status              `json:"status,omitempty"`
	Auth            *AuthMaterial        `json:"auth,omitempty"`
	OAuth           *OAuthResult         `json:"oauth,omitempty"`
	ModelKeyIDs     *ModelKeyIDs         `json:"model_key_ids,omitempty"`
	ProjectCreate   *ProjectCreateResult `json:"project_create,omitempty"`
	ProjectRename   *ProjectRenameResult `json:"project_rename,omitempty"`
}

type Handler func(context.Context, Request) Response

type Server struct {
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func SDDL(ownerSID, portalServiceSID string) (string, error) {
	if !isSID(ownerSID) || !isSID(portalServiceSID) {
		return "", errors.New("owner and Portal service SIDs must be valid")
	}
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)(A;;GRGW;;;%s)", ownerSID, portalServiceSID), nil
}

func Listen(ctx context.Context, pipeName, securityDescriptor string, handler Handler) (*Server, error) {
	if !strings.HasPrefix(pipeName, `\\.\pipe\AionUiWeb-S-1-`) {
		return nil, errors.New("invalid AionUi UserHost pipe name")
	}
	if handler == nil {
		return nil, errors.New("nil IPC handler")
	}
	listener, err := winio.ListenPipe(pipeName, &winio.PipeConfig{
		SecurityDescriptor: securityDescriptor,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on protected UserHost pipe: %w", err)
	}
	serverCtx, cancel := context.WithCancel(ctx)
	s := &Server{listener: listener, cancel: cancel}
	s.wg.Add(1)
	go s.accept(serverCtx, handler)
	return s, nil
}

func (s *Server) accept(ctx context.Context, handler Handler) {
	defer s.wg.Done()
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			var req Request
			if err := readFrame(conn, &req); err != nil {
				return
			}
			if req.ProtocolVersion != ProtocolVersion || len(req.Nonce) < 16 || len(req.Nonce) > 256 {
				_ = writeFrame(conn, Response{ProtocolVersion: ProtocolVersion, Nonce: req.Nonce, OK: false, ErrorCode: "BAD_REQUEST", ErrorMessage: "invalid protocol request"})
				return
			}
			response := handler(ctx, req)
			response.ProtocolVersion = ProtocolVersion
			response.Nonce = req.Nonce
			_ = writeFrame(conn, response)
		}()
	}
}

func (s *Server) Close() error {
	s.cancel()
	err := s.listener.Close()
	s.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func Call(ctx context.Context, pipeName string, request Request) (Response, error) {
	if request.ProtocolVersion == 0 {
		request.ProtocolVersion = ProtocolVersion
	}
	conn, err := winio.DialPipeContext(ctx, pipeName)
	if err != nil {
		return Response{}, fmt.Errorf("connect UserHost pipe: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := writeFrame(conn, request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := readFrame(conn, &response); err != nil {
		return Response{}, err
	}
	if response.ProtocolVersion != ProtocolVersion || response.Nonce != request.Nonce {
		return Response{}, errors.New("UserHost IPC response did not match request")
	}
	return response, nil
}

func writeFrame(w io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode IPC message: %w", err)
	}
	if len(b) > maxMessageBytes {
		return errors.New("IPC message exceeds size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write IPC header: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write IPC body: %w", err)
	}
	return nil
}

func readFrame(r io.Reader, value any) error {
	reader := bufio.NewReaderSize(r, 64*1024)
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("read IPC header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxMessageBytes {
		return errors.New("invalid IPC message size")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(reader, b); err != nil {
		return fmt.Errorf("read IPC body: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return fmt.Errorf("decode IPC message: %w", err)
	}
	return nil
}

func isSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 184 {
		return false
	}
	for _, r := range s[4:] {
		if (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
