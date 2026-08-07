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
	ProtocolVersion           = 2
	maxMessageBytes           = 2 * 1024 * 1024
	defaultRequestTimeout     = 15 * time.Second
	sharedAgentRequestTimeout = 31 * time.Minute
)

func requestTimeout(command string) time.Duration {
	if command == "shared_agent_run" {
		return sharedAgentRequestTimeout
	}
	return defaultRequestTimeout
}

type Request struct {
	ProtocolVersion  int                                `json:"protocol_version"`
	Command          string                             `json:"command"`
	Nonce            string                             `json:"nonce"`
	OAuthStart       *OAuthStartRequest                 `json:"oauth_start,omitempty"`
	OAuthComplete    *OAuthCompleteRequest              `json:"oauth_complete,omitempty"`
	OAuthCancel      *OAuthCancelRequest                `json:"oauth_cancel,omitempty"`
	ProjectCreate    *ProjectCreateRequest              `json:"project_create,omitempty"`
	ProjectRename    *ProjectRenameRequest              `json:"project_rename,omitempty"`
	ProjectResolve   *ProjectResolveRequest             `json:"project_resolve,omitempty"`
	ProjectList      *ProjectListRequest                `json:"project_list,omitempty"`
	SharedProject    *SharedProjectRequest              `json:"shared_project,omitempty"`
	SharedAgent      *SharedAgentRequest                `json:"shared_agent,omitempty"`
	SharedAgentStop  *SharedAgentStopRequest            `json:"shared_agent_stop,omitempty"`
	SharedCredential *SharedAgentCredentialRequest      `json:"shared_credential,omitempty"`
	SharedFile       *SharedFileRequest                 `json:"shared_file,omitempty"`
	SharedTransfer   *SharedTransferRequest             `json:"shared_transfer,omitempty"`
	SharedRelocate   *SharedConversationRelocateRequest `json:"shared_relocate,omitempty"`
	UsageSnapshot    json.RawMessage                    `json:"usage_snapshot,omitempty"`
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
	Path      string `json:"path"`
	ProjectID string `json:"project_id"`
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
	ProjectID            string `json:"project_id"`
}

type ProjectResolveRequest struct {
	InstanceID string `json:"instance_id"`
	ProjectID  string `json:"project_id"`
}

type ProjectResolveResult struct {
	Path string `json:"path"`
}

type ProjectListRequest struct {
	InstanceID string `json:"instance_id"`
}

type ProjectListItem struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

type ProjectListResult struct {
	Projects []ProjectListItem `json:"projects"`
}

type SharedProjectRequest struct {
	InstanceID          string   `json:"instance_id"`
	ProjectID           string   `json:"project_id"`
	SourceKind          string   `json:"source_kind"`
	SourceProjectID     string   `json:"source_project_id,omitempty"`
	ProjectMemberSIDs   []string `json:"project_member_sids"`
	OwnerRootMemberSIDs []string `json:"owner_root_member_sids"`
	Commit              bool     `json:"commit,omitempty"`
}

type SharedProjectResult struct {
	ProjectID string `json:"project_id"`
	SizeBytes uint64 `json:"size_bytes"`
}

type SharedAgentRequest struct {
	InstanceID            string `json:"instance_id"`
	ProjectID             string `json:"project_id"`
	RuntimeConversationID string `json:"runtime_conversation_id,omitempty"`
	Name                  string `json:"name"`
	AssistantID           string `json:"assistant_id"`
	AssistantBackend      string `json:"assistant_backend"`
	ModelID               string `json:"model_id"`
	ThinkingEffort        string `json:"thinking_effort"`
	Context               string `json:"context"`
	RecoveryContext       string `json:"recovery_context"`
	CredentialID          string `json:"credential_id"`
}

type SharedAgentResult struct {
	RuntimeConversationID string `json:"runtime_conversation_id"`
	TurnID                string `json:"turn_id"`
	AssistantBody         string `json:"assistant_body,omitempty"`
	Recovered             bool   `json:"recovered"`
}

type SharedAgentStopRequest struct {
	InstanceID string `json:"instance_id"`
	ProjectID  string `json:"project_id"`
}

type SharedAgentCredentialRequest struct {
	InstanceID   string `json:"instance_id"`
	CredentialID string `json:"credential_id"`
	PlainKey     string `json:"plain_key,omitempty"`
	BaseURL      string `json:"base_url,omitempty"`
}

type SharedAgentCredentialResult struct {
	Installed bool `json:"installed"`
}

type SharedFileRequest struct {
	InstanceID string `json:"instance_id"`
	OwnerSID   string `json:"owner_sid"`
	ProjectID  string `json:"project_id"`
	Operation  string `json:"operation"`
	Path       string `json:"path,omitempty"`
	Data       string `json:"data,omitempty"`
	NewName    string `json:"new_name,omitempty"`
}

type SharedFileResult struct {
	Data json.RawMessage `json:"data"`
}

type SharedTransferRequest struct {
	InstanceID                  string   `json:"instance_id"`
	ProjectID                   string   `json:"project_id"`
	OldOwnerSID                 string   `json:"old_owner_sid"`
	ProjectMemberSIDs           []string `json:"project_member_sids"`
	OldProjectMemberSIDs        []string `json:"old_project_member_sids"`
	OwnerRootMemberSIDs         []string `json:"owner_root_member_sids"`
	PreviousOwnerRootMemberSIDs []string `json:"previous_owner_root_member_sids"`
	Commit                      bool     `json:"commit,omitempty"`
}

type SharedConversationRelocateRequest struct {
	InstanceID  string `json:"instance_id"`
	ProjectID   string `json:"project_id"`
	OldOwnerSID string `json:"old_owner_sid"`
	NewOwnerSID string `json:"new_owner_sid"`
	Phase       string `json:"phase"`
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

type StorageBucketUsage struct {
	LimitBytes     uint64 `json:"limit_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	RemainingBytes uint64 `json:"remaining_bytes"`
	MeasuredAt     string `json:"measured_at"`
}

type StorageUsage struct {
	Personal StorageBucketUsage `json:"personal"`
	Shared   StorageBucketUsage `json:"shared"`
}

type Response struct {
	ProtocolVersion  int                          `json:"protocol_version"`
	Nonce            string                       `json:"nonce"`
	OK               bool                         `json:"ok"`
	ErrorCode        string                       `json:"error_code,omitempty"`
	ErrorMessage     string                       `json:"error_message,omitempty"`
	Status           *Status                      `json:"status,omitempty"`
	Auth             *AuthMaterial                `json:"auth,omitempty"`
	OAuth            *OAuthResult                 `json:"oauth,omitempty"`
	ModelKeyIDs      *ModelKeyIDs                 `json:"model_key_ids,omitempty"`
	StorageUsage     *StorageUsage                `json:"storage_usage,omitempty"`
	ProjectCreate    *ProjectCreateResult         `json:"project_create,omitempty"`
	ProjectRename    *ProjectRenameResult         `json:"project_rename,omitempty"`
	ProjectResolve   *ProjectResolveResult        `json:"project_resolve,omitempty"`
	ProjectList      *ProjectListResult           `json:"project_list,omitempty"`
	SharedProject    *SharedProjectResult         `json:"shared_project,omitempty"`
	SharedAgent      *SharedAgentResult           `json:"shared_agent,omitempty"`
	SharedCredential *SharedAgentCredentialResult `json:"shared_credential,omitempty"`
	SharedFile       *SharedFileResult            `json:"shared_file,omitempty"`
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
			conn.SetDeadline(time.Now().Add(defaultRequestTimeout))
			var req Request
			if err := readFrame(conn, &req); err != nil {
				return
			}
			if req.ProtocolVersion != ProtocolVersion || len(req.Nonce) < 16 || len(req.Nonce) > 256 {
				_ = writeFrame(conn, Response{ProtocolVersion: ProtocolVersion, Nonce: req.Nonce, OK: false, ErrorCode: "BAD_REQUEST", ErrorMessage: "invalid protocol request"})
				return
			}
			conn.SetDeadline(time.Now().Add(requestTimeout(req.Command)))
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
