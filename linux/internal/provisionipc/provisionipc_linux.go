//go:build linux

package provisionipc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	SocketPath      = "/run/workagent/provision.sock"
	ProtocolVersion = 1
	maxMessageBytes = 32 * 1024
)

type Request struct {
	ProtocolVersion int    `json:"protocol_version"`
	Command         string `json:"command"`
	Username        string `json:"username"`
	PortalPassword  []byte `json:"portal_password,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
	Actor           string `json:"actor"`
	Nonce           string `json:"nonce"`
}

type User struct {
	Username    string `json:"username"`
	TenantID    string `json:"tenant_id"`
	RuntimeUser string `json:"runtime_user"`
	Enabled     bool   `json:"enabled"`
}

type Response struct {
	ProtocolVersion int    `json:"protocol_version"`
	Nonce           string `json:"nonce"`
	OK              bool   `json:"ok"`
	ErrorCode       string `json:"error_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	User            *User  `json:"user,omitempty"`
}

type Handler func(context.Context, Request) Response

type Server struct {
	listener net.Listener
	cancel   context.CancelFunc
	wait     sync.WaitGroup
}

func ListenerFromFile(file *os.File) (net.Listener, error) {
	if file == nil {
		return nil, errors.New("provision listener file is missing")
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("open provision listener: %w", err)
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		listener.Close()
		return nil, errors.New("provision listener is not a Unix socket")
	}
	return listener, nil
}

func Serve(ctx context.Context, listener net.Listener, portalUID uint32, handler Handler) (*Server, error) {
	if ctx == nil || listener == nil || portalUID == 0 || handler == nil {
		return nil, errors.New("provision server configuration is incomplete")
	}
	serverCtx, cancel := context.WithCancel(ctx)
	server := &Server{listener: listener, cancel: cancel}
	server.wait.Add(1)
	go server.accept(serverCtx, portalUID, handler)
	return server, nil
}

func (s *Server) accept(ctx context.Context, portalUID uint32, handler Handler) {
	defer s.wait.Done()
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		s.wait.Add(1)
		go func() {
			defer s.wait.Done()
			defer connection.Close()
			if err := verifyPeerUID(connection, portalUID); err != nil {
				return
			}
			_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
			var request Request
			if err := readFrame(connection, &request); err != nil {
				return
			}
			defer clear(request.PortalPassword)
			if err := validateRequest(request); err != nil {
				_ = writeFrame(connection, Response{ProtocolVersion: ProtocolVersion, Nonce: request.Nonce, ErrorCode: "BAD_REQUEST", ErrorMessage: err.Error()})
				return
			}
			response := handler(ctx, request)
			response.ProtocolVersion, response.Nonce = ProtocolVersion, request.Nonce
			_ = writeFrame(connection, response)
		}()
	}
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	err := s.listener.Close()
	s.wait.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func Call(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("provision request context is missing")
	}
	request.ProtocolVersion = ProtocolVersion
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return Response{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := writeFrame(connection, request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := readFrame(connection, &response); err != nil {
		return Response{}, err
	}
	if response.ProtocolVersion != ProtocolVersion || response.Nonce != request.Nonce {
		return Response{}, errors.New("provision response mismatch")
	}
	if !response.OK {
		return Response{}, fmt.Errorf("provision failed (%s): %s", response.ErrorCode, response.ErrorMessage)
	}
	return response, nil
}

func validateRequest(request Request) error {
	if request.ProtocolVersion != ProtocolVersion || len(request.Nonce) < 16 || len(request.Nonce) > 256 || strings.TrimSpace(request.Username) == "" || strings.TrimSpace(request.Actor) == "" {
		return errors.New("invalid provision request")
	}
	switch request.Command {
	case "add-user":
		if len(request.PortalPassword) == 0 || request.Enabled != nil {
			return errors.New("invalid add-user request")
		}
	case "set-enabled":
		if len(request.PortalPassword) != 0 || request.Enabled == nil {
			return errors.New("invalid set-enabled request")
		}
	default:
		return errors.New("unsupported provision command")
	}
	return nil
}

func verifyPeerUID(connection net.Conn, expected uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("provision connection is not Unix")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if credential == nil || credential.Uid != expected {
		return errors.New("provision peer UID is not authorized")
	}
	return nil
}

func writeFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > maxMessageBytes {
		return errors.New("invalid provision message")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func readFrame(reader io.Reader, value any) error {
	buffered := bufio.NewReaderSize(reader, 16*1024)
	var header [4]byte
	if _, err := io.ReadFull(buffered, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxMessageBytes {
		return errors.New("invalid provision frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(buffered, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("provision frame contains trailing JSON")
	}
	return nil
}
