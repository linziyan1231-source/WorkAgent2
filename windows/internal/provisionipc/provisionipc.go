package provisionipc

import (
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
	PipeName        = `\\.\pipe\AionUiPortalProvisioner`
	ProtocolVersion = 1
	maxMessageBytes = 32 * 1024
)

type Request struct {
	ProtocolVersion int      `json:"protocol_version"`
	Command         string   `json:"command"`
	Username        string   `json:"username"`
	PortalPassword  []byte   `json:"portal_password"`
	Enabled         bool     `json:"enabled,omitempty"`
	AllowedSources  []string `json:"allowed_sources,omitempty"`
	DailyLimit      int      `json:"daily_limit,omitempty"`
	MonthlyLimit    int      `json:"monthly_limit,omitempty"`
	Nonce           string   `json:"nonce"`
}

type User struct {
	Username        string `json:"username"`
	WindowsUsername string `json:"windows_username"`
	WindowsSID      string `json:"windows_sid"`
}

type Progress struct {
	Percent int    `json:"percent"`
	Step    string `json:"step"`
}

type Response struct {
	ProtocolVersion int                  `json:"protocol_version"`
	Nonce           string               `json:"nonce"`
	OK              bool                 `json:"ok"`
	ErrorCode       string               `json:"error_code,omitempty"`
	ErrorMessage    string               `json:"error_message,omitempty"`
	User            *User                `json:"user,omitempty"`
	KimiDatasource  *KimiDatasourceGrant `json:"kimi_datasource,omitempty"`
	Progress        *Progress            `json:"progress,omitempty"`
}

type KimiDatasourceGrant struct {
	Enabled        bool     `json:"enabled"`
	AllowedSources []string `json:"allowed_sources"`
	DailyLimit     int      `json:"daily_limit"`
	MonthlyLimit   int      `json:"monthly_limit"`
	DailyUsed      int      `json:"daily_used"`
	MonthlyUsed    int      `json:"monthly_used"`
}

type Handler func(context.Context, Request, func(Progress)) Response

type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("provision failed (%s): %s", e.Code, e.Message)
}

type Server struct {
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func SDDL(portalServiceSID string) (string, error) {
	if !validSID(portalServiceSID) {
		return "", errors.New("invalid Portal service SID")
	}
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", portalServiceSID), nil
}

func Listen(ctx context.Context, securityDescriptor string, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("nil provision handler")
	}
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: securityDescriptor, InputBufferSize: 16 * 1024, OutputBufferSize: 16 * 1024})
	if err != nil {
		return nil, err
	}
	serverCtx, cancel := context.WithCancel(ctx)
	server := &Server{listener: listener, cancel: cancel}
	server.wg.Add(1)
	go server.accept(serverCtx, handler)
	return server, nil
}

func (s *Server) accept(ctx context.Context, handler Handler) {
	defer s.wg.Done()
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
			var request Request
			if err := readFrame(connection, &request); err != nil {
				return
			}
			if request.ProtocolVersion != ProtocolVersion || len(request.Nonce) < 16 || len(request.Nonce) > 256 ||
				(request.Command != "add-user" && request.Command != "set-kimi-datasource") {
				_ = writeFrame(connection, Response{ProtocolVersion: ProtocolVersion, Nonce: request.Nonce, ErrorCode: "BAD_REQUEST", ErrorMessage: "invalid provision request"})
				return
			}
			report := func(progress Progress) {
				_ = writeFrame(connection, Response{ProtocolVersion: ProtocolVersion, Nonce: request.Nonce, Progress: &progress})
			}
			response := handler(ctx, request, report)
			response.ProtocolVersion, response.Nonce = ProtocolVersion, request.Nonce
			_ = writeFrame(connection, response)
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

func Call(ctx context.Context, request Request) (Response, error) {
	return CallWithProgress(ctx, request, nil)
}

func CallWithProgress(ctx context.Context, request Request, onProgress func(Progress)) (Response, error) {
	request.ProtocolVersion = ProtocolVersion
	connection, err := winio.DialPipeContext(ctx, PipeName)
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
	for {
		var response Response
		if err := readFrame(connection, &response); err != nil {
			return Response{}, err
		}
		if response.ProtocolVersion != ProtocolVersion || response.Nonce != request.Nonce {
			return Response{}, errors.New("provision response mismatch")
		}
		if response.Progress != nil {
			if onProgress != nil {
				onProgress(*response.Progress)
			}
			continue
		}
		if !response.OK {
			return response, &RemoteError{Code: response.ErrorCode, Message: response.ErrorMessage}
		}
		return response, nil
	}
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
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxMessageBytes {
		return errors.New("invalid provision frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func validSID(value string) bool {
	if !strings.HasPrefix(value, "S-1-") || len(value) > 184 {
		return false
	}
	for _, character := range value[4:] {
		if (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
