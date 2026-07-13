package adminipc

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

	"aionuiportal/internal/ipc"
	"github.com/Microsoft/go-winio"
)

const (
	PipeName        = `\\.\pipe\AionUiPortalAdmin`
	ProtocolVersion = 1
	maxMessageBytes = 128 * 1024
)

type Request struct {
	ProtocolVersion int    `json:"protocol_version"`
	Command         string `json:"command"`
	WindowsSID      string `json:"windows_sid"`
	Nonce           string `json:"nonce"`
}

type Response struct {
	ProtocolVersion int         `json:"protocol_version"`
	Nonce           string      `json:"nonce"`
	OK              bool        `json:"ok"`
	ErrorCode       string      `json:"error_code,omitempty"`
	ErrorMessage    string      `json:"error_message,omitempty"`
	Status          *ipc.Status `json:"status,omitempty"`
	Sessions        int         `json:"sessions"`
	Requests        int         `json:"requests"`
	WebSockets      int         `json:"websockets"`
}

type Handler func(context.Context, Request) Response

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
		return nil, errors.New("nil Portal admin IPC handler")
	}
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: securityDescriptor, InputBufferSize: 64 * 1024, OutputBufferSize: 64 * 1024})
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
			_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
			var request Request
			if err := readFrame(connection, &request); err != nil {
				return
			}
			if request.ProtocolVersion != ProtocolVersion || len(request.Nonce) < 16 || len(request.Nonce) > 256 || !validSID(request.WindowsSID) {
				_ = writeFrame(connection, Response{ProtocolVersion: ProtocolVersion, Nonce: request.Nonce, OK: false, ErrorCode: "BAD_REQUEST", ErrorMessage: "invalid admin IPC request"})
				return
			}
			response := handler(ctx, request)
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
	if request.ProtocolVersion == 0 {
		request.ProtocolVersion = ProtocolVersion
	}
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
	var response Response
	if err := readFrame(connection, &response); err != nil {
		return Response{}, err
	}
	if response.ProtocolVersion != ProtocolVersion || response.Nonce != request.Nonce {
		return Response{}, errors.New("Portal admin IPC response mismatch")
	}
	if !response.OK {
		return Response{}, fmt.Errorf("Portal admin IPC failed (%s): %s", response.ErrorCode, response.ErrorMessage)
	}
	return response, nil
}

func writeFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > maxMessageBytes {
		return errors.New("invalid Portal admin IPC message")
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
	buffered := bufio.NewReaderSize(reader, 64*1024)
	var header [4]byte
	if _, err := io.ReadFull(buffered, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxMessageBytes {
		return errors.New("invalid Portal admin IPC frame")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(buffered, data); err != nil {
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
