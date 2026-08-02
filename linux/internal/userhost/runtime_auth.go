package userhost

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

const (
	workAgentTenantEnvironment    = "WORKAGENT_TENANT_ID"
	workAgentRuntimeFDEnvironment = "WORKAGENT_RUNTIME_FD"
	workAgentRuntimeFDText        = "3"
	workAgentRuntimeChildFD       = 3
	// Reserved legacy name. A runtime token in any environment is forbidden.
	workAgentRuntimeEnvironment    = "WORKAGENT_RUNTIME_TOKEN"
	workAgentRuntimeHeader         = "X-WorkAgent-Runtime-Token"
	workAgentRuntimeTokenBytes     = 32
	workAgentRuntimeTokenTextBytes = 43
	workAgentRuntimeFrameBytes     = 42
)

var workAgentRuntimeFrameMagic = [8]byte{'W', 'A', 'T', 'O', 'K', 'N', '1', 0}

func generateWorkAgentRuntimeToken() ([]byte, error) {
	raw := make([]byte, workAgentRuntimeTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		clear(raw)
		return nil, errors.New("generate tenant runtime transport credential")
	}
	token := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(token, raw)
	clear(raw)
	if !validWorkAgentRuntimeToken(token) {
		clear(token)
		return nil, errors.New("generated tenant runtime transport credential is invalid")
	}
	return token, nil
}

func validWorkAgentRuntimeToken(token []byte) bool {
	if len(token) != workAgentRuntimeTokenTextBytes {
		return false
	}
	decoded := make([]byte, workAgentRuntimeTokenBytes)
	n, err := base64.RawURLEncoding.Decode(decoded, token)
	if err != nil || n != workAgentRuntimeTokenBytes {
		clear(decoded)
		return false
	}
	canonical := make([]byte, workAgentRuntimeTokenTextBytes)
	base64.RawURLEncoding.Encode(canonical, decoded)
	clear(decoded)
	valid := subtle.ConstantTimeCompare(canonical, token) == 1
	clear(canonical)
	return valid
}

func setWorkAgentRuntimeHeader(request *http.Request, token []byte) {
	request.Header.Del(workAgentRuntimeHeader)
	request.Header.Set(workAgentRuntimeHeader, string(token))
}

// startRuntimeCommand passes the credential exactly once over an anonymous
// AF_UNIX/SOCK_SEQPACKET inherited as child fd 3. The secret never enters an
// environment, argument, filesystem object, pipe or memfd. The send happens
// only after Start identifies the exact child, then both parent-side socket
// references and all temporary raw/frame buffers are destroyed.
func startRuntimeCommand(command *exec.Cmd, token []byte) error {
	if command == nil || len(command.ExtraFiles) != 0 || !validWorkAgentRuntimeToken(token) {
		return errors.New("prepare tenant runtime credential channel")
	}
	raw := make([]byte, workAgentRuntimeTokenBytes)
	n, err := base64.RawURLEncoding.Decode(raw, token)
	if err != nil || n != workAgentRuntimeTokenBytes {
		clear(raw)
		return errors.New("prepare tenant runtime credential frame")
	}
	frame := make([]byte, workAgentRuntimeFrameBytes)
	copy(frame[:len(workAgentRuntimeFrameMagic)], workAgentRuntimeFrameMagic[:])
	binary.BigEndian.PutUint16(frame[len(workAgentRuntimeFrameMagic):], workAgentRuntimeTokenBytes)
	copy(frame[len(workAgentRuntimeFrameMagic)+2:], raw)
	clear(raw)

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		clear(frame)
		return errors.New("create tenant runtime credential channel")
	}
	parent := os.NewFile(uintptr(fds[0]), "workagent-runtime-parent")
	child := os.NewFile(uintptr(fds[1]), "workagent-runtime-child")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		} else {
			_ = syscall.Close(fds[0])
		}
		if child != nil {
			_ = child.Close()
		} else {
			_ = syscall.Close(fds[1])
		}
		clear(frame)
		return errors.New("adopt tenant runtime credential channel")
	}
	command.ExtraFiles = []*os.File{child}
	startErr := command.Start()
	command.ExtraFiles = nil
	for index := range command.Env {
		command.Env[index] = ""
	}
	command.Env = nil
	_ = child.Close()
	if startErr != nil {
		_ = parent.Close()
		clear(frame)
		return startErr
	}

	written, sendErr := syscall.Write(int(parent.Fd()), frame)
	shutdownErr := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR)
	closeErr := parent.Close()
	clear(frame)
	if sendErr == nil && written != workAgentRuntimeFrameBytes {
		sendErr = fmt.Errorf("credential frame write was %d bytes", written)
	}
	if sendErr == nil && shutdownErr != nil {
		sendErr = shutdownErr
	}
	if sendErr == nil && closeErr != nil {
		sendErr = closeErr
	}
	if sendErr != nil {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		return errors.New("deliver tenant runtime credential")
	}
	return nil
}
