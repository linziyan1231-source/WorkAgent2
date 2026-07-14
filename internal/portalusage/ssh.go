package portalusage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"aionuiportal/internal/modelbootstrap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	maxSSHOutput       = 64 * 1024
	maxSSHError        = 8 * 1024
	maxSSHIdentityFile = 16 * 1024
	maxSSHKnownHosts   = 64 * 1024
	sshConnectTimeout  = 10 * time.Second
	sshIOTimeout       = 25 * time.Second
)

var (
	sshTargetPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.-]{1,253}$`)
	helperPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,240}$`)
)

type SSHOptions struct {
	Target         string
	HelperPath     string
	IdentityFile   string
	KnownHostsFile string
}

type commandRunner func(context.Context, string, []byte, io.Writer, io.Writer) error

type SSHClient struct {
	options SSHOptions
	run     commandRunner
}

func NewSSHClient(options SSHOptions) (*SSHClient, error) {
	if !sshTargetPattern.MatchString(options.Target) {
		return nil, errors.New("Portal usage SSH target is invalid")
	}
	if !helperPathPattern.MatchString(options.HelperPath) || strings.Contains(options.HelperPath, "..") {
		return nil, errors.New("Portal usage remote helper path is invalid")
	}
	for name, path := range map[string]string{"identity": options.IdentityFile, "known-hosts": options.KnownHostsFile} {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("Portal usage SSH %s file must be absolute", name)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("Portal usage SSH %s file must be a regular non-symlink file", name)
		}
	}
	identity, err := readBoundedFile(options.IdentityFile, maxSSHIdentityFile)
	if err != nil {
		return nil, errors.New("Portal usage SSH identity could not be read")
	}
	signer, err := ssh.ParsePrivateKey(identity)
	clear(identity)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("Portal usage SSH identity must be an unencrypted Ed25519 key")
	}
	if info, err := os.Stat(options.KnownHostsFile); err != nil || info.Size() == 0 || info.Size() > maxSSHKnownHosts {
		return nil, errors.New("Portal usage SSH known-hosts file is empty or oversized")
	}
	hostKeyCallback, err := knownhosts.New(options.KnownHostsFile)
	if err != nil {
		return nil, errors.New("Portal usage SSH known-hosts file is invalid")
	}
	user, host, _ := strings.Cut(options.Target, "@")
	address := net.JoinHostPort(host, "22")
	config := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hostKeyCallback, Timeout: sshConnectTimeout}
	return &SSHClient{options: options, run: nativeSSHRunner(address, config)}, nil
}

func (c *SSHClient) Query(ctx context.Context, ids modelbootstrap.KeyIDs) (RawSnapshot, error) {
	request := struct {
		Version int `json:"version"`
		Keys    []struct {
			Kind  string `json:"kind"`
			KeyID string `json:"key_id"`
		} `json:"keys"`
	}{Version: 1}
	request.Keys = append(request.Keys,
		struct {
			Kind  string `json:"kind"`
			KeyID string `json:"key_id"`
		}{Kind: KindChatGPT, KeyID: ids.CodexKeyID},
		struct {
			Kind  string `json:"kind"`
			KeyID string `json:"key_id"`
		}{Kind: KindKimi, KeyID: ids.KimiKeyID},
	)
	payload, err := json.Marshal(request)
	if err != nil {
		return RawSnapshot{}, errors.New("encode remote usage request")
	}
	stdout := &cappedBuffer{limit: maxSSHOutput}
	stderr := &cappedBuffer{limit: maxSSHError}
	if err := c.run(ctx, c.options.HelperPath+" usage", payload, stdout, stderr); err != nil {
		if ctx.Err() != nil {
			return RawSnapshot{}, ctx.Err()
		}
		return RawSnapshot{}, errors.New("remote usage helper failed")
	}
	if stdout.overflow {
		return RawSnapshot{}, errors.New("remote usage response exceeded the output limit")
	}
	return parseRemoteResponse(stdout.Bytes())
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("file exceeds the permitted size")
	}
	return data, nil
}

func nativeSSHRunner(address string, config *ssh.ClientConfig) commandRunner {
	return func(ctx context.Context, command string, stdin []byte, stdout, stderr io.Writer) error {
		dialer := net.Dialer{Timeout: sshConnectTimeout}
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		defer connection.Close()
		if err := connection.SetDeadline(boundedDeadline(ctx, sshConnectTimeout)); err != nil {
			return err
		}
		clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
		if err != nil {
			return err
		}
		client := ssh.NewClient(clientConnection, channels, requests)
		defer client.Close()
		if err := connection.SetDeadline(boundedDeadline(ctx, sshIOTimeout)); err != nil {
			return err
		}
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		session.Stdin = bytes.NewReader(stdin)
		session.Stdout = stdout
		session.Stderr = stderr
		if err := session.Run(command); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		return nil
	}
}

func boundedDeadline(ctx context.Context, maximum time.Duration) time.Time {
	deadline := time.Now().Add(maximum)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func parseRemoteResponse(data []byte) (RawSnapshot, error) {
	var response struct {
		Version   int           `json:"version"`
		AsOf      string        `json:"as_of"`
		Providers []RawProvider `json:"providers"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return RawSnapshot{}, errors.New("remote usage response was invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || response.Version != 1 {
		return RawSnapshot{}, errors.New("remote usage response had an unsupported shape")
	}
	return RawSnapshot{AsOf: response.AsOf, Providers: response.Providers}, nil
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buffer.Write(data)
	}
	if original > remaining {
		b.overflow = true
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }
