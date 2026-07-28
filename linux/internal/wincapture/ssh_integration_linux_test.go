//go:build linux

package wincapture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestOpenSSHAuthenticatesWithOnlySealedTransportInputs(t *testing.T) {
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSSHKey, err := ssh.NewPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	identityBlock, err := ssh.MarshalPrivateKey(clientPrivate, "workagent-capture-test")
	if err != nil {
		t.Fatal(err)
	}
	identityPayload := pem.EncodeToMemory(identityBlock)
	defer clear(identityPayload)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	alias := "workagent-windows-11111111111111111111111111111111"
	hostSSHKey, err := ssh.NewPublicKey(hostPublic)
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPayload := append([]byte(alias+" "), ssh.MarshalAuthorizedKey(hostSSHKey)...)
	defer clear(knownHostsPayload)
	binding := SSHTransport{
		ConnectAddress: "127.0.0.1", Port: port, User: "fixture", HostKeyAlias: alias, HostKeyAlgorithm: ssh.KeyAlgoED25519,
	}
	if err := validateDedicatedKnownHosts(knownHostsPayload, binding); err != nil {
		t.Fatal(err)
	}
	if err := validateSSHIdentity(identityPayload); err != nil {
		t.Fatal(err)
	}

	expectedUID := uint32(os.Geteuid())
	knownHosts, err := newSealedTransportFile("workagent-ssh-integration-known-hosts", knownHostsPayload, expectedUID)
	if err != nil {
		t.Fatal(err)
	}
	defer knownHosts.close()
	identity, err := newSealedTransportFile("workagent-ssh-integration-identity", identityPayload, expectedUID)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.close()

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != binding.User || !bytes.Equal(key.Marshal(), clientSSHKey.Marshal()) {
				return nil, errors.New("unexpected test client identity")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	serverResult := make(chan error, 1)
	remoteCommand := make(chan string, 1)
	remoteInput := make(chan string, 1)
	go serveOpenSSHIntegrationConnection(listener, serverConfig, remoteCommand, remoteInput, serverResult)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arguments := sshCommandArguments(binding, knownHosts.path, identity.path, "inventory", []string{"/c/fixture"})
	command := exec.CommandContext(ctx, "/usr/bin/ssh", arguments...)
	command.Dir = "/"
	command.Env = sshCommandEnvironment()
	command.Stdin = strings.NewReader("sealed-input-probe\n")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("fixed OpenSSH transport failed: %v (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	wantCommand := "/usr/bin/bash -s -- inventory " + fmt.Sprintf("%x", []byte("/c/fixture"))
	if got := <-remoteCommand; got != wantCommand {
		t.Fatalf("remote command = %q, want %q", got, wantCommand)
	}
	if got := <-remoteInput; got != "sealed-input-probe\n" {
		t.Fatalf("remote stdin = %q", got)
	}
}

func serveOpenSSHIntegrationConnection(listener net.Listener, config *ssh.ServerConfig, commandResult, inputResult chan<- string, result chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	defer connection.Close()
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		result <- err
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			result <- err
			return
		}
		for request := range channelRequests {
			if request.Type != "exec" {
				_ = request.Reply(false, nil)
				continue
			}
			var execRequest struct{ Command string }
			if err := ssh.Unmarshal(request.Payload, &execRequest); err != nil {
				_ = request.Reply(false, nil)
				channel.Close()
				result <- err
				return
			}
			if err := request.Reply(true, nil); err != nil {
				channel.Close()
				result <- err
				return
			}
			input, err := io.ReadAll(channel)
			if err != nil {
				channel.Close()
				result <- err
				return
			}
			commandResult <- execRequest.Command
			inputResult <- string(input)
			status := struct{ Status uint32 }{Status: 0}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&status))
			if err := channel.Close(); err != nil {
				result <- err
				return
			}
			// Let the real OpenSSH client observe the channel close and finish its
			// protocol shutdown before the test server closes the whole transport.
			// The mux reports the peer's final disconnect as an error by design;
			// command.Run above is the authoritative client-side success result.
			_ = server.Wait()
			result <- nil
			return
		}
		channel.Close()
		result <- errors.New("OpenSSH test client did not request a remote command on its session")
		return
	}
	result <- errors.New("OpenSSH test client did not open a session")
}

func TestSSHCommandUsesBoundPortAsDecimal(t *testing.T) {
	binding := SSHTransport{ConnectAddress: "192.0.2.10", Port: 2222, User: "fixture", HostKeyAlias: "workagent-windows-11111111111111111111111111111111", HostKeyAlgorithm: ssh.KeyAlgoED25519}
	arguments := sshCommandArguments(binding, "/dev/null", "/dev/null", "oauth", nil)
	for index := range len(arguments) - 1 {
		if arguments[index] == "-p" && arguments[index+1] == strconv.Itoa(binding.Port) {
			return
		}
	}
	t.Fatal("bound SSH port is absent")
}
