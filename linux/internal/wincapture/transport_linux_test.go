//go:build linux

package wincapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSSHTransportValidationRequiresCanonicalIPv4AndEd25519(t *testing.T) {
	valid := validSSHTransport(t)
	if err := validateSSHTransport(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*SSHTransport)
	}{
		{name: "hostname", mutate: func(value *SSHTransport) { value.ConnectAddress = "windows.example.test" }},
		{name: "noncanonical-ipv4", mutate: func(value *SSHTransport) { value.ConnectAddress = "192.000.002.010" }},
		{name: "loopback", mutate: func(value *SSHTransport) { value.ConnectAddress = "127.0.0.1" }},
		{name: "ipv6", mutate: func(value *SSHTransport) { value.ConnectAddress = "2001:db8::1" }},
		{name: "algorithm-list", mutate: func(value *SSHTransport) { value.HostKeyAlgorithm = "ssh-ed25519,ssh-rsa" }},
		{name: "alias", mutate: func(value *SSHTransport) { value.HostKeyAlias = "windows.example.test" }},
		{name: "same-file", mutate: func(value *SSHTransport) { value.Identity.Path = value.KnownHosts.Path }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateSSHTransport(candidate); err == nil {
				t.Fatal("invalid SSH transport was accepted")
			}
		})
	}
}

func TestCaptureSpecRequiresSchemaV2TransportBinding(t *testing.T) {
	spec := validSpec(t)
	spec.SchemaVersion = 1
	if err := validateSpec(spec); err == nil {
		t.Fatal("schema-v1 capture spec was accepted")
	}
	spec.SchemaVersion = SpecSchemaVersion
	spec.SSHTransport = SSHTransport{}
	if err := validateSpec(spec); err == nil {
		t.Fatal("capture spec without an SSH transport binding was accepted")
	}
}

func TestSSHTransportProfileIsCanonicalPrivateAndContentPinned(t *testing.T) {
	binding := validSSHTransport(t)
	root := privateTemp(t)
	profilePath := filepath.Join(root, "ssh-transport.json")
	payload, err := marshalPrivateJSON(sshTransportProfile{SchemaVersion: sshTransportProfileSchemaVersion, SSHTransport: binding})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if err := os.WriteFile(profilePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSSHTransportProfile(profilePath, uint32(os.Geteuid()))
	if err != nil || loaded != binding {
		t.Fatalf("valid transport profile was rejected: %v", err)
	}

	if err := os.Chmod(profilePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSHTransportProfile(profilePath, uint32(os.Geteuid())); err == nil {
		t.Fatal("non-private transport profile was accepted")
	}
	if err := os.Chmod(profilePath, 0o600); err != nil {
		t.Fatal(err)
	}

	noncanonical := bytes.TrimSpace(payload)
	if err := os.WriteFile(profilePath, noncanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSHTransportProfile(profilePath, uint32(os.Geteuid())); err == nil {
		t.Fatal("non-canonical transport profile was accepted")
	}
}

func TestSSHTransportInputsRejectUnapprovedOrAmbiguousFiles(t *testing.T) {
	t.Run("approved-digest", func(t *testing.T) {
		binding := validSSHTransport(t)
		binding.Identity.SHA256 = strings.Repeat("f", 64)
		if err := verifySSHTransportInputs(binding, uint32(os.Geteuid())); err == nil {
			t.Fatal("unapproved identity bytes were accepted")
		}
	})
	t.Run("known-hosts-extra-record", func(t *testing.T) {
		binding := validSSHTransport(t)
		payload, err := os.ReadFile(binding.KnownHosts.Path)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, payload...)
		if err := os.WriteFile(binding.KnownHosts.Path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		binding.KnownHosts.SHA256 = hex.EncodeToString(digest[:])
		if err := verifySSHTransportInputs(binding, uint32(os.Geteuid())); err == nil {
			t.Fatal("multi-record known-hosts input was accepted")
		}
	})
	t.Run("known-hosts-hardlink", func(t *testing.T) {
		binding := validSSHTransport(t)
		if err := os.Link(binding.KnownHosts.Path, binding.KnownHosts.Path+".link"); err != nil {
			t.Fatal(err)
		}
		if err := verifySSHTransportInputs(binding, uint32(os.Geteuid())); err == nil {
			t.Fatal("hardlinked known-hosts input was accepted")
		}
	})
	t.Run("identity-trailing-data", func(t *testing.T) {
		binding := validSSHTransport(t)
		payload, err := os.ReadFile(binding.Identity.Path)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, []byte("unapproved trailing data\n")...)
		if err := os.WriteFile(binding.Identity.Path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		binding.Identity.SHA256 = hex.EncodeToString(digest[:])
		if err := verifySSHTransportInputs(binding, uint32(os.Geteuid())); err == nil {
			t.Fatal("identity with trailing data was accepted")
		}
	})
}

func TestBindRemoteSessionRejectsEmptyFactoryResult(t *testing.T) {
	engine := &captureEngine{
		expectedUID: uint32(os.Geteuid()),
		remoteFactory: func(SSHTransport, uint32) (remoteSession, error) {
			return nil, nil
		},
	}
	if run, err := engine.bindRemoteSession(validSSHTransport(t)); err == nil || run != nil || engine.remote != nil {
		t.Fatalf("empty SSH session was accepted: run=%#v remote=%#v err=%v", run, engine.remote, err)
	}
}

type trackingRemoteSession struct {
	remoteTransport
	verifyCalls int
	closeCalls  int
}

func (session *trackingRemoteSession) verify() error {
	session.verifyCalls++
	return nil
}

func (session *trackingRemoteSession) close() error {
	session.closeCalls++
	return nil
}

func TestBoundRemoteSessionUsesOneExactFactoryResultAndClosesOnce(t *testing.T) {
	binding := validSSHTransport(t)
	underlying := newFixtureTransport(t, validSpec(t))
	session := &trackingRemoteSession{remoteTransport: underlying}
	factoryCalls := 0
	expectedUID := uint32(os.Geteuid())
	engine := &captureEngine{
		expectedUID: expectedUID,
		remoteFactory: func(got SSHTransport, gotUID uint32) (remoteSession, error) {
			factoryCalls++
			if got != binding || gotUID != expectedUID {
				t.Fatalf("factory binding changed: %#v / %d", got, gotUID)
			}
			return session, nil
		},
	}
	run, err := engine.bindRemoteSession(binding)
	if err != nil || factoryCalls != 1 || engine.remote != session {
		t.Fatalf("bind result = %#v / calls=%d / remote=%#v / err=%v", run, factoryCalls, engine.remote, err)
	}
	if err := run.verify(); err != nil || session.verifyCalls != 1 {
		t.Fatalf("session verification was not exact: calls=%d err=%v", session.verifyCalls, err)
	}
	if err := run.close(); err != nil || session.closeCalls != 1 || engine.remote != nil {
		t.Fatalf("session close was not exact: calls=%d remote=%#v err=%v", session.closeCalls, engine.remote, err)
	}
	if err := run.close(); err != nil || session.closeCalls != 1 {
		t.Fatalf("session close was not idempotent: calls=%d err=%v", session.closeCalls, err)
	}
}

func TestSSHTransportSessionUsesSealedSnapshotsAndDetectsSourceDrift(t *testing.T) {
	binding := validSSHTransport(t)
	transport, err := newSSHTransport(binding, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	identitySnapshotPath := transport.identity.path
	if err := transport.verify(); err != nil {
		transport.close()
		t.Fatal(err)
	}
	if err := os.WriteFile(binding.Identity.Path, []byte("rotated\n"), 0o600); err != nil {
		transport.close()
		t.Fatal(err)
	}
	if err := transport.identity.verify(); err != nil {
		transport.close()
		t.Fatalf("sealed identity snapshot changed with its source: %v", err)
	}
	if err := transport.verify(); err == nil {
		transport.close()
		t.Fatal("source identity drift was accepted")
	}
	if err := transport.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Open(identitySnapshotPath); err == nil {
		t.Fatal("closed sealed identity remained reopenable")
	}
}

func TestSSHCommandEnvironmentIsMinimalAndNonInteractive(t *testing.T) {
	environment := sshCommandEnvironment()
	want := []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "SSH_ASKPASS_REQUIRE=never"}
	if !slices.Equal(environment, want) {
		t.Fatalf("SSH environment is not exact: %#v", environment)
	}
	for _, forbidden := range []string{"LD_PRELOAD", "SSH_AUTH_SOCK", "DISPLAY", "SSH_ASKPASS="} {
		for _, variable := range environment {
			if strings.HasPrefix(variable, forbidden) {
				t.Fatalf("SSH environment retained %s", forbidden)
			}
		}
	}
}
