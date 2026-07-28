//go:build linux

package wincapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const (
	sshTransportProfileSchemaVersion = 1
	maximumTransportProfileBytes     = 64 * 1024
	maximumKnownHostsBytes           = 64 * 1024
	maximumIdentityBytes             = 1024 * 1024
	supportedHostKeyAlgorithm        = ssh.KeyAlgoED25519
)

var (
	sshUserPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+\\-]{0,127}$`)
	hostKeyAliasPattern  = regexp.MustCompile(`^workagent-windows-[0-9a-f]{32}$`)
	limitedBroadcastIPv4 = netip.MustParseAddr("255.255.255.255")
)

// sshTransportProfile is a canonical, root-private operator approval. Its
// hashes are supplied by the operator rather than silently learned from the
// files during spec initialization.
type sshTransportProfile struct {
	SchemaVersion int          `json:"schema_version"`
	SSHTransport  SSHTransport `json:"ssh_transport"`
}

type sshTransportInputPayloads struct {
	knownHosts []byte
	identity   []byte
}

func (payloads *sshTransportInputPayloads) clear() {
	clear(payloads.knownHosts)
	clear(payloads.identity)
}

func validateSSHTransport(binding SSHTransport) error {
	address, err := netip.ParseAddr(binding.ConnectAddress)
	if err != nil || !address.Is4() || address.String() != binding.ConnectAddress || !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsMulticast() || address.IsLinkLocalUnicast() || address == limitedBroadcastIPv4 {
		return errors.New("capture spec SSH connect address must be one canonical public or management IPv4 literal")
	}
	if binding.Port < 1 || binding.Port > 65535 || !sshUserPattern.MatchString(binding.User) {
		return errors.New("capture spec SSH port or user is invalid")
	}
	if !hostKeyAliasPattern.MatchString(binding.HostKeyAlias) || binding.HostKeyAlgorithm != supportedHostKeyAlgorithm {
		return errors.New("capture spec SSH host-key alias or algorithm is unsupported")
	}
	if err := validateTransportFileBinding(binding.KnownHosts, "known-hosts"); err != nil {
		return err
	}
	if err := validateTransportFileBinding(binding.Identity, "identity"); err != nil {
		return err
	}
	if binding.KnownHosts.Path == binding.Identity.Path {
		return errors.New("capture spec SSH transport files must be distinct")
	}
	return nil
}

func validateTransportFileBinding(binding TransportFileBinding, label string) error {
	if err := validateAbsoluteFilePath(binding.Path, "SSH "+label); err != nil || !sha256Pattern.MatchString(binding.SHA256) {
		return fmt.Errorf("capture spec SSH %s binding is invalid", label)
	}
	return nil
}

func loadSSHTransportProfile(filename string, expectedUID uint32) (SSHTransport, error) {
	var profile sshTransportProfile
	payload, _, err := readPrivateCanonicalJSON(filename, "SSH transport profile", maximumTransportProfileBytes, expectedUID, &profile)
	if err != nil {
		return SSHTransport{}, err
	}
	defer clear(payload)
	if profile.SchemaVersion != sshTransportProfileSchemaVersion {
		return SSHTransport{}, errors.New("private SSH transport profile schema is unsupported")
	}
	if err := validateSSHTransport(profile.SSHTransport); err != nil {
		return SSHTransport{}, err
	}
	if err := verifySSHTransportInputs(profile.SSHTransport, expectedUID); err != nil {
		return SSHTransport{}, err
	}
	return profile.SSHTransport, nil
}

func verifySSHTransportInputs(binding SSHTransport, expectedUID uint32) error {
	payloads, err := loadSSHTransportInputPayloads(binding, expectedUID)
	if err != nil {
		return err
	}
	payloads.clear()
	return nil
}

func loadSSHTransportInputPayloads(binding SSHTransport, expectedUID uint32) (sshTransportInputPayloads, error) {
	if err := validateSSHTransport(binding); err != nil {
		return sshTransportInputPayloads{}, err
	}
	knownHosts, err := readPrivateAbsoluteFile(binding.KnownHosts.Path, maximumKnownHostsBytes, expectedUID)
	if err != nil {
		return sshTransportInputPayloads{}, errors.New("read dedicated private SSH known-hosts input")
	}
	if sha256Bytes(knownHosts) != binding.KnownHosts.SHA256 || validateDedicatedKnownHosts(knownHosts, binding) != nil {
		clear(knownHosts)
		return sshTransportInputPayloads{}, errors.New("dedicated private SSH known-hosts input does not match its approved binding")
	}
	identity, err := readPrivateAbsoluteFile(binding.Identity.Path, maximumIdentityBytes, expectedUID)
	if err != nil {
		clear(knownHosts)
		return sshTransportInputPayloads{}, errors.New("read dedicated private SSH identity input")
	}
	if sha256Bytes(identity) != binding.Identity.SHA256 || validateSSHIdentity(identity) != nil {
		clear(knownHosts)
		clear(identity)
		return sshTransportInputPayloads{}, errors.New("dedicated private SSH identity input does not match its approved binding")
	}
	return sshTransportInputPayloads{knownHosts: knownHosts, identity: identity}, nil
}

func validateDedicatedKnownHosts(payload []byte, binding SSHTransport) error {
	marker, hosts, key, comment, rest, err := ssh.ParseKnownHosts(payload)
	if err != nil || marker != "" || len(hosts) != 1 || hosts[0] != binding.HostKeyAlias || comment != "" || len(rest) != 0 ||
		key == nil || key.Type() != binding.HostKeyAlgorithm {
		return errors.New("dedicated SSH known-hosts contract is invalid")
	}
	canonical := append([]byte(binding.HostKeyAlias+" "), ssh.MarshalAuthorizedKey(key)...)
	defer clear(canonical)
	if !bytes.Equal(payload, canonical) {
		return errors.New("dedicated SSH known-hosts input is not canonical")
	}
	return nil
}

func validateSSHIdentity(payload []byte) error {
	block, rest := pem.Decode(payload)
	if block == nil || len(rest) != 0 || len(block.Headers) != 0 {
		return errors.New("dedicated SSH identity must contain exactly one canonical PEM block")
	}
	canonical := pem.EncodeToMemory(block)
	defer clear(canonical)
	if !bytes.Equal(payload, canonical) {
		return errors.New("dedicated SSH identity must use canonical PEM encoding")
	}
	signer, err := ssh.ParsePrivateKey(payload)
	if err != nil || signer == nil || signer.PublicKey() == nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return errors.New("dedicated SSH identity must be one unencrypted Ed25519 private key")
	}
	return nil
}

// sshTransport owns immutable, sealed snapshots for one complete invocation.
// Every child reconnects independently but sees the same endpoint, host key,
// and client identity bytes. The mutable source files are revalidated before
// success evidence is admitted.
type sshTransport struct {
	binding     SSHTransport
	expectedUID uint32
	knownHosts  *sealedTransportFile
	identity    *sealedTransportFile
	mu          sync.Mutex
	closed      bool
}

type sealedTransportFile struct {
	file        *os.File
	path        string
	digest      string
	expectedUID uint32
}

func newSSHTransport(binding SSHTransport, expectedUID uint32) (*sshTransport, error) {
	payloads, err := loadSSHTransportInputPayloads(binding, expectedUID)
	if err != nil {
		return nil, err
	}
	defer payloads.clear()
	knownHosts, err := newSealedTransportFile("workagent-ssh-known-hosts", payloads.knownHosts, expectedUID)
	if err != nil {
		return nil, err
	}
	identity, err := newSealedTransportFile("workagent-ssh-identity", payloads.identity, expectedUID)
	if err != nil {
		knownHosts.close()
		return nil, err
	}
	result := &sshTransport{binding: binding, expectedUID: expectedUID, knownHosts: knownHosts, identity: identity}
	if err := result.verify(); err != nil {
		result.close()
		return nil, errors.New("private SSH transport inputs changed during session construction")
	}
	return result, nil
}

func newSealedTransportFile(name string, payload []byte, expectedUID uint32) (*sealedTransportFile, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errors.New("create immutable SSH transport input")
	}
	file := os.NewFile(uintptr(fd), name)
	fail := func(message string) (*sealedTransportFile, error) {
		file.Close()
		return nil, errors.New(message)
	}
	if err := file.Chmod(0o600); err != nil {
		return fail("secure immutable SSH transport input")
	}
	if written, err := file.Write(payload); err != nil || written != len(payload) {
		return fail("write immutable SSH transport input")
	}
	if err := file.Sync(); err != nil {
		return fail("sync immutable SSH transport input")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail("rewind immutable SSH transport input")
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return fail("seal immutable SSH transport input")
	}
	result := &sealedTransportFile{
		file: file, path: "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.Itoa(fd), digest: sha256Bytes(payload), expectedUID: expectedUID,
	}
	if err := result.verify(); err != nil {
		result.close()
		return nil, err
	}
	return result, nil
}

func (file *sealedTransportFile) verify() error {
	if file == nil || file.file == nil {
		return errors.New("immutable SSH transport input is unavailable")
	}
	seals, err := unix.FcntlInt(file.file.Fd(), unix.F_GET_SEALS, 0)
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var before unix.Stat_t
	if err != nil || seals&wantSeals != wantSeals || unix.Fstat(int(file.file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		os.FileMode(before.Mode).Perm() != 0o600 || before.Uid != file.expectedUID || before.Gid != file.expectedUID || before.Size < 1 {
		return errors.New("immutable SSH transport input contract is invalid")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file.file, 0, before.Size)); err != nil {
		return errors.New("read immutable SSH transport input")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.file.Fd()), &after); err != nil || !stableFileStat(before, after) || hex.EncodeToString(hasher.Sum(nil)) != file.digest {
		return errors.New("immutable SSH transport input changed")
	}
	probe, err := os.Open(file.path)
	if err != nil {
		return errors.New("immutable SSH transport input is not reopenable by SSH")
	}
	if err := probe.Close(); err != nil {
		return errors.New("close immutable SSH transport input probe")
	}
	return nil
}

func (file *sealedTransportFile) close() error {
	if file == nil || file.file == nil {
		return nil
	}
	err := file.file.Close()
	file.file = nil
	return err
}

func (transport *sshTransport) verify() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return errors.New("SSH transport session is already closed")
	}
	if err := transport.knownHosts.verify(); err != nil {
		return err
	}
	if err := transport.identity.verify(); err != nil {
		return err
	}
	if err := verifySSHTransportInputs(transport.binding, transport.expectedUID); err != nil {
		return errors.New("private SSH transport inputs drifted during the remote window")
	}
	return nil
}

func (transport *sshTransport) close() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return nil
	}
	transport.closed = true
	return errors.Join(transport.knownHosts.close(), transport.identity.close())
}
