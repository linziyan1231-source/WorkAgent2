package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const generatedCredentialEntropyBytes = 48

var (
	installableCredentialNames = map[string]bool{
		"admin-master-password-hash": true,
		"chatforward-key":            true,
		"cliproxy-management-key":    true,
		"notifications-key":          true,
	}
	generatedCredentialNames = map[string]bool{
		"chatforward-key":         true,
		"cliproxy-management-key": true,
		"notifications-key":       true,
	}
	systemdCredsCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command("/usr/bin/systemd-creds", arguments...)
	}
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: workagent-secret <install|generate-install> [options]")
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(os.Args[2:])
	case "generate-install":
		err = generateInstall(os.Args[2:])
	default:
		fatal("usage: workagent-secret <install|generate-install> [options]")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func install(arguments []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "systemd credential name")
	inputPath := flags.String("input-file", "", "protected plaintext input file")
	storeRoot := flags.String("credential-store", "/etc/credstore.encrypted/workagent", "encrypted credential directory")
	rotate := flags.Bool("rotate", false, "atomically replace an existing encrypted credential")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("install accepts no positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("credential installation must run as root")
	}
	if !installableCredentialNames[*name] {
		return errors.New("credential name is not in the installation allowlist")
	}
	plaintext, err := readProtectedInput(*inputPath)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	target, err := installEncryptedCredential(*name, *storeRoot, *rotate, plaintext)
	if err != nil {
		return err
	}
	return writeInstallResult(os.Stdout, target)
}

func generateInstall(arguments []string) error {
	flags := flag.NewFlagSet("generate-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "generated systemd credential name")
	storeRoot := flags.String("credential-store", "/etc/credstore.encrypted/workagent", "encrypted credential directory")
	rotate := flags.Bool("rotate", false, "atomically replace an existing encrypted credential")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate-install accepts no positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("credential generation and installation must run as root")
	}
	if !generatedCredentialNames[*name] {
		return errors.New("generated credential name is not in the internal allowlist")
	}
	if err := verifyStore(*storeRoot); err != nil {
		return err
	}
	plaintext, err := generateCredential()
	if err != nil {
		return err
	}
	defer clear(plaintext)
	target, err := installEncryptedCredential(*name, *storeRoot, *rotate, plaintext)
	if err != nil {
		return err
	}
	return writeInstallResult(os.Stdout, target)
}

func generateCredential() ([]byte, error) {
	raw := make([]byte, generatedCredentialEntropyBytes)
	if _, err := rand.Read(raw); err != nil {
		clear(raw)
		return nil, errors.New("secure random credential generation failed")
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	clear(raw)
	return encoded, nil
}

func installEncryptedCredential(name, storeRoot string, rotate bool, plaintext []byte) (string, error) {
	if err := verifyStore(storeRoot); err != nil {
		return "", err
	}
	return encryptCredential(name, storeRoot, rotate, plaintext)
}

func encryptCredential(name, storeRoot string, rotate bool, plaintext []byte) (string, error) {
	if !installableCredentialNames[name] {
		return "", errors.New("credential name is not in the installation allowlist")
	}
	if storeRoot == "" || !filepath.IsAbs(storeRoot) || filepath.Clean(storeRoot) != storeRoot || storeRoot == string(filepath.Separator) {
		return "", errors.New("credential store must be a clean absolute path")
	}
	if len(plaintext) < 1 || len(plaintext) > 64*1024 {
		return "", errors.New("credential plaintext size is invalid")
	}
	target := filepath.Join(storeRoot, name+".cred")
	if filepath.Dir(target) != storeRoot {
		return "", errors.New("credential target escapes its store")
	}
	if info, err := os.Lstat(target); err == nil {
		if !rotate {
			return "", errors.New("encrypted credential already exists; use --rotate to replace it")
		}
		stat, ownerOK := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ownerOK || stat.Uid != 0 {
			return "", errors.New("existing encrypted credential is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	temporary, err := os.CreateTemp(storeRoot, ".credential-*.partial")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", err
	}
	// Host-bound encryption is intentional. These ciphertexts are operational
	// credentials for this OS installation, not cross-host backup material.
	// Blank-host recovery provisions fresh values instead of copying the host
	// credential secret or weakening encryption for portability.
	// A generated or supplied plaintext exists only in this process's memory and
	// is streamed over the child's stdin. It never enters argv, the environment,
	// a plaintext temporary file, or command output.
	command := systemdCredsCommand("encrypt", "--with-key=host", "--newline=no", "--name="+name, "-", temporaryPath)
	command.Stdin = bytes.NewReader(plaintext)
	if err := command.Run(); err != nil {
		// Never relay child output: a broken implementation could echo stdin.
		return "", fmt.Errorf("systemd credential encryption failed: %w (diagnostic redacted)", err)
	}
	info, err := os.Lstat(temporaryPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128*1024 {
		return "", errors.New("systemd credential encryption produced an unsafe file")
	}
	if err := os.Chmod(temporaryPath, 0o400); err != nil {
		return "", err
	}
	decrypt := systemdCredsCommand("decrypt", "--newline=no", "--name="+name, temporaryPath, "-")
	decrypted, err := decrypt.Output()
	defer clear(decrypted)
	if err != nil {
		return "", errors.New("encrypted credential failed read-back verification")
	}
	if len(decrypted) != len(plaintext) || subtle.ConstantTimeCompare(decrypted, plaintext) != 1 {
		return "", errors.New("encrypted credential read-back did not match its input")
	}
	file, err := os.Open(temporaryPath)
	if err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return "", err
	}
	directory, err := os.Open(storeRoot)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return "", err
	}
	return target, nil
}

func writeInstallResult(writer io.Writer, target string) error {
	return json.NewEncoder(writer).Encode(map[string]any{"installed": true, "path": target})
}

func readProtectedInput(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("--input-file must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64*1024 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential input is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("credential input must be owned by root")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("credential input could not be read")
	}
	return payload, nil
}

func verifyStore(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("credential store must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("credential store is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("credential store must be owned by root")
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "workagent-secret:", sanitizeDiagnostic(message))
	os.Exit(1)
}

func sanitizeDiagnostic(message string) string {
	message = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(message))
	characters := []rune(message)
	if len(characters) > 512 {
		message = string(characters[:512])
	}
	if message == "" {
		message = "operation failed"
	}
	return message
}
