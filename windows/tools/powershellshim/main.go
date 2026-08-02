package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	assetName = "aioncore-v0.1.42-x86_64-pc-windows-msvc.zip"
	assetHash = "2959b07558d597de7837a2c99c2cb642831680a7d64161afb128d082fce4b0df"
	assetSize = 27936769
)

func main() {
	if strings.Contains(strings.Join(os.Args[1:], " "), "Invoke-WebRequest") {
		if err := provideVerifiedAsset(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	command := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, os.Args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func provideVerifiedAsset() error {
	source := `C:\projects\WorkAgent2\.tools\downloads\` + assetName
	if err := verify(source); err != nil {
		return err
	}
	destinationDir := filepath.Join(os.TempDir(), "aioncore-prepare", "v0.1.42", "win32-x64")
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(destinationDir, assetName), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func verify(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != assetSize {
		return fmt.Errorf("verified AionCore asset has an unexpected size")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != assetHash {
		return fmt.Errorf("verified AionCore asset hash mismatch")
	}
	return nil
}
