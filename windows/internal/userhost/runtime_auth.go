package userhost

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

const workAgentRuntimeTokenBytes = 43

// stageRuntimeToken places one startup-only credential in the SID-private
// runtime directory. The WebHost must consume and delete it before listening.
func stageRuntimeToken(runtimeDir, token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	canonical := err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
	for index := range raw {
		raw[index] = 0
	}
	if !canonical {
		return "", errors.New("managed runtime token is not canonical")
	}
	info, err := os.Lstat(runtimeDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("managed runtime directory is not a regular directory")
	}
	file, err := os.CreateTemp(runtimeDir, ".workagent-runtime-*.token")
	if err != nil {
		return "", err
	}
	path := file.Name()
	remove := true
	defer func() {
		file.Close()
		if remove {
			os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.WriteString(token); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("managed runtime token path is not absolute")
	}
	remove = false
	return path, nil
}
