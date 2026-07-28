package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	workconfig "github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
)

const ConfigSchemaVersion = 2

type Config struct {
	SchemaVersion           int      `json:"schema_version"`
	LocalDirectory          string   `json:"local_directory"`
	OffHostDirectory        string   `json:"off_host_directory"`
	RequireRemoteFilesystem bool     `json:"require_remote_filesystem"`
	EncryptionKey           string   `json:"encryption_key_file"`
	MetricsFile             string   `json:"metrics_file"`
	RetentionCount          int      `json:"retention_count"`
	AdditionalSources       []Source `json:"additional_sources"`
}

func LoadConfig(path string) (Config, error) {
	if !cleanAbsolute(path) {
		return Config{}, errors.New("backup configuration path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, errors.New("backup configuration is missing or unsafe")
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1024*1024 ||
		info.Mode().Perm() != 0o600 || !statOK || stat.Uid != 0 || stat.Gid != 0 {
		return Config{}, errors.New("backup configuration is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	var value Config
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("decode backup configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("backup configuration must contain one JSON value")
	}
	if err := value.Validate(); err != nil {
		return Config{}, err
	}
	return value, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("backup schema_version must be %d", ConfigSchemaVersion)
	}
	for name, value := range map[string]string{"local_directory": c.LocalDirectory, "off_host_directory": c.OffHostDirectory, "encryption_key_file": c.EncryptionKey, "metrics_file": c.MetricsFile} {
		if !cleanAbsolute(value) {
			return fmt.Errorf("backup %s must be a clean absolute path", name)
		}
	}
	if c.LocalDirectory == c.OffHostDirectory || pathWithin(c.LocalDirectory, c.OffHostDirectory) || pathWithin(c.OffHostDirectory, c.LocalDirectory) {
		return errors.New("local and off-host backup directories must be distinct and non-nested")
	}
	if !c.RequireRemoteFilesystem {
		return errors.New("backup require_remote_filesystem must be true")
	}
	if c.RetentionCount < 2 || c.RetentionCount > 365 {
		return errors.New("backup retention_count must be between 2 and 365")
	}
	if len(c.AdditionalSources) > 64 {
		return errors.New("backup has too many additional sources")
	}
	if len(c.AdditionalSources) != 0 {
		if err := validateSources(c.AdditionalSources); err != nil {
			return fmt.Errorf("validate additional backup sources: %w", err)
		}
	}
	for _, source := range c.AdditionalSources {
		if pathsOverlap(source.Path, "/etc/credstore.encrypted") || pathsOverlap(source.Path, "/var/lib/systemd/credential.secret") {
			return errors.New("host-bound systemd credentials and their host key must not be included in application backups")
		}
		if pathsOverlap(source.Path, workconfig.CLIProxyAuthDirectory) {
			return errors.New("CLIProxy provider OAuth material must not be included in application backups")
		}
		for _, profile := range []string{"/var/lib/workagent/chatforward/chromium", "/var/cache/workagent/chatforward/chromium"} {
			if pathsOverlap(source.Path, profile) {
				return errors.New("ChatForward host-bound browser profile must not be included in application backups")
			}
		}
		if pathsOverlap(source.Path, c.EncryptionKey) {
			return errors.New("backup encryption key must not be included in a backup source")
		}
	}
	return nil
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

// pathWithin requires strict containment: candidate must lie inside root and
// must not be root itself.
func pathWithin(root, candidate string) bool {
	return fsutil.PathWithin(root, candidate) && filepath.Clean(root) != filepath.Clean(candidate)
}

func pathsOverlap(first, second string) bool {
	return first == second || pathWithin(first, second) || pathWithin(second, first)
}
