package agentcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	RootDirectoryName = "AionAgentCliShared"
	ManifestName      = "release-manifest.json"
	CurrentName       = "current.json"
	PreviousName      = "previous.json"

	CodexRelativePath = "codex/vendor/x86_64-pc-windows-msvc/bin/codex.exe"
	KimiRelativePath  = "kimi-bin/kimi.exe"
)

type File struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion int             `json:"format_version"`
	ReleaseID     string          `json:"release_id"`
	CodexVersion  string          `json:"codex_version"`
	KimiVersion   string          `json:"kimi_version"`
	PythonVersion string          `json:"python_version"`
	Files         map[string]File `json:"files"`
}

type Pointer struct {
	FormatVersion  int    `json:"format_version"`
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	CodexVersion   string `json:"codex_version"`
	KimiVersion    string `json:"kimi_version"`
	PythonVersion  string `json:"python_version"`
}

type Verified struct {
	Path     string
	Manifest Manifest
}

func RootFromAionReleases(aionReleasesRoot string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Clean(aionReleasesRoot))), RootDirectoryName)
}

func BinFromAionReleases(aionReleasesRoot string) string {
	return filepath.Join(RootFromAionReleases(aionReleasesRoot), "bin")
}

func BuildManifest(releasePath, releaseID, codexVersion, kimiVersion, pythonVersion string) (Manifest, error) {
	if err := validateReleasePath(releasePath, releaseID); err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{FormatVersion: 1, ReleaseID: releaseID, CodexVersion: codexVersion, KimiVersion: kimiVersion,
		PythonVersion: pythonVersion, Files: make(map[string]File)}
	if !validVersion(codexVersion) || !validVersion(kimiVersion) || !validVersion(pythonVersion) {
		return Manifest{}, errors.New("agent CLI and Python versions contain unsupported characters")
	}
	err := filepath.WalkDir(releasePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			return fmt.Errorf("agent CLI release contains a reparse point: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(releasePath, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == ManifestName {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !validRelative(name) {
			return fmt.Errorf("agent CLI release contains an invalid file: %s", path)
		}
		hash, err := hashFile(path)
		if err != nil {
			return err
		}
		manifest.Files[name] = File{Size: info.Size(), SHA256: hash}
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func WriteManifest(releasePath string, manifest Manifest) (string, error) {
	if err := validateReleasePath(releasePath, manifest.ReleaseID); err != nil {
		return "", err
	}
	if err := validateManifest(manifest); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := atomicWrite(filepath.Join(releasePath, ManifestName), data); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func Activate(root, releaseID string) (Verified, error) {
	verified, err := VerifyRelease(root, releaseID)
	if err != nil {
		return Verified{}, err
	}
	manifestBytes, err := os.ReadFile(filepath.Join(verified.Path, ManifestName))
	if err != nil {
		return Verified{}, err
	}
	sum := sha256.Sum256(manifestBytes)
	pointer := Pointer{FormatVersion: 1, ReleaseID: releaseID, ManifestSHA256: hex.EncodeToString(sum[:]),
		CodexVersion: verified.Manifest.CodexVersion, KimiVersion: verified.Manifest.KimiVersion, PythonVersion: verified.Manifest.PythonVersion}
	currentPath := filepath.Join(root, CurrentName)
	previousPath := filepath.Join(root, PreviousName)
	if existing, err := os.ReadFile(currentPath); err == nil {
		var current Pointer
		if err := strictJSON(existing, &current); err != nil {
			return Verified{}, fmt.Errorf("current agent CLI pointer is invalid; refusing to overwrite: %w", err)
		}
		if current.ReleaseID != pointer.ReleaseID {
			if err := atomicWrite(previousPath, existing); err != nil {
				return Verified{}, fmt.Errorf("preserve previous agent CLI pointer: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Verified{}, err
	}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return Verified{}, err
	}
	if err := atomicWrite(currentPath, append(data, '\n')); err != nil {
		return Verified{}, err
	}
	return verified, nil
}

func VerifyCurrent(root string) (Verified, error) {
	pointer, _, err := loadPointer(root)
	if err != nil {
		return Verified{}, err
	}
	verified, err := VerifyRelease(root, pointer.ReleaseID)
	if err != nil {
		return Verified{}, err
	}
	if err := pointerMatchesManifest(pointer, verified.Manifest, filepath.Join(verified.Path, ManifestName)); err != nil {
		return Verified{}, err
	}
	return verified, nil
}

func VerifyRelease(root, releaseID string) (Verified, error) {
	if !filepath.IsAbs(root) || !validVersion(releaseID) {
		return Verified{}, errors.New("agent CLI root must be absolute and release ID must be valid")
	}
	releasePath := filepath.Join(filepath.Clean(root), "releases", releaseID)
	if err := validateReleasePath(releasePath, releaseID); err != nil {
		return Verified{}, err
	}
	manifest, _, err := loadManifest(releasePath)
	if err != nil {
		return Verified{}, err
	}
	if manifest.ReleaseID != releaseID {
		return Verified{}, errors.New("agent CLI release directory and manifest IDs do not match")
	}
	seen := make(map[string]bool, len(manifest.Files))
	err = filepath.WalkDir(releasePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			return fmt.Errorf("agent CLI release contains a reparse point: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(releasePath, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == ManifestName {
			return nil
		}
		expected, ok := manifest.Files[name]
		if !ok {
			return fmt.Errorf("agent CLI release contains an unmanifested file: %s", name)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() != expected.Size {
			return fmt.Errorf("agent CLI release file has unexpected type or size: %s", name)
		}
		hash, err := hashFile(path)
		if err != nil || !strings.EqualFold(hash, expected.SHA256) {
			return fmt.Errorf("agent CLI release file hash mismatch: %s", name)
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return Verified{}, err
	}
	if len(seen) != len(manifest.Files) {
		missing := make([]string, 0)
		for name := range manifest.Files {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return Verified{}, fmt.Errorf("agent CLI release is missing manifested file %s", missing[0])
	}
	return Verified{Path: releasePath, Manifest: manifest}, nil
}

func loadCurrentFast(root string) (Verified, error) {
	pointer, _, err := loadPointer(root)
	if err != nil {
		return Verified{}, err
	}
	releasePath := filepath.Join(filepath.Clean(root), "releases", pointer.ReleaseID)
	if err := validateReleasePath(releasePath, pointer.ReleaseID); err != nil {
		return Verified{}, err
	}
	manifest, _, err := loadManifest(releasePath)
	if err != nil {
		return Verified{}, err
	}
	if err := pointerMatchesManifest(pointer, manifest, filepath.Join(releasePath, ManifestName)); err != nil {
		return Verified{}, err
	}
	for _, name := range []string{CodexRelativePath, KimiRelativePath} {
		entry := manifest.Files[name]
		path := filepath.Join(releasePath, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return Verified{}, fmt.Errorf("agent CLI critical file is missing or has the wrong size: %s", name)
		}
		if reparse, err := isReparsePoint(path); err != nil || reparse {
			return Verified{}, fmt.Errorf("agent CLI critical file is a reparse point: %s", name)
		}
	}
	return Verified{Path: releasePath, Manifest: manifest}, nil
}

func loadPointer(root string) (Pointer, []byte, error) {
	if !filepath.IsAbs(root) {
		return Pointer{}, nil, errors.New("agent CLI root must be absolute")
	}
	path := filepath.Join(filepath.Clean(root), CurrentName)
	if reparse, err := isReparsePoint(path); err != nil {
		return Pointer{}, nil, err
	} else if reparse {
		return Pointer{}, nil, errors.New("agent CLI current pointer is a reparse point")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Pointer{}, nil, fmt.Errorf("read agent CLI current pointer: %w", err)
	}
	var pointer Pointer
	if err := strictJSON(data, &pointer); err != nil {
		return Pointer{}, nil, err
	}
	if pointer.FormatVersion != 1 || !validVersion(pointer.ReleaseID) || len(pointer.ManifestSHA256) != 64 ||
		!validVersion(pointer.CodexVersion) || !validVersion(pointer.KimiVersion) || !validVersion(pointer.PythonVersion) {
		return Pointer{}, nil, errors.New("agent CLI current pointer metadata is invalid")
	}
	if _, err := hex.DecodeString(pointer.ManifestSHA256); err != nil {
		return Pointer{}, nil, errors.New("agent CLI current pointer manifest hash is invalid")
	}
	return pointer, data, nil
}

func loadManifest(releasePath string) (Manifest, []byte, error) {
	path := filepath.Join(releasePath, ManifestName)
	if reparse, err := isReparsePoint(path); err != nil {
		return Manifest{}, nil, err
	} else if reparse {
		return Manifest{}, nil, errors.New("agent CLI manifest is a reparse point")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read agent CLI release manifest: %w", err)
	}
	var manifest Manifest
	if err := strictJSON(data, &manifest); err != nil {
		return Manifest{}, nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, err
	}
	return manifest, data, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.FormatVersion != 1 || !validVersion(manifest.ReleaseID) || !validVersion(manifest.CodexVersion) ||
		!validVersion(manifest.KimiVersion) || !validVersion(manifest.PythonVersion) || len(manifest.Files) == 0 {
		return errors.New("agent CLI release manifest metadata is invalid")
	}
	for _, critical := range []string{CodexRelativePath, KimiRelativePath} {
		if _, ok := manifest.Files[critical]; !ok {
			return fmt.Errorf("agent CLI release manifest is missing critical file %s", critical)
		}
	}
	for name, entry := range manifest.Files {
		if !validRelative(name) || entry.Size < 0 || len(entry.SHA256) != 64 {
			return fmt.Errorf("agent CLI release manifest entry is invalid: %q", name)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return fmt.Errorf("agent CLI release manifest hash is invalid: %q", name)
		}
	}
	return nil
}

func pointerMatchesManifest(pointer Pointer, manifest Manifest, manifestPath string) error {
	if pointer.ReleaseID != manifest.ReleaseID || pointer.CodexVersion != manifest.CodexVersion ||
		pointer.KimiVersion != manifest.KimiVersion || pointer.PythonVersion != manifest.PythonVersion {
		return errors.New("agent CLI pointer and release manifest metadata do not match")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(pointer.ManifestSHA256, hex.EncodeToString(sum[:])) {
		return errors.New("agent CLI release manifest hash does not match current pointer")
	}
	return nil
}

func validateReleasePath(releasePath, releaseID string) error {
	if !filepath.IsAbs(releasePath) || !validVersion(releaseID) || filepath.Base(filepath.Clean(releasePath)) != releaseID ||
		!strings.EqualFold(filepath.Base(filepath.Dir(filepath.Clean(releasePath))), "releases") {
		return errors.New("agent CLI release path does not match its release ID")
	}
	return nil
}

func validVersion(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') &&
			character != '.' && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validRelative(name string) bool {
	if name == "" || strings.Contains(name, "\\") || filepath.IsAbs(filepath.FromSlash(name)) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode agent CLI metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("agent CLI metadata contains multiple JSON values")
		}
		return err
	}
	return nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + fmt.Sprintf(".tmp-%d", os.Getpid())
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func isReparsePoint(path string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}
