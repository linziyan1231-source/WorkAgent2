package release

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

const ManifestName = "release-manifest.json"

type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	FormatVersion   int             `json:"format_version"`
	Version         string          `json:"version"`
	AionCoreVersion string          `json:"aioncore_version"`
	Files           map[string]File `json:"files"`
}

type Pointer struct {
	FormatVersion  int    `json:"format_version"`
	Version        string `json:"version"`
	ReleasePath    string `json:"release_path"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type Verified struct {
	Path     string
	Manifest Manifest
}

func VerifyCurrent(pointerPath, releasesRoot string, supportedAionCore []string) (Verified, error) {
	verified, err := loadCurrentMetadata(pointerPath, releasesRoot, supportedAionCore)
	if err != nil {
		return Verified{}, err
	}
	seen := make(map[string]bool, len(verified.Manifest.Files))
	err = filepath.WalkDir(verified.Path, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			return fmt.Errorf("release contains a reparse point: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(verified.Path, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == ManifestName {
			return nil
		}
		expected, ok := verified.Manifest.Files[name]
		if !ok {
			return fmt.Errorf("release contains an unmanifested file: %s", name)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() != expected.Size {
			return fmt.Errorf("release file %s has unexpected type or size", name)
		}
		hash, err := hashFile(path)
		if err != nil || !strings.EqualFold(hash, expected.SHA256) {
			return fmt.Errorf("release file hash mismatch: %s", name)
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return Verified{}, err
	}
	if len(seen) != len(verified.Manifest.Files) {
		missing := make([]string, 0)
		for name := range verified.Manifest.Files {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return Verified{}, fmt.Errorf("release is missing manifested file %s", missing[0])
	}
	return verified, nil
}

// VerifyCurrentFast validates the protected pointer and manifest, then checks
// that each executable or bootstrap-critical file still has the manifested
// type and size. Full content hashing remains an install/activation/readiness
// gate; this bounded check is for ordinary per-user cold starts.
func VerifyCurrentFast(pointerPath, releasesRoot string, supportedAionCore []string) (Verified, error) {
	verified, err := loadCurrentMetadata(pointerPath, releasesRoot, supportedAionCore)
	if err != nil {
		return Verified{}, err
	}
	for _, name := range criticalFiles() {
		entry := verified.Manifest.Files[name]
		full := filepath.Join(verified.Path, filepath.FromSlash(name))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return Verified{}, fmt.Errorf("release critical file is missing or has the wrong type or size: %s", name)
		}
		if err := ensureNoReparsePath(verified.Path, full); err != nil {
			return Verified{}, fmt.Errorf("release critical file is a reparse point: %s", name)
		}
	}
	return verified, nil
}

func loadCurrentMetadata(pointerPath, releasesRoot string, supportedAionCore []string) (Verified, error) {
	if !filepath.IsAbs(pointerPath) || !filepath.IsAbs(releasesRoot) {
		return Verified{}, errors.New("release pointer and root must be absolute")
	}
	if reparse, err := isReparsePoint(pointerPath); err != nil || reparse {
		return Verified{}, errors.New("current release pointer is a reparse point or cannot be inspected")
	}
	b, err := os.ReadFile(pointerPath)
	if err != nil {
		return Verified{}, fmt.Errorf("read current release pointer: %w", err)
	}
	var p Pointer
	if err := strictJSON(b, &p); err != nil {
		return Verified{}, fmt.Errorf("decode current release pointer: %w", err)
	}
	if p.FormatVersion != 1 || p.Version == "" || !filepath.IsAbs(p.ReleasePath) || len(p.ManifestSHA256) != 64 {
		return Verified{}, errors.New("invalid current release pointer")
	}
	root, err := filepath.Abs(releasesRoot)
	if err != nil {
		return Verified{}, err
	}
	releasePath, err := filepath.Abs(p.ReleasePath)
	if err != nil {
		return Verified{}, err
	}
	if !isWithin(root, releasePath) || strings.Contains(p.Version, "\\") || strings.Contains(p.Version, "/") || filepath.Base(releasePath) != p.Version {
		return Verified{}, errors.New("release pointer escapes releases root or has a mismatched version")
	}
	if reparse, err := isReparsePoint(releasePath); err != nil || reparse {
		return Verified{}, errors.New("release directory is a reparse point or cannot be inspected")
	}
	manifestPath := filepath.Join(releasePath, ManifestName)
	if reparse, err := isReparsePoint(manifestPath); err != nil || reparse {
		return Verified{}, errors.New("release manifest is a reparse point or cannot be inspected")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Verified{}, fmt.Errorf("read release manifest: %w", err)
	}
	sum := sha256.Sum256(manifestBytes)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), p.ManifestSHA256) {
		return Verified{}, errors.New("release manifest hash does not match current pointer")
	}
	var manifest Manifest
	if err := strictJSON(manifestBytes, &manifest); err != nil {
		return Verified{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if manifest.FormatVersion != 1 || manifest.Version != p.Version || len(manifest.Files) == 0 {
		return Verified{}, errors.New("invalid release manifest metadata")
	}
	if !contains(supportedAionCore, manifest.AionCoreVersion) {
		return Verified{}, fmt.Errorf("unsupported aioncore version %q", manifest.AionCoreVersion)
	}
	for _, critical := range criticalFiles() {
		if _, ok := manifest.Files[critical]; !ok {
			return Verified{}, fmt.Errorf("release manifest is missing critical file %s", critical)
		}
	}
	paths := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		entry := manifest.Files[name]
		if !validRelative(name) || len(entry.SHA256) != 64 || entry.Size < 0 {
			return Verified{}, fmt.Errorf("invalid release manifest entry %q", name)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return Verified{}, fmt.Errorf("invalid release manifest hash %q", name)
		}
	}
	return Verified{Path: releasePath, Manifest: manifest}, nil
}

func criticalFiles() []string {
	return []string{
		"aionui-web.exe",
		"package.json",
		"static/index.html",
		"bundled-aioncore/win32-x64/aioncore.exe",
		"workagent-builtin-assistants/assistants.json",
		"workagent-builtin-assistants/rules/aionui-assistant.en-US.md",
		"workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md",
		"workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md",
	}
}

func BuildManifest(root, version, aionCoreVersion string) (Manifest, error) {
	if !filepath.IsAbs(root) || version == "" || aionCoreVersion == "" {
		return Manifest{}, errors.New("absolute root, version, and aioncore version are required")
	}
	m := Manifest{FormatVersion: 1, Version: version, AionCoreVersion: aionCoreVersion, Files: map[string]File{}}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("release may not contain symlink: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestName {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release contains non-regular file: %s", rel)
		}
		hash, err := hashFile(path)
		if err != nil {
			return err
		}
		m.Files[rel] = File{SHA256: hash, Size: info.Size()}
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func WriteManifest(path string, manifest Manifest) (string, error) {
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func strictJSON(b []byte, target any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func isWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validRelative(name string) bool {
	if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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

func ensureNoReparsePath(root, path string) error {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path escapes release root")
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		reparse, err := isReparsePoint(current)
		if err != nil {
			return err
		}
		if reparse {
			return errors.New("path contains a reparse point")
		}
	}
	return nil
}
