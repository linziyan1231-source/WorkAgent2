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
	if !filepath.IsAbs(pointerPath) || !filepath.IsAbs(releasesRoot) {
		return Verified{}, errors.New("release pointer and root must be absolute")
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
	manifestPath := filepath.Join(releasePath, ManifestName)
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
	for _, critical := range []string{
		"aionui-web.exe",
		"package.json",
		"static/index.html",
		"bundled-aioncore/win32-x64/aioncore.exe",
		"workagent-builtin-assistants/assistants.json",
		"workagent-builtin-assistants/rules/aionui-assistant.en-US.md",
		"workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md",
		"workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md",
	} {
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
		full := filepath.Join(releasePath, filepath.FromSlash(name))
		info, err := os.Lstat(full)
		if err != nil {
			return Verified{}, fmt.Errorf("release file %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Size {
			return Verified{}, fmt.Errorf("release file %s has unexpected type or size", name)
		}
		hash, err := hashFile(full)
		if err != nil {
			return Verified{}, err
		}
		if !strings.EqualFold(hash, entry.SHA256) {
			return Verified{}, fmt.Errorf("release file hash mismatch: %s", name)
		}
	}
	return Verified{Path: releasePath, Manifest: manifest}, nil
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
