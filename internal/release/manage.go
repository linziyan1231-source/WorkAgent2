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

func Install(source, releasesRoot, version, aionCoreVersion string, supportedAionCore []string) (verified Verified, err error) {
	if !filepath.IsAbs(source) || !filepath.IsAbs(releasesRoot) {
		return Verified{}, errors.New("release source and destination root must be absolute")
	}
	if !validVersion(version) || !contains(supportedAionCore, aionCoreVersion) {
		return Verified{}, errors.New("invalid release version or unsupported aioncore version")
	}
	if err := os.MkdirAll(releasesRoot, 0o755); err != nil {
		return Verified{}, err
	}
	destination := filepath.Join(releasesRoot, version)
	if _, statErr := os.Stat(destination); statErr == nil {
		existing, err := VerifyReleasePath(destination, version, supportedAionCore)
		if err != nil {
			return Verified{}, err
		}
		if existing.Manifest.AionCoreVersion != aionCoreVersion {
			return Verified{}, fmt.Errorf("existing immutable release %s uses aioncore %s, not requested %s", version, existing.Manifest.AionCoreVersion, aionCoreVersion)
		}
		sourceManifest, err := BuildManifest(source, version, aionCoreVersion)
		if err != nil {
			return Verified{}, fmt.Errorf("hash existing-version source: %w", err)
		}
		if !sameFiles(existing.Manifest.Files, sourceManifest.Files) {
			return Verified{}, fmt.Errorf("existing immutable release %s differs from the supplied source; use a new version", version)
		}
		return existing, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return Verified{}, statErr
	}
	staging, err := os.MkdirTemp(releasesRoot, ".staging-"+version+"-")
	if err != nil {
		return Verified{}, err
	}
	removeStaging := true
	defer func() {
		if removeStaging {
			root, _ := filepath.Abs(releasesRoot)
			candidate, _ := filepath.Abs(staging)
			if isWithin(root, candidate) && strings.HasPrefix(filepath.Base(candidate), ".staging-") {
				_ = os.RemoveAll(candidate)
			}
		}
	}()
	if err := copyRelease(source, staging); err != nil {
		return Verified{}, err
	}
	manifest, err := BuildManifest(staging, version, aionCoreVersion)
	if err != nil {
		return Verified{}, err
	}
	if _, err := WriteManifest(filepath.Join(staging, ManifestName), manifest); err != nil {
		return Verified{}, err
	}
	verified, err = VerifyReleasePath(staging, version, supportedAionCore)
	if err != nil {
		return Verified{}, err
	}
	if err := os.Rename(staging, destination); err != nil {
		return Verified{}, fmt.Errorf("atomically install immutable release: %w", err)
	}
	removeStaging = false
	verified.Path = destination
	return verified, nil
}

func VerifyReleasePath(releasePath, expectedVersion string, supportedAionCore []string) (Verified, error) {
	if !filepath.IsAbs(releasePath) || !validVersion(expectedVersion) {
		return Verified{}, errors.New("invalid release path or version")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(releasePath, ManifestName))
	if err != nil {
		return Verified{}, fmt.Errorf("read release manifest: %w", err)
	}
	var manifest Manifest
	if err := strictJSON(manifestBytes, &manifest); err != nil {
		return Verified{}, err
	}
	if manifest.FormatVersion != 1 || manifest.Version != expectedVersion || !contains(supportedAionCore, manifest.AionCoreVersion) || len(manifest.Files) == 0 {
		return Verified{}, errors.New("release manifest metadata is invalid or unsupported")
	}
	for _, critical := range []string{"aionui-web.exe", "package.json", "static/index.html", "bundled-aioncore/win32-x64/aioncore.exe"} {
		if _, ok := manifest.Files[critical]; !ok {
			return Verified{}, fmt.Errorf("release manifest is missing critical file %s", critical)
		}
	}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := manifest.Files[name]
		if !validRelative(name) || len(entry.SHA256) != 64 || entry.Size < 0 {
			return Verified{}, fmt.Errorf("invalid release manifest entry %q", name)
		}
		path := filepath.Join(releasePath, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return Verified{}, fmt.Errorf("release file %s has unexpected type or size: %w", name, err)
		}
		hash, err := hashFile(path)
		if err != nil || !strings.EqualFold(hash, entry.SHA256) {
			return Verified{}, fmt.Errorf("release file hash mismatch: %s", name)
		}
	}
	return Verified{Path: releasePath, Manifest: manifest}, nil
}

func Activate(verified Verified, currentPointerPath, previousPointerPath string) error {
	if !filepath.IsAbs(currentPointerPath) || !filepath.IsAbs(previousPointerPath) || currentPointerPath == previousPointerPath {
		return errors.New("current and previous release pointer paths must be distinct and absolute")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(verified.Path, ManifestName))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(manifestBytes)
	pointer := Pointer{FormatVersion: 1, Version: verified.Manifest.Version, ReleasePath: verified.Path, ManifestSHA256: hex.EncodeToString(sum[:])}
	if existing, err := os.ReadFile(currentPointerPath); err == nil {
		var old Pointer
		if err := strictJSON(existing, &old); err != nil {
			return fmt.Errorf("current release pointer is invalid; refusing to overwrite: %w", err)
		}
		if old.Version != pointer.Version || !strings.EqualFold(old.ReleasePath, pointer.ReleasePath) {
			if err := atomicWrite(previousPointerPath, existing); err != nil {
				return fmt.Errorf("preserve previous release pointer: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, _ := json.MarshalIndent(pointer, "", "  ")
	return atomicWrite(currentPointerPath, append(data, '\n'))
}

func Rollback(currentPointerPath, previousPointerPath, releasesRoot string, supportedAionCore []string) (Verified, error) {
	currentBytes, err := os.ReadFile(currentPointerPath)
	if err != nil {
		return Verified{}, err
	}
	previousBytes, err := os.ReadFile(previousPointerPath)
	if err != nil {
		return Verified{}, errors.New("no previous release pointer is available")
	}
	var previous Pointer
	if err := strictJSON(previousBytes, &previous); err != nil {
		return Verified{}, fmt.Errorf("previous release pointer is invalid: %w", err)
	}
	verified, err := VerifyCurrent(previousPointerPath, releasesRoot, supportedAionCore)
	if err != nil {
		return Verified{}, fmt.Errorf("previous release failed integrity verification: %w", err)
	}
	if err := atomicWrite(currentPointerPath, previousBytes); err != nil {
		return Verified{}, err
	}
	if err := atomicWrite(previousPointerPath, currentBytes); err != nil {
		return Verified{}, fmt.Errorf("current pointer switched but reverse history update failed: %w", err)
	}
	return verified, nil
}

func copyRelease(source, destination string) error {
	source, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("release source contains a symlink: %s", path)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("release source path escaped its root")
		}
		if relative == "." {
			return nil
		}
		if filepath.Base(path) == ManifestName {
			return nil
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("release source contains a non-regular file: %s", path)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
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

func validVersion(version string) bool {
	if version == "" || version == "." || version == ".." || len(version) > 128 {
		return false
	}
	for _, character := range version {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') &&
			character != '.' && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func sameFiles(left, right map[string]File) bool {
	if len(left) != len(right) {
		return false
	}
	for name, expected := range left {
		actual, ok := right[name]
		if !ok || actual.Size != expected.Size || !strings.EqualFold(actual.SHA256, expected.SHA256) {
			return false
		}
	}
	return true
}
