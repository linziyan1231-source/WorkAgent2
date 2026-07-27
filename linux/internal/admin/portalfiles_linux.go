package admin

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

// VerifyPortalFiles enforces the Linux equivalent of the Windows service ACL
// baseline for the root-managed Portal configuration, policy and brand tree.
func VerifyPortalFiles(portal config.Portal, configPath string) error {
	if err := portal.ValidateProductionLayout(configPath); err != nil {
		return err
	}
	account, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return fmt.Errorf("lookup Portal account for configuration verification: %w", err)
	}
	runtimeGID, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || runtimeGID == 0 {
		return errors.New("Portal group is invalid")
	}
	root := filepath.Dir(configPath)
	if err := verifyPortalDirectoryTree(root, root, uint32(runtimeGID)); err != nil {
		return err
	}
	if err := verifyRuntimeReadableFile(configPath, 1024*1024, 0, uint32(runtimeGID), true); err != nil {
		return fmt.Errorf("Portal configuration protection: %w", err)
	}
	for label, path := range map[string]string{"policy": portal.PolicyFile, "brand": portal.BrandFile} {
		if err := verifyPortalDirectoryTree(root, filepath.Dir(path), uint32(runtimeGID)); err != nil {
			return fmt.Errorf("%s directory protection: %w", label, err)
		}
		if err := verifyRuntimeReadableFile(path, 1024*1024, 0, uint32(runtimeGID), false); err != nil {
			return fmt.Errorf("%s file protection: %w", label, err)
		}
	}
	brand, err := productconfig.LoadBrand(portal.BrandFile)
	if err != nil {
		return err
	}
	if _, err := productconfig.LoadPolicy(portal.PolicyFile); err != nil {
		return err
	}
	for _, name := range []string{"logo", "logo-dark", "favicon", "app-icon"} {
		path, ok := brand.AssetPath(name)
		if !ok {
			return fmt.Errorf("brand asset %s is unavailable", name)
		}
		if err := verifyPortalDirectoryTree(root, filepath.Dir(path), uint32(runtimeGID)); err != nil {
			return fmt.Errorf("brand asset %s directory protection: %w", name, err)
		}
		if err := verifyRuntimeReadableFile(path, 2*1024*1024, 0, uint32(runtimeGID), false); err != nil {
			return fmt.Errorf("brand asset %s protection: %w", name, err)
		}
	}
	return nil
}

func verifyPortalDirectoryTree(root, target string, runtimeGID uint32) error {
	root, target = filepath.Clean(root), filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Portal product file is outside the protected configuration tree")
	}
	current := root
	if err := verifyRuntimeTraversableDirectory(current, 0, runtimeGID); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("Portal product directory path is invalid")
		}
		current = filepath.Join(current, component)
		if err := verifyRuntimeTraversableDirectory(current, 0, runtimeGID); err != nil {
			return err
		}
	}
	return nil
}

func verifyRuntimeReadableFile(path string, maximum int64, expectedUID, runtimeGID uint32, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return errors.New("protected file path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !ok || stat.Uid != expectedUID || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || mode&0o022 != 0 || mode&0o111 != 0 {
		return errors.New("file is not a protected regular file")
	}
	groupReadable := stat.Gid == runtimeGID && mode&0o040 != 0
	otherReadable := mode&0o004 != 0
	if !groupReadable && !otherReadable {
		return errors.New("file is not readable by the Portal runtime")
	}
	if private && (stat.Gid != runtimeGID || !groupReadable || mode&0o007 != 0) {
		return errors.New("private file is not restricted to the Portal group")
	}
	return nil
}

func verifyRuntimeTraversableDirectory(path string, expectedUID, runtimeGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !ok || stat.Uid != expectedUID || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || mode&0o022 != 0 {
		return errors.New("Portal configuration directory is unsafe")
	}
	if !((stat.Gid == runtimeGID && mode&0o010 != 0) || mode&0o001 != 0) {
		return errors.New("Portal configuration directory is not traversable by the runtime")
	}
	return nil
}
