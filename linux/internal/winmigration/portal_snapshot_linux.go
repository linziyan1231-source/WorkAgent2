//go:build linux

package winmigration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	sourcePortalRelative    = "global/portal.windows.db"
	sourcePortalWALRelative = "global/portal.windows.db-wal"
	sourcePortalSHMRelative = "global/portal.windows.db-shm"

	maximumPortalDatabaseBytes = int64(4 * 1024 * 1024 * 1024)
	maximumPortalWALBytes      = int64(4 * 1024 * 1024 * 1024)
	maximumPortalSHMBytes      = int64(1 * 1024 * 1024 * 1024)
	portalWorkPrefix           = "workagent-portal-source-"
)

type portalSourceSet struct {
	databaseSHA256 string
	walSHA256      string
	shmSHA256      string
	databaseSize   int64
	walSize        int64
	shmSize        int64
}

func inspectPortalSourceSet(snapshotFD int) (portalSourceSet, error) {
	var result portalSourceSet
	var err error
	result.databaseSHA256, result.databaseSize, err = hashSecureFile(snapshotFD, sourcePortalRelative)
	if err != nil {
		return portalSourceSet{}, fmt.Errorf("inspect Windows Portal database: %w", err)
	}
	result.walSHA256, result.walSize, err = hashSecureFile(snapshotFD, sourcePortalWALRelative)
	if err != nil {
		return portalSourceSet{}, fmt.Errorf("inspect Windows Portal WAL: %w", err)
	}
	result.shmSHA256, result.shmSize, err = hashSecureFile(snapshotFD, sourcePortalSHMRelative)
	if err != nil {
		return portalSourceSet{}, fmt.Errorf("inspect Windows Portal SHM: %w", err)
	}
	if result.databaseSize < 1 || result.databaseSize > maximumPortalDatabaseBytes {
		return portalSourceSet{}, errors.New("Windows Portal database is outside its size boundary")
	}
	if result.walSize < 0 || result.walSize > maximumPortalWALBytes {
		return portalSourceSet{}, errors.New("Windows Portal WAL is outside its size boundary")
	}
	if result.shmSize < 0 || result.shmSize > maximumPortalSHMBytes {
		return portalSourceSet{}, errors.New("Windows Portal SHM is outside its size boundary")
	}
	return result, nil
}

func verifyPortalSourceSet(snapshotFD int, expected portalSourceSet) error {
	actual, err := inspectPortalSourceSet(snapshotFD)
	if err != nil || actual != expected {
		return errors.New("Windows Portal DB/WAL/SHM snapshot changed during migration")
	}
	return nil
}

func preparePortalWorkingCopy(snapshotFD int, source portalSourceSet) (string, string, error) {
	temporaryBase, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil || !filepath.IsAbs(temporaryBase) || filepath.Clean(temporaryBase) != temporaryBase {
		return "", "", errors.New("resolve private Portal working-copy directory")
	}
	info, err := os.Lstat(temporaryBase)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("Portal working-copy parent is not a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode()
	privateOwner := ok && stat.Uid == uint32(os.Geteuid()) && mode.Perm()&0o022 == 0
	rootSticky := ok && stat.Uid == 0 && mode&os.ModeSticky != 0
	if !privateOwner && !rootSticky {
		return "", "", errors.New("Portal working-copy parent is not private or root-owned sticky storage")
	}
	workRoot, err := os.MkdirTemp(temporaryBase, portalWorkPrefix)
	if err != nil {
		return "", "", fmt.Errorf("create private Portal working copy: %w", err)
	}
	clean := false
	defer func() {
		if !clean {
			cleanupPortalWorkRoot(workRoot)
		}
	}()
	if err := os.Chmod(workRoot, 0o700); err != nil {
		return "", "", err
	}
	workInfo, err := os.Lstat(workRoot)
	if err != nil {
		return "", "", errors.New("inspect private Portal working-copy directory")
	}
	workStat, statOK := workInfo.Sys().(*syscall.Stat_t)
	if !statOK || workInfo.Mode()&os.ModeSymlink != 0 || !workInfo.IsDir() || workInfo.Mode().Perm() != 0o700 || workStat.Uid != uint32(os.Geteuid()) {
		return "", "", errors.New("private Portal working-copy directory is unsafe")
	}
	databasePath := filepath.Join(workRoot, "portal.windows.db")
	for _, file := range []struct {
		relative string
		target   string
		hash     string
	}{
		{sourcePortalRelative, databasePath, source.databaseSHA256},
		{sourcePortalWALRelative, databasePath + "-wal", source.walSHA256},
		{sourcePortalSHMRelative, databasePath + "-shm", source.shmSHA256},
	} {
		if err := copySecureSnapshotFile(snapshotFD, file.relative, file.target, file.hash); err != nil {
			return "", "", fmt.Errorf("copy %s into private Portal working set: %w", filepath.Base(file.relative), err)
		}
	}
	if err := syncDirectory(workRoot); err != nil {
		return "", "", err
	}
	clean = true
	return workRoot, databasePath, nil
}

// cleanupPortalWorkRoot removes only the exact, private flat directory created
// above. It never recursively removes a nested directory or follows a link.
func cleanupPortalWorkRoot(workRoot string) {
	if workRoot == "" || !filepath.IsAbs(workRoot) || filepath.Clean(workRoot) != workRoot ||
		!strings.HasPrefix(filepath.Base(workRoot), portalWorkPrefix) || filepath.Base(workRoot) == portalWorkPrefix {
		return
	}
	info, err := os.Lstat(workRoot)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		_ = os.Remove(workRoot)
		return
	}
	entries, err := os.ReadDir(workRoot)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return
		}
	}
	for _, entry := range entries {
		_ = os.Remove(filepath.Join(workRoot, entry.Name()))
	}
	_ = os.Remove(workRoot)
}

func (plan *migrationPlan) cleanup() {
	if plan == nil {
		return
	}
	cleanupPortalWorkRoot(plan.portalWorkRoot)
	plan.portalWorkRoot = ""
	plan.portalPath = ""
}
