package edgepublication

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	JournalPath = "/var/lib/workagent-edge/publication.json"
	PermitPath  = "/run/workagent-edge/publication.permit"
)

type directoryIdentity struct {
	device uint64
	inode  uint64
	mode   os.FileMode
	uid    uint32
	gid    uint32
}

// AssertClean is the ordinary-writer admission gate. It must be called only
// after acquiring the global activation lock so an edge publisher cannot
// create evidence between the two protected-parent snapshots.
func AssertClean() error {
	return assertCleanAt(JournalPath, PermitPath, 0, 0)
}

func assertCleanAt(journalPath, permitPath string, expectedUID, expectedGID uint32) error {
	if !filepath.IsAbs(journalPath) || filepath.Clean(journalPath) != journalPath || !filepath.IsAbs(permitPath) || filepath.Clean(permitPath) != permitPath || filepath.Dir(journalPath) == filepath.Dir(permitPath) {
		return errors.New("edge-publication cleanliness layout is invalid")
	}
	paths := []string{journalPath, permitPath}
	before := make([]directoryIdentity, len(paths))
	for index, path := range paths {
		identity, err := protectedAbsent(path, expectedUID, expectedGID)
		if err != nil {
			return err
		}
		before[index] = identity
	}
	for index, path := range paths {
		after, err := protectedAbsent(path, expectedUID, expectedGID)
		if err != nil {
			return err
		}
		if after != before[index] {
			return fmt.Errorf("edge-publication protected parent changed while proving %s absent", path)
		}
	}
	return nil
}

func protectedAbsent(path string, expectedUID, expectedGID uint32) (directoryIdentity, error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return directoryIdentity{}, fmt.Errorf("inspect edge-publication protected parent %s: %w", parent, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return directoryIdentity{}, fmt.Errorf("edge-publication protected parent %s is unsafe", parent)
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return directoryIdentity{}, errors.Join(fmt.Errorf("pending or unsafe edge-publication evidence exists at %s", path), err)
	}
	return directoryIdentity{device: uint64(stat.Dev), inode: stat.Ino, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid}, nil
}
