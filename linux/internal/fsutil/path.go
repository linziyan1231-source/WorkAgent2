package fsutil

import (
	"path/filepath"
	"strings"
)

// PathWithin reports whether candidate is root itself or lies inside root.
func PathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
