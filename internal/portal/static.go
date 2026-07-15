package portal

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var fingerprintedStaticAsset = regexp.MustCompile(`^/assets/(?:[^/]+/)*[^/]+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$`)

func newStaticHandler(root string) (http.Handler, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	indexPath := filepath.Join(root, "index.html")
	info, err := os.Stat(indexPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("verified Renderer static directory is missing index.html")
	}
	index, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, err
	}
	index = injectOAuthBridge(index)
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsRune(r.URL.Path, '\\') {
			http.NotFound(w, r)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		rel := strings.TrimPrefix(clean, "/")
		candidate := filepath.Join(root, filepath.FromSlash(rel))
		if candidateInfo, err := os.Stat(candidate); err == nil && candidateInfo.Mode().IsRegular() && !sameStaticPath(candidate, indexPath) {
			if fingerprintedStaticAsset.MatchString(clean) {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			copy := r.Clone(r.Context())
			copy.URL.Path = clean
			files.ServeHTTP(w, copy)
			return
		}
		http.ServeContent(w, r, "index.html", info.ModTime(), bytes.NewReader(index))
	}), nil
}

func injectOAuthBridge(index []byte) []byte {
	const tag = `<script src="/portal-mcp-oauth.js"></script>`
	if bytes.Contains(index, []byte(tag)) {
		return index
	}
	lower := bytes.ToLower(index)
	start := bytes.Index(lower, []byte("<head"))
	if start < 0 {
		return index
	}
	end := bytes.IndexByte(index[start:], '>')
	if end < 0 {
		return index
	}
	position := start + end + 1
	result := make([]byte, 0, len(index)+len(tag)+3)
	result = append(result, index[:position]...)
	result = append(result, '\n')
	result = append(result, []byte(tag)...)
	result = append(result, index[position:]...)
	return result
}

func sameStaticPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
