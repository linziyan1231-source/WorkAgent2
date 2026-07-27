package portal

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

//go:embed ui/*
var staticFiles embed.FS

var fingerprintedRendererAsset = regexp.MustCompile(`^/assets/(?:[^/]+/)*[^/]+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$`)

func newRendererStaticHandler(rootPath string) (http.Handler, error) {
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open Renderer root: %w", err)
	}
	index, err := root.ReadFile("index.html", 8*1024*1024)
	if err != nil {
		root.Close()
		return nil, errors.New("verified Renderer root is missing a bounded index.html")
	}
	index = injectRendererBridge(index)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.ContainsRune(request.URL.Path, '\\') {
			http.NotFound(writer, request)
			return
		}
		clean := path.Clean("/" + request.URL.Path)
		relative := strings.TrimPrefix(clean, "/")
		if relative != "" && relative != "." {
			file, openErr := root.Open(relative, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
			if openErr == nil {
				info, statErr := file.Stat()
				if statErr == nil && info.Mode().IsRegular() && info.Size() <= 256*1024*1024 {
					if fingerprintedRendererAsset.MatchString(clean) {
						writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					http.ServeContent(writer, request, path.Base(relative), info.ModTime(), file)
					file.Close()
					return
				}
				file.Close()
			}
		}
		writer.Header().Set("Cache-Control", "no-store")
		http.ServeContent(writer, request, "index.html", time.Time{}, bytes.NewReader(index))
	}), nil
}

func injectRendererBridge(index []byte) []byte {
	const tag = `<script src="/portal-mcp-oauth.js"></script>`
	if bytes.Contains(index, []byte(tag)) {
		return index
	}
	lower := bytes.ToLower(index)
	head := bytes.Index(lower, []byte("<head"))
	if head < 0 {
		return index
	}
	end := bytes.IndexByte(index[head:], '>')
	if end < 0 {
		return index
	}
	position := head + end + 1
	result := make([]byte, 0, len(index)+len(tag)+1)
	result = append(result, index[:position]...)
	result = append(result, '\n')
	result = append(result, tag...)
	result = append(result, index[position:]...)
	return result
}
