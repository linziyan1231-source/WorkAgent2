package portal

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
var rendererLogoAsset = regexp.MustCompile(`^(?:/assets/app-[A-Za-z0-9_-]{8,}\.png|/pwa/(?:workagent-)?(?:favicon(?:-v[0-9]+)?|icon-(?:180|192|512)(?:-v[0-9]+)?)\.png)$`)

const rendererBrandVersion = "workagent-v1"

func newRendererStaticHandler(rootPath string, brandLogoPaths ...string) (http.Handler, error) {
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
	index = brandRendererText(index)
	var brandLogo []byte
	if len(brandLogoPaths) > 0 && brandLogoPaths[0] != "" {
		logoInfo, statErr := os.Lstat(brandLogoPaths[0])
		if statErr != nil || logoInfo.Mode()&os.ModeSymlink != 0 || !logoInfo.Mode().IsRegular() || logoInfo.Size() <= 0 || logoInfo.Size() > 2*1024*1024 {
			root.Close()
			return nil, errors.New("configured Renderer brand logo is missing or unsafe")
		}
		brandLogo, err = os.ReadFile(brandLogoPaths[0])
		if err != nil {
			root.Close()
			return nil, fmt.Errorf("read Renderer brand logo: %w", err)
		}
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.ContainsRune(request.URL.Path, '\\') {
			http.NotFound(writer, request)
			return
		}
		clean := path.Clean("/" + request.URL.Path)
		if len(brandLogo) > 0 && rendererLogoAsset.MatchString(clean) {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Content-Type", "image/png")
			http.ServeContent(writer, request, "workagent-logo.png", time.Time{}, bytes.NewReader(brandLogo))
			return
		}
		relative := strings.TrimPrefix(clean, "/")
		if relative != "" && relative != "." {
			file, openErr := root.Open(relative, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
			if openErr == nil {
				info, statErr := file.Stat()
				if statErr == nil && info.Mode().IsRegular() && info.Size() <= 256*1024*1024 {
					if rendererBrandTextAsset(clean) {
						content, readErr := io.ReadAll(io.LimitReader(file, 256*1024*1024+1))
						file.Close()
						if readErr == nil && len(content) <= 256*1024*1024 {
							branded := brandRendererText(content)
							digest := sha256.Sum256(branded)
							writer.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
							writer.Header().Set("ETag", fmt.Sprintf(`"%x"`, digest))
							http.ServeContent(writer, request, path.Base(relative), info.ModTime(), bytes.NewReader(branded))
							return
						}
						return
					}
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

func rendererBrandTextAsset(clean string) bool {
	switch strings.ToLower(path.Ext(clean)) {
	case ".css", ".html", ".js", ".json", ".map", ".md", ".txt", ".webmanifest":
		return true
	default:
		return false
	}
}

func brandRendererText(content []byte) []byte {
	return bytes.ReplaceAll(content, []byte("WorkAgent"+" AI"), []byte("WorkAgent2"))
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
