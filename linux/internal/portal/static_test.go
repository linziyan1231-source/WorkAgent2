package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRendererStaticHandlerServesAssetsAndSPAFallbackWithoutSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<!doctype html><html><head></head><body>renderer</body></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app-abcdefgh.js"), []byte("window.renderer=true"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.js")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "assets", "linked.js")); err != nil {
		t.Fatal(err)
	}
	handler, err := newRendererStaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets/app-abcdefgh.js", nil))
	if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.Contains(asset.Body.String(), "renderer") {
		t.Fatalf("asset response status=%d cache=%q body=%q", asset.Code, asset.Header().Get("Cache-Control"), asset.Body.String())
	}
	spa := httptest.NewRecorder()
	handler.ServeHTTP(spa, httptest.NewRequest(http.MethodGet, "https://portal.example.test/conversation/one", nil))
	if spa.Code != http.StatusOK || !strings.Contains(spa.Body.String(), "renderer") || !strings.Contains(spa.Body.String(), "/portal-mcp-oauth.js") {
		t.Fatalf("SPA fallback was not the injected Renderer index: %d %q", spa.Code, spa.Body.String())
	}
	linked := httptest.NewRecorder()
	handler.ServeHTTP(linked, httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets/linked.js", nil))
	if strings.Contains(linked.Body.String(), "secret") {
		t.Fatal("Renderer handler followed a symlink outside the release")
	}
}
