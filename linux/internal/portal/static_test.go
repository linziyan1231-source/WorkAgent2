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
	if err := os.Mkdir(filepath.Join(root, "pwa"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<!doctype html><html><head><title>WorkAgent"+" AI</title></head><body>renderer</body></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app-abcdefgh.js"), []byte(`window.renderer="WorkAgent`+` AI"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pwa", "workagent-favicon-v2.png"), []byte("old-logo"), 0o600); err != nil {
		t.Fatal(err)
	}
	brandLogo := filepath.Join(t.TempDir(), "workagent-logo.png")
	if err := os.WriteFile(brandLogo, []byte("new-workagent-logo"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.js")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "assets", "linked.js")); err != nil {
		t.Fatal(err)
	}
	handler, err := newRendererStaticHandler(root, brandLogo)
	if err != nil {
		t.Fatal(err)
	}
	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets/app-abcdefgh.js", nil))
	if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=0, must-revalidate" || asset.Header().Get("ETag") == "" || !strings.Contains(asset.Body.String(), "WorkAgent2") || strings.Contains(asset.Body.String(), "WorkAgent"+" AI") {
		t.Fatalf("asset response status=%d cache=%q body=%q", asset.Code, asset.Header().Get("Cache-Control"), asset.Body.String())
	}
	cachedAsset := httptest.NewRecorder()
	cachedRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets/app-abcdefgh.js", nil)
	cachedRequest.Header.Set("If-None-Match", asset.Header().Get("ETag"))
	handler.ServeHTTP(cachedAsset, cachedRequest)
	if cachedAsset.Code != http.StatusNotModified || cachedAsset.Body.Len() != 0 {
		t.Fatalf("cached branded asset was downloaded again: status=%d bytes=%d", cachedAsset.Code, cachedAsset.Body.Len())
	}
	spa := httptest.NewRecorder()
	handler.ServeHTTP(spa, httptest.NewRequest(http.MethodGet, "https://portal.example.test/conversation/one", nil))
	if spa.Code != http.StatusOK || !strings.Contains(spa.Body.String(), "renderer") || !strings.Contains(spa.Body.String(), "/portal-mcp-oauth.js") || !strings.Contains(spa.Body.String(), "WorkAgent2") || strings.Contains(spa.Body.String(), "WorkAgent"+" AI") {
		t.Fatalf("SPA fallback was not the injected Renderer index: %d %q", spa.Code, spa.Body.String())
	}
	logo := httptest.NewRecorder()
	handler.ServeHTTP(logo, httptest.NewRequest(http.MethodGet, "https://portal.example.test/pwa/workagent-favicon-v2.png", nil))
	if logo.Code != http.StatusOK || logo.Body.String() != "new-workagent-logo" || logo.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("Renderer logo was not replaced: status=%d type=%q body=%q", logo.Code, logo.Header().Get("Content-Type"), logo.Body.String())
	}
	linked := httptest.NewRecorder()
	handler.ServeHTTP(linked, httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets/linked.js", nil))
	if strings.Contains(linked.Body.String(), "secret") {
		t.Fatal("Renderer handler followed a symlink outside the release")
	}
}

func TestPortalBridgeCacheBustsRendererBrandLogo(t *testing.T) {
	if !strings.Contains(portalOAuthBridgeScript, `/brand/logo?v=workagent-v1`) ||
		!strings.Contains(portalOAuthBridgeScript, `MutationObserver`) ||
		!strings.Contains(portalOAuthBridgeScript, `rendererLogoPath`) ||
		!strings.Contains(portalOAuthBridgeScript, `object-fit`) ||
		!strings.Contains(portalOAuthBridgeScript, `brandedText`) {
		t.Fatal("Portal bridge does not replace cached Renderer brand logos")
	}
}
