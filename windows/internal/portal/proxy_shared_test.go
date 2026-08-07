package portal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/store"
)

func TestStableSharedProjectRootRejectsPathsAndAcceptsOnlyStableID(t *testing.T) {
	id := strings.Repeat("a", 32)
	if got, ok := stableSharedProjectRoot("shared://" + id); !ok || got != id {
		t.Fatalf("stable root = %q, %v", got, ok)
	}
	for _, value := range []string{
		"shared://" + id + "/file.txt",
		"shared://../" + id,
		`C:\Data\shared\S-1-5-21-1\` + id,
		"shared://" + strings.Repeat("a", 31),
	} {
		if _, ok := stableSharedProjectRoot(value); ok {
			t.Fatalf("unexpected stable shared root acceptance: %q", value)
		}
	}
}

func TestInternalSharedWorkspaceIsRejectedAtBrowserBoundary(t *testing.T) {
	base := `C:\AionData`
	if !isInternalSharedWorkspace(`C:\AionData\shared\S-1-5-21-1\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, base) {
		t.Fatal("absolute shared workspace was not recognized")
	}
	if isInternalSharedWorkspace(`C:\AionData\S-1-5-21-1\workspace\project`, base) {
		t.Fatal("private workspace was misclassified as shared")
	}
	if isInternalSharedWorkspace(`shared://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, base) {
		t.Fatal("stable shared workspace was misclassified as internal")
	}
}

func TestDangerousBrowserWorkspaceRejectsDeviceUNCRelativeAndShortAliases(t *testing.T) {
	for _, value := range []string{
		`\\?\C:\AionData\shared\S-1-5-21-1\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
		`\\.\C:\AionData\shared\S-1-5-21-1\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
		`\\server\share\project`,
		`\root-relative`,
		`C:drive-relative`,
		`C:\AIONDA~1\shared\project`,
	} {
		if !dangerousBrowserWorkspace(value) {
			t.Fatalf("dangerous workspace was accepted: %q", value)
		}
	}
	for _, value := range []string{`C:\AionData\S-1-5-21-1\workspace\project`, `shared://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`} {
		if dangerousBrowserWorkspace(value) {
			t.Fatalf("normal workspace was rejected: %q", value)
		}
	}
}

func TestRewriteSharedWorkspaceRequestDoesNotTrustContentType(t *testing.T) {
	server, data, _ := testServer(t)
	server.cfg.UserDataRoot = `D:\AionData`
	_ = createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 32)
	if _, err := data.CreateSharedProject(context.Background(), store.SharedProject{ID: id, OwnerUserID: user.ID, Name: "shared", SourceKind: "new"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(context.Background(), id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(`{"extra":{"workspace":"shared://`+id+`"}}`))
	request.Header.Set("Content-Type", "text/plain")
	if err := server.rewriteSharedWorkspaceRequest(request, user.ID, true); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	if strings.Contains(string(body), "shared://") || !strings.Contains(string(body), user.WindowsSID) {
		t.Fatalf("content-type bypassed stable workspace rewrite: %s", body)
	}
}

func TestRewriteConversationRequestStripsBrowserWorkspaceClassification(t *testing.T) {
	server, _, _ := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(`{"extra":{"workspace":"C:\\private\\project","custom_workspace":true,"is_project_workspace":true}}`))
	if err := server.rewriteSharedWorkspaceRequest(request, 1, false); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	if strings.Contains(string(body), "custom_workspace") || strings.Contains(string(body), "is_project_workspace") {
		t.Fatalf("browser workspace classification survived: %s", body)
	}
}

func TestRewriteConversationRequestRejectsParserDifferentialKeysAndMalformedJSON(t *testing.T) {
	server, _, _ := testServer(t)
	for _, body := range []string{
		`{"Extra":{"workspace":"C:\\private\\project","custom_workspace":true}}`,
		`{"EXTRA":{"workspace":"C:\\private\\project","custom_workspace":true}}`,
		`{"extra":`,
	} {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(body))
		if err := server.rewriteSharedWorkspaceRequest(request, 1, false); err == nil {
			t.Fatalf("parser-differential request was accepted: %s", body)
		}
	}
	clone := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations/clone", strings.NewReader(`{"Conversation":{"extra":{"workspace":"C:\\private\\project"}}}`))
	if err := server.rewriteSharedWorkspaceRequest(clone, 1, false); err == nil {
		t.Fatal("non-canonical clone conversation key was accepted")
	}
}

func TestRewriteSharedWorkspaceRequestAuthorizesStableIDAndKeepsBrowserPathOpaque(t *testing.T) {
	server, data, _ := testServer(t)
	server.cfg.UserDataRoot = `D:\AionData`
	_ = createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 32)
	if _, err := data.CreateSharedProject(context.Background(), store.SharedProject{ID: id, OwnerUserID: user.ID, Name: "shared", SourceKind: "new"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(context.Background(), id, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(`{"type":"acp","extra":{"workspace":"shared://`+id+`"}}`))
	request.Header.Set("Content-Type", "application/json")
	if err := server.rewriteSharedWorkspaceRequest(request, user.ID, true); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Extra map[string]any `json:"extra"`
	}
	if json.Unmarshal(body, &payload) != nil {
		t.Fatalf("invalid rewritten JSON: %s", body)
	}
	want := filepath.Join(server.cfg.UserDataRoot, "shared", user.WindowsSID, id)
	if payload.Extra["workspace"] != want || payload.Extra["custom_workspace"] != true || payload.Extra["is_project_workspace"] != true {
		t.Fatalf("rewritten extra=%+v want workspace=%s", payload.Extra, want)
	}
}

func TestSanitizeSharedPathValueHidesOwnerSIDAndAbsolutePath(t *testing.T) {
	id := strings.Repeat("b", 32)
	root := filepath.Join(`C:\AionData`, "shared")
	absolute := filepath.Join(root, "S-1-5-21-100-200-300-400", id)
	payload := map[string]any{
		"workspace": absolute,
		"content":   "continue in " + filepath.Join(absolute, "docs", "readme.md"),
	}
	sanitized := sanitizeSharedPathValue(payload, nil, root).(map[string]any)
	for key, raw := range sanitized {
		value := raw.(string)
		if strings.Contains(strings.ToLower(value), "s-1-5-21") || strings.Contains(strings.ToLower(value), strings.ToLower(root)) {
			t.Fatalf("%s leaked internal shared path: %q", key, value)
		}
		if !strings.Contains(value, "shared://"+id) {
			t.Fatalf("%s did not retain stable project path: %q", key, value)
		}
	}
}

func TestSanitizeUnknownSharedPathRedactsOwnerWithoutStableProject(t *testing.T) {
	root := `C:\AionData\shared`
	for _, raw := range []string{
		`failed at C:\AionData\shared\S-1-5-21-100`,
		`failed at C:\AionData\shared\S-1-5-21-100\not-a-stable-project`,
	} {
		got := sanitizeUnknownSharedPath(raw, root)
		if strings.Contains(strings.ToLower(got), strings.ToLower(root)) || strings.Contains(got, "S-1-5-21-100") {
			t.Fatalf("shared owner leaked: %q", got)
		}
	}
}
