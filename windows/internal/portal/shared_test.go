package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/store"
)

func TestSharedAPIsRequireEmployeeOptIn(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.CollaborationEnabled {
		t.Fatal("new employee unexpectedly has collaboration enabled")
	}

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/portal/shared-projects"},
		{http.MethodPut, "/api/portal/shared-projects/hidden"},
		{http.MethodPost, "/api/portal/shared-projects/transfer"},
		{http.MethodPost, "/api/portal/shared-conversations"},
		{http.MethodGet, "/api/portal/shared-runtime-options?backend=codex"},
		{http.MethodGet, "/api/portal/shared-events"},
		{http.MethodPost, "/api/portal/shared-files"},
		{http.MethodPost, "/api/portal/shared-messages"},
		{http.MethodGet, "/api/portal/shared-users"},
		{http.MethodPost, "/api/portal/shared-invites"},
		{http.MethodPost, "/api/portal/shared-invites/accept"},
		{http.MethodPost, "/api/portal/shared-invites/decline"},
		{http.MethodPost, "/api/portal/shared-invite-links"},
		{http.MethodPost, "/api/portal/shared-invite-links/accept"},
		{http.MethodGet, "/api/portal/shared-members"},
		{http.MethodDelete, "/api/portal/shared-members/leave"},
	} {
		request := httptest.NewRequest(route.method, "https://portal.example.test"+route.path, nil)
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"COLLABORATION_DISABLED"`) {
			t.Fatalf("disabled collaboration route %s %s returned status=%d body=%s", route.method, route.path, response.Code, response.Body.String())
		}
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/shared-projects", nil)
	unauthenticatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated collaboration route returned status=%d body=%s", unauthenticatedResponse.Code, unauthenticatedResponse.Body.String())
	}

	adminHash, err := auth.HashPassword([]byte("correct-administrator-portal-password"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := data.CreateAdministrator(context.Background(), "collaboration-admin", adminHash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	adminToken, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.CreateSession(context.Background(), adminToken, admin, time.Hour, "192.0.2.11", "admin-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	adminRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/shared-projects", nil)
	adminRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: adminToken})
	adminResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusForbidden || !strings.Contains(adminResponse.Body.String(), `"code":"COLLABORATION_DISABLED"`) {
		t.Fatalf("administrator collaboration route returned status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}

	if _, err := data.UpdateProfile(context.Background(), user.ID, "Alice", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/shared-projects", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("enabled collaboration route returned status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSharedRuntimeOptionsUseManagedBackendCatalogs(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateProfile(context.Background(), user.ID, "Alice", true, time.Now()); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/shared-runtime-options?backend=kimi", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"default_model_id":"kimi-code/kimi-k3,thinking"`) || strings.Contains(response.Body.String(), "gpt-5.6") {
		t.Fatalf("managed Kimi options returned status=%d body=%s", response.Code, response.Body.String())
	}

	bad := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/shared-runtime-options?backend=other", nil)
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	badResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest || !strings.Contains(badResponse.Body.String(), `"code":"INVALID_SHARED_RUNTIME"`) {
		t.Fatalf("invalid shared runtime returned status=%d body=%s", badResponse.Code, badResponse.Body.String())
	}
}

func TestSharedInviteEndpointReturnsStableDuplicateAndMemberErrors(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	owner, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateProfile(context.Background(), owner.ID, "Alice", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	target, err := data.CreateUser(context.Background(), "invite-target-http", "hash", "S-1-5-21-1-2991", `SERVER\invite-target-http`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	projectID := "91919191919191919191919191919191"
	if _, err := data.CreateSharedProject(context.Background(), store.SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "Invite semantics", SourceKind: "new"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(context.Background(), projectID, true, time.Now()); err != nil {
		t.Fatal(err)
	}

	send := func() *httptest.ResponseRecorder {
		body := strings.NewReader(fmt.Sprintf(`{"project_id":%q,"target_user_id":%d}`, projectID, target.ID))
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/shared-invites", body)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://portal.example.test")
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	if response := send(); response.Code != http.StatusCreated {
		t.Fatalf("initial invite returned status=%d body=%s", response.Code, response.Body.String())
	}
	if response := send(); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"SHARED_INVITE_ALREADY_PENDING"`) {
		t.Fatalf("duplicate invite returned status=%d body=%s", response.Code, response.Body.String())
	}
	pending, err := data.ListPendingSharedInvites(context.Background(), target.ID, time.Now())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending invites=%d err=%v", len(pending), err)
	}
	if _, err := data.BeginAcceptSharedInvite(context.Background(), pending[0].ID, target.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.FinishAcceptSharedInvite(context.Background(), pending[0].ID, target.ID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if response := send(); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"SHARED_MEMBER_ALREADY_EXISTS"`) {
		t.Fatalf("member invite returned status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSharedWorkspaceProxyRequiresEmployeeOptIn(t *testing.T) {
	server, data, _ := testServer(t)
	server.cfg.UserDataRoot = `D:\AionData`
	token := createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	projectID := strings.Repeat("f", 32)
	if _, err := data.CreateSharedProject(context.Background(), store.SharedProject{ID: projectID, OwnerUserID: user.ID, Name: "Shared", SourceKind: "new"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(context.Background(), projectID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(`{"extra":{"workspace":"shared://`+projectID+`"}}`))
	if err := server.rewriteSharedWorkspaceRequest(request, user.ID, false); !errors.Is(err, errCollaborationDisabled) {
		t.Fatalf("disabled shared workspace returned %v", err)
	}

	request = httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/conversations", strings.NewReader(`{"extra":{"workspace":"shared://`+projectID+`"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"COLLABORATION_DISABLED"`) {
		t.Fatalf("disabled shared workspace proxy returned status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSharedMessageOnlyStructuredFixedAssistantMentionStartsAI(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateProfile(context.Background(), user.ID, "Alice", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	projectID := "11111111111111111111111111111111"
	if _, err := data.CreateSharedProject(context.Background(), store.SharedProject{ID: projectID, OwnerUserID: user.ID, Name: "Shared", SourceKind: "new"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(context.Background(), projectID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	conversationID := "22222222222222222222222222222222"
	if _, err := data.CreateSharedConversation(context.Background(), store.SharedConversation{ID: conversationID, ProjectID: projectID, Name: "Group", AssistantID: "codex", AssistantBackend: "codex", ModelID: "gpt-5"}, user.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	send := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/shared-messages", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://portal.example.test")
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	plain := send(`{"conversation_id":"` + conversationID + `","body":"@Codex please run","mentions":[],"attachments":[]}`)
	if plain.Code != http.StatusCreated || !strings.Contains(plain.Body.String(), `"ai_started":false`) || !strings.Contains(plain.Body.String(), `"author_name":"Alice"`) {
		t.Fatalf("plain mention unexpectedly started AI: status=%d body=%s", plain.Code, plain.Body.String())
	}
	member := send(`{"conversation_id":"` + conversationID + `","body":"FYI","mentions":[{"kind":"member","id":"1"}],"attachments":[]}`)
	if member.Code != http.StatusCreated || !strings.Contains(member.Body.String(), `"ai_started":false`) {
		t.Fatalf("member mention unexpectedly started AI: status=%d body=%s", member.Code, member.Body.String())
	}
	structured := send(`{"conversation_id":"` + conversationID + `","body":"please run","mentions":[{"kind":"assistant","id":"codex"}],"attachments":[]}`)
	if structured.Code != http.StatusCreated || !strings.Contains(structured.Body.String(), `"ai_started":true`) {
		t.Fatalf("structured assistant mention did not start AI: status=%d body=%s", structured.Code, structured.Body.String())
	}
}
