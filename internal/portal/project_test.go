package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/projectfs"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
)

func TestCreateProjectCreatesProtectedDirectoryForAuthenticatedUser(t *testing.T) {
	server, data, _ := testServer(t)
	profile := prepareProjectProfile(t, server, testSID1, "test1")
	token := createPortalSession(t, data)

	response := createProjectRequest(server, token, `{"name":"网站项目"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	target := filepath.Join(profile, config.UserDataDirectoryName, "workspace", "网站项目")
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("created project directory is unavailable: info=%v err=%v", info, err)
	}
	if err := winutil.VerifyACL(target, winutil.PrivateTreePolicy(testSID1)); err != nil {
		t.Fatalf("created project ACL is invalid: %v", err)
	}
}

func TestCreateProjectRejectsExistingProjectWithoutChangingIt(t *testing.T) {
	server, data, _ := testServer(t)
	profile := prepareProjectProfile(t, server, testSID1, "test1")
	token := createPortalSession(t, data)
	first := createProjectRequest(server, token, `{"name":"existing"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status=%d body=%s", first.Code, first.Body.String())
	}

	second := createProjectRequest(server, token, `{"name":"existing"}`)
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), `"code":"PROJECT_EXISTS"`) {
		t.Fatalf("duplicate status=%d body=%s", second.Code, second.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(profile, config.UserDataDirectoryName, "workspace"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("duplicate create changed workspace: entries=%v err=%v", entries, err)
	}
}

func TestCreateProjectRejectsUnsafeWindowsNames(t *testing.T) {
	invalid := []string{"", " ", ".", "..", "../escape", `nested\escape`, "bad:name", "trailing.", " leading", "CON", "con.txt", "LPT9.log", "line\nbreak"}
	for _, name := range invalid {
		if projectfs.ValidName(name) {
			t.Fatalf("unsafe project name accepted: %q", name)
		}
	}
	for _, name := range []string{"project", "网站项目", "project.name", "CONSOLE"} {
		if !projectfs.ValidName(name) {
			t.Fatalf("valid project name rejected: %q", name)
		}
	}
}

func TestCreateProjectRejectsAnonymousAndCrossOriginRequests(t *testing.T) {
	server, data, _ := testServer(t)
	prepareProjectProfile(t, server, testSID1, "test1")
	token := createPortalSession(t, data)

	anonymous := createProjectRequest(server, "", `{"name":"anonymous"}`)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d body=%s", anonymous.Code, anonymous.Body.String())
	}
	crossOriginRequest := newCreateProjectRequest(token, `{"name":"cross-origin"}`)
	crossOriginRequest.Header.Set("Origin", "https://attacker.example.test")
	crossOrigin := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossOrigin, crossOriginRequest)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}
}

func TestRenameProjectRoutesOnlyManagedProtectedDirectory(t *testing.T) {
	server, data, instances := testServer(t)
	profile := prepareProjectProfile(t, server, testSID1, "test1")
	token := createPortalSession(t, data)
	source := filepath.Join(profile, config.UserDataDirectoryName, "workspace", "old-project")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := winutil.ApplyACL(source, winutil.PrivateTreePolicy(testSID1)); err != nil {
		t.Fatal(err)
	}
	instances.projectRenameResult = ipc.ProjectRenameResult{OldPath: source, NewPath: filepath.Join(filepath.Dir(source), "new-project"), UpdatedConversations: 2}

	response := renameProjectRequest(server, token, source, "new-project")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if instances.projectRename == nil || instances.projectRename.OldName != "old-project" || instances.projectRename.NewName != "new-project" {
		t.Fatalf("wrong rename request: %+v", instances.projectRename)
	}
	if !strings.Contains(response.Body.String(), `"updated_conversations":2`) {
		t.Fatalf("rename result is incomplete: %s", response.Body.String())
	}
}

func TestRenameProjectRejectsOutsidePathAndMapsOccupiedDirectory(t *testing.T) {
	server, data, instances := testServer(t)
	profile := prepareProjectProfile(t, server, testSID1, "test1")
	token := createPortalSession(t, data)
	outside := filepath.Join(profile, "outside")
	outsideResponse := renameProjectRequest(server, token, outside, "new-project")
	if outsideResponse.Code != http.StatusBadRequest || !strings.Contains(outsideResponse.Body.String(), `"code":"INVALID_PROJECT_PATH"`) {
		t.Fatalf("outside status=%d body=%s", outsideResponse.Code, outsideResponse.Body.String())
	}
	if instances.projectRename != nil {
		t.Fatalf("outside path reached UserHost: %+v", instances.projectRename)
	}

	source := filepath.Join(profile, config.UserDataDirectoryName, "workspace", "old-project")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := winutil.ApplyACL(source, winutil.PrivateTreePolicy(testSID1)); err != nil {
		t.Fatal(err)
	}
	instances.projectRenameError = &instance.UserHostCommandError{Command: "project_rename", Code: "PROJECT_IN_USE", Message: "occupied"}
	occupied := renameProjectRequest(server, token, source, "new-project")
	if occupied.Code != http.StatusConflict || !strings.Contains(occupied.Body.String(), `"code":"PROJECT_IN_USE"`) {
		t.Fatalf("occupied status=%d body=%s", occupied.Code, occupied.Body.String())
	}
}

func prepareProjectProfile(t *testing.T, server *Server, sid, profileName string) string {
	t.Helper()
	profilesRoot := t.TempDir()
	profile := filepath.Join(profilesRoot, profileName)
	workspace := filepath.Join(profile, config.UserDataDirectoryName, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := winutil.ApplyACL(workspace, winutil.PrivateTreePolicy(sid)); err != nil {
		t.Fatal(err)
	}
	server.cfg.UserProfilesRoot = profilesRoot
	server.profilePath = func(requestedSID string) (string, error) {
		if requestedSID == sid {
			return profile, nil
		}
		return "", store.ErrNotFound
	}
	return profile
}

func createProjectRequest(server *Server, token, body string) *httptest.ResponseRecorder {
	request := newCreateProjectRequest(token, body)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func newCreateProjectRequest(token, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/projects", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	if token != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	return request
}

func renameProjectRequest(server *Server, token, path, name string) *httptest.ResponseRecorder {
	body := `{"path":` + strconv.Quote(path) + `,"name":` + strconv.Quote(name) + `}`
	request := httptest.NewRequest(http.MethodPatch, "https://portal.example.test/api/portal/me/projects", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	if token != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
