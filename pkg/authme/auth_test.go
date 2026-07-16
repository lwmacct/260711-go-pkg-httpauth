package authme_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/adapters/statictoken"
)

var testToken = "example.10.admin." + strings.Repeat("Y", 32)

func TestTokenSessionLifecycle(t *testing.T) {
	auth := newTestAuth(t, testToken)
	handler := auth.Handler()

	login := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/auth/login/token", strings.NewReader(`{"token":"`+testToken+`"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("Origin", "https://tool.example.com")
	handler.ServeHTTP(login, loginRequest)
	if login.Code != http.StatusNoContent || len(login.Result().Cookies()) != 1 {
		t.Fatalf("unexpected login response: status=%d cookies=%d body=%q", login.Code, len(login.Result().Cookies()), login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	if cookie.Name != "__Host-authme" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode || strings.Contains(cookie.Value, testToken) {
		t.Fatalf("unexpected session cookie: %#v", cookie)
	}

	session := httptest.NewRecorder()
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/session", nil)
	sessionRequest.AddCookie(cookie)
	handler.ServeHTTP(session, sessionRequest)
	var response authme.SessionResponse
	if err := json.Unmarshal(session.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if session.Code != http.StatusOK || response.Status != authme.SessionStatusAuthenticated || response.Method != "token" || response.Access != authme.AccessStatusGranted || response.Identity == nil || response.Identity.Subject != "admin" || len(response.Methods) != 1 {
		t.Fatalf("unexpected session response: status=%d response=%#v", session.Code, response)
	}

	logout := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodDelete, "https://tool.example.com/auth/session", nil)
	logoutRequest.Header.Set("Origin", "https://tool.example.com")
	logoutRequest.AddCookie(cookie)
	handler.ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent || len(logout.Result().Cookies()) != 1 || logout.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("unexpected logout response: status=%d cookies=%#v", logout.Code, logout.Result().Cookies())
	}
}

func TestInvalidExplicitBearerDoesNotFallBackToSession(t *testing.T) {
	auth := newTestAuth(t, testToken)
	cookie := loginCookie(t, auth, testToken)

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/resource", nil)
	request.AddCookie(cookie)
	request.Header.Set("Authorization", "Bearer invalid-invalid-invalid")
	recorder := httptest.NewRecorder()
	auth.RequireAccess(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer fell back to session: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestSessionRevokedWhenTokenChanges(t *testing.T) {
	first := newTestAuth(t, testToken)
	cookie := loginCookie(t, first, testToken)
	second := newTestAuth(t, "example.10.admin."+strings.Repeat("Z", 32))

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/session", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	second.Handler().ServeHTTP(recorder, request)
	var response authme.SessionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || response.Status != authme.SessionStatusSignedOut {
		t.Fatalf("rotated token did not revoke session: status=%d response=%#v", recorder.Code, response)
	}
}

func TestSessionKeyRotation(t *testing.T) {
	oldKey := testKey("old", 1)
	newKey := testKey("new", 2)
	oldAuth := newTestAuthWithKeys(t, testToken, []authme.SessionKey{oldKey})
	cookie := loginCookie(t, oldAuth, testToken)
	rotated := newTestAuthWithKeys(t, testToken, []authme.SessionKey{newKey, oldKey})

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/session", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	rotated.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"authenticated"`) {
		t.Fatalf("old key could not read session after rotation: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestUnsafeSessionRequestRequiresTrustedOrigin(t *testing.T) {
	auth := newTestAuth(t, testToken)
	cookie := loginCookie(t, auth, testToken)
	request := httptest.NewRequest(http.MethodPost, "https://tool.example.com/api/resource", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	auth.RequireAccess(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unsafe session request without origin was accepted: %d", recorder.Code)
	}
}

func newTestAuth(t *testing.T, token string) *authme.Auth {
	t.Helper()
	return newTestAuthWithKeys(t, token, []authme.SessionKey{testKey("primary", 1)})
}

func newTestAuthWithKeys(t *testing.T, token string, keys []authme.SessionKey) *authme.Auth {
	t.Helper()
	digest, err := statictoken.Digest("example", token)
	if err != nil {
		t.Fatal(err)
	}
	method, err := statictoken.New(statictoken.Config{Namespace: "example", Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", TokenSHA256: digest},
	}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authme.New(authme.Config{
		Origins: []string{"https://tool.example.com"},
		Session: authme.SessionConfig{Keys: keys, TTL: 24 * time.Hour},
	}, authme.WithMethods(method))
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func loginCookie(t *testing.T, auth *authme.Auth, token string) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://tool.example.com/auth/login/token", strings.NewReader(`{"token":"`+token+`"}`))
	request.Header.Set("Origin", "https://tool.example.com")
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("login failed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	return recorder.Result().Cookies()[0]
}

func testKey(id string, fill byte) authme.SessionKey {
	return authme.SessionKey{ID: id, Secret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(fill), 32)))}
}
