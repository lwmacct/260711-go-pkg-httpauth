package authme_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/adapters/statictoken"
)

var testToken = "test-token/with.punctuation~1"

func TestDefaultPathPrefix(t *testing.T) {
	auth := newTestAuth(t, testToken)
	if auth.PathPrefix() != "/authme" {
		t.Fatalf("unexpected default path prefix: %q", auth.PathPrefix())
	}
}

func TestDefaultSessionTTL(t *testing.T) {
	config := authme.Config{Origins: []string{"https://tool.example.com"}}
	normalized, err := config.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Session.TTL != 24*time.Hour {
		t.Fatalf("unexpected default session TTL: %s", normalized.Session.TTL)
	}
}

func TestCustomPathPrefix(t *testing.T) {
	method, err := statictoken.New(statictoken.Config{Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", Token: testToken},
	}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authme.New(authme.Config{
		Prefix:  "/custom-auth",
		Origins: []string{"https://tool.example.com"},
		Session: authme.SessionConfig{Keys: []authme.SessionKey{testKey("primary", 1)}, TTL: 24 * time.Hour},
	}, authme.WithMethods(method))
	if err != nil {
		t.Fatal(err)
	}
	if auth.PathPrefix() != "/custom-auth" {
		t.Fatalf("unexpected custom path prefix: %q", auth.PathPrefix())
	}
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tool.example.com/custom-auth/session", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("custom path prefix was not routed: %d", recorder.Code)
	}
}

func TestTokenSessionLifecycle(t *testing.T) {
	auth := newTestAuth(t, testToken)
	handler := auth.Handler()

	login := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/authme/login/token", strings.NewReader(`{"token":"`+testToken+`"}`))
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
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/authme/session", nil)
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
	logoutRequest := httptest.NewRequest(http.MethodDelete, "https://tool.example.com/authme/session", nil)
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
	second := newTestAuth(t, "rotated-token")

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/authme/session", nil)
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

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/authme/session", nil)
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

func TestWithLoggerRecordsUnexpectedBearerFailure(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	auth := newTestAuthWithOptions(t, failingBearerMethod{err: errors.New("credential backend unavailable")}, authme.WithLogger(logger))

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/resource", nil)
	request.Header.Set("Authorization", "Bearer opaque-token")
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("unexpected bearer failure was ignored")
	}
	message := output.String()
	if !strings.Contains(message, `"msg":"authentication method failed"`) || !strings.Contains(message, `"method":"failing"`) || !strings.Contains(message, `"error":"credential backend unavailable"`) {
		t.Fatalf("unexpected log output: %s", message)
	}
}

func TestWithLoggerDoesNotRecordRejectedBearer(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	auth := newTestAuthWithOptions(t, failingBearerMethod{err: authme.ErrUnauthenticated}, authme.WithLogger(logger))

	request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/resource", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	if _, err := auth.Authenticate(request); !errors.Is(err, authme.ErrUnauthenticated) {
		t.Fatalf("unexpected authentication error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid credential was logged: %s", output.String())
	}
}

type failingBearerMethod struct{ err error }

func (f failingBearerMethod) Info() authme.MethodInfo {
	return authme.MethodInfo{ID: "failing", Flow: authme.LoginFlowSecret, Label: "Failing"}
}

func (f failingBearerMethod) LoginHandler(authme.SessionIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func (f failingBearerMethod) AuthenticateBearer(context.Context, string) (authme.Session, error) {
	return authme.Session{}, f.err
}

func (f failingBearerMethod) ValidateSession(context.Context, authme.Session) (authme.Principal, error) {
	return authme.Principal{}, authme.ErrUnauthenticated
}

func newTestAuth(t *testing.T, token string) *authme.Auth {
	t.Helper()
	return newTestAuthWithKeys(t, token, []authme.SessionKey{testKey("primary", 1)})
}

func newTestAuthWithKeys(t *testing.T, token string, keys []authme.SessionKey) *authme.Auth {
	t.Helper()
	method, err := statictoken.New(statictoken.Config{Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", Token: token},
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

func newTestAuthWithOptions(t *testing.T, method authme.Method, options ...authme.Option) *authme.Auth {
	t.Helper()
	options = append([]authme.Option{authme.WithMethods(method)}, options...)
	auth, err := authme.New(authme.Config{
		Origins: []string{"https://tool.example.com"},
		Session: authme.SessionConfig{Keys: []authme.SessionKey{testKey("primary", 1)}, TTL: 24 * time.Hour},
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func loginCookie(t *testing.T, auth *authme.Auth, token string) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://tool.example.com/authme/login/token", strings.NewReader(`{"token":"`+token+`"}`))
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
