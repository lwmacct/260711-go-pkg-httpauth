package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth"
)

func TestOIDCLoginCallbackAndUnifiedSession(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	store := NewMemoryFlowStore()
	store.now = func() time.Time { return now }
	method, err := New(t.Context(), Config{ID: "github", Label: "GitHub", Issuer: provider.server.URL, ClientID: "tool", SessionTTL: 30 * time.Minute}, Options{
		HTTPClient: provider.server.Client(),
		FlowStore:  store,
		Now:        func() time.Time { return now },
		IdentityMapper: IdentityMapperFunc(func(_ context.Context, raw json.RawMessage) (httpauth.Principal, error) {
			var claims struct {
				Subject  string `json:"sub"`
				Username string `json:"preferred_username"`
			}
			if err := json.Unmarshal(raw, &claims); err != nil {
				return httpauth.Principal{}, err
			}
			return httpauth.Principal{Subject: claims.Subject, Username: claims.Username, Provider: "github"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := httpauth.New(httpauth.Config{
		ExternalURLs: []string{"https://tool.example.com", "https://other.example.com"},
		Session:      httpauth.SessionConfig{Keys: []httpauth.SessionKey{{ID: "primary", Secret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}}, TTL: 24 * time.Hour},
	}, []httpauth.Method{method}, httpauth.Options{})
	if err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRecorder()
	auth.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/login/github?return_to=%2F%23%2Fconsole", nil))
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if login.Code != http.StatusFound || query.Get("code_challenge_method") != "S256" || query.Get("state") == "" || query.Get("nonce") == "" || query.Get("redirect_uri") != "https://tool.example.com/auth/callback/github" {
		t.Fatalf("unexpected login redirect: status=%d location=%q", login.Code, location.String())
	}
	store.mu.Lock()
	flow := store.flows[query.Get("state")]
	store.mu.Unlock()
	provider.nonce = query.Get("nonce")
	provider.expectedVerifier = flow.Verifier
	provider.expectedRedirectURI = "https://tool.example.com/auth/callback/github"

	callbackRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/callback/github?code=code&state="+url.QueryEscape(query.Get("state")), nil)
	callbackRequest.AddCookie(login.Result().Cookies()[0])
	callback := httptest.NewRecorder()
	auth.Handler().ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "/#/console" {
		t.Fatalf("unexpected callback: status=%d location=%q body=%q", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	sessionCookie := findCookie(t, callback.Result().Cookies(), "__Host-httpauth")
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %#v", sessionCookie)
	}

	sessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/session", nil)
	sessionRequest.AddCookie(sessionCookie)
	session := httptest.NewRecorder()
	auth.Handler().ServeHTTP(session, sessionRequest)
	var response httpauth.SessionResponse
	if err := json.NewDecoder(session.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if session.Code != http.StatusOK || response.Status != httpauth.SessionStatusAuthenticated || response.Method != "github" || response.Identity == nil || response.Identity.Username != "admin" {
		t.Fatalf("unexpected session: status=%d response=%#v", session.Code, response)
	}

	replay := httptest.NewRecorder()
	auth.Handler().ServeHTTP(replay, callbackRequest)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback was accepted: %d", replay.Code)
	}
}

func TestOIDCCallbackMustUseLoginOrigin(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	method, err := New(t.Context(), Config{ID: "github", Label: "GitHub", Issuer: provider.server.URL, ClientID: "tool", SessionTTL: time.Hour}, Options{
		HTTPClient: provider.server.Client(),
		Now:        func() time.Time { return now },
		IdentityMapper: IdentityMapperFunc(func(context.Context, json.RawMessage) (httpauth.Principal, error) {
			return httpauth.Principal{Subject: "subject"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := httpauth.New(httpauth.Config{ExternalURLs: []string{"https://tool.example.com", "https://other.example.com"}, Session: httpauth.SessionConfig{Keys: []httpauth.SessionKey{{ID: "key", Secret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}}, TTL: time.Hour}}, []httpauth.Method{method}, httpauth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	auth.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/login/github", nil))
	location, _ := url.Parse(login.Header().Get("Location"))
	callback := httptest.NewRequest(http.MethodGet, "https://other.example.com/auth/callback/github?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(login.Result().Cookies()[0])
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, callback)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("cross-origin callback was accepted: %d", recorder.Code)
	}
}

type testProvider struct {
	server              *httptest.Server
	privateKey          *rsa.PrivateKey
	oidcServer          *oidctest.Server
	now                 time.Time
	nonce               string
	expectedVerifier    string
	expectedRedirectURI string
}

func newTestProvider(t *testing.T, now time.Time) *testProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProvider{privateKey: privateKey, now: now}
	provider.oidcServer = &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: privateKey.Public(), KeyID: "key", Algorithm: coreoidc.RS256}}}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	provider.oidcServer.SetIssuer(provider.server.URL)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *testProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" {
		p.oidcServer.ServeHTTP(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "tool" || r.Form.Get("client_secret") != "" || r.Form.Get("code_verifier") != p.expectedVerifier || r.Form.Get("redirect_uri") != p.expectedRedirectURI {
		http.Error(w, "invalid token request", http.StatusUnauthorized)
		return
	}
	claims := fmt.Sprintf(`{"iss":%q,"aud":"tool","sub":"subject","iat":%d,"exp":%d,"nonce":%q,"preferred_username":"admin"}`, p.server.URL, p.now.Unix(), p.now.Add(time.Hour).Unix(), p.nonce)
	raw := oidctest.SignIDToken(p.privateKey, "key", coreoidc.RS256, claims)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}
