package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

func TestClientFlowAndExchange(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	client, err := New(t.Context(), Config{Issuer: provider.server.URL, ClientID: "tool"}, WithHTTPClient(provider.server.Client()), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	flow, err := client.NewFlow("https://tool.example.com/authme/callback/github")
	if err != nil {
		t.Fatal(err)
	}
	location, err := client.AuthorizationURL(flow)
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if query.Get("state") != flow.State || query.Get("nonce") != flow.Nonce || query.Get("code_challenge_method") != "S256" || query.Get("redirect_uri") != flow.RedirectURI {
		t.Fatalf("unexpected authorization URL: %s", location)
	}
	provider.nonce = flow.Nonce
	provider.verifier = flow.Verifier
	provider.redirectURI = flow.RedirectURI
	identity, err := client.Exchange(t.Context(), flow, "code")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "subject" || !identity.IssuedAt.Equal(now) || !identity.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

type testProvider struct {
	server      *httptest.Server
	oidcServer  *oidctest.Server
	privateKey  *rsa.PrivateKey
	now         time.Time
	nonce       string
	verifier    string
	redirectURI string
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
	if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "tool" || r.Form.Get("code_verifier") != p.verifier || r.Form.Get("redirect_uri") != p.redirectURI {
		http.Error(w, "invalid token request", http.StatusUnauthorized)
		return
	}
	claims := fmt.Sprintf(`{"iss":%q,"aud":"tool","sub":"subject","iat":%d,"exp":%d,"nonce":%q}`, p.server.URL, p.now.Unix(), p.now.Add(time.Hour).Unix(), p.nonce)
	raw := oidctest.SignIDToken(p.privateKey, "key", coreoidc.RS256, claims)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
}
