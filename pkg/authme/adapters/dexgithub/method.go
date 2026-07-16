package dexgithub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/internal/browserflow"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/oidc"
)

type Option interface{ apply(*options) error }
type options struct {
	httpClient *http.Client
	random     io.Reader
	now        func() time.Time
}
type optionFunc func(*options) error

func (f optionFunc) apply(value *options) error { return f(value) }
func WithHTTPClient(client *http.Client) Option {
	return optionFunc(func(value *options) error { value.httpClient = client; return nil })
}
func WithRandom(random io.Reader) Option {
	return optionFunc(func(value *options) error { value.random = random; return nil })
}
func WithClock(now func() time.Time) Option {
	return optionFunc(func(value *options) error { value.now = now; return nil })
}

type Method struct {
	config  Config
	options options
	client  *oidc.Client
	flows   browserflow.Store
}

func New(ctx context.Context, config Config, opts ...Option) (*Method, error) {
	var runtime options
	for index, option := range opts {
		if option == nil {
			return nil, fmt.Errorf("dexgithub: option %d is nil", index)
		}
		if err := option.apply(&runtime); err != nil {
			return nil, err
		}
	}
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	if runtime.httpClient == nil {
		runtime.httpClient = http.DefaultClient
	}
	if runtime.random == nil {
		runtime.random = rand.Reader
	}
	if runtime.now == nil {
		runtime.now = time.Now
	}
	flows := browserflow.NewMemoryStore(browserflow.WithClock(runtime.now))
	client, err := oidc.New(ctx, oidc.Config{Issuer: normalized.Issuer, ClientID: normalized.ClientID, ClientSecret: normalized.ClientSecret, Scopes: []string{"openid", "profile", "federated:id"}}, oidc.WithHTTPClient(runtime.httpClient), oidc.WithRandom(runtime.random), oidc.WithClock(runtime.now))
	if err != nil {
		return nil, err
	}
	return &Method{config: normalized, options: runtime, client: client, flows: flows}, nil
}

func (m *Method) Info() authme.MethodInfo {
	return authme.MethodInfo{ID: m.config.ID, Flow: authme.LoginFlowRedirect, Label: m.config.Label}
}

func (m *Method) LoginHandler(issuer authme.RedirectContext) http.Handler {
	secure := issuer.Secure()
	flowCookie := browserflow.CookieName(m.config.ID+":"+m.config.ClientID, secure)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		external, ok := issuer.ExternalURL(r)
		if !ok {
			authme.WriteError(w, http.StatusBadRequest, "untrusted_host", "Untrusted request host")
			return
		}
		returnTo, err := browserflow.NormalizeReturnTo(r.URL.Query().Get("return_to"))
		if err != nil {
			authme.WriteError(w, http.StatusBadRequest, "invalid_return_to", "Invalid return path")
			return
		}
		redirectURI := external.String() + strings.TrimRight(issuer.Prefix(), "/") + "/callback/" + m.config.ID
		flow, err := m.client.NewFlow(redirectURI)
		if err != nil {
			authme.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		flowState := browserflow.Flow{State: flow.State, Nonce: flow.Nonce, Verifier: flow.Verifier, RedirectURI: flow.RedirectURI, Origin: external.String(), ReturnTo: returnTo, ExpiresAt: m.options.now().Add(m.config.FlowTTL)}
		if err := m.flows.Create(r.Context(), flowState); err != nil {
			authme.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		browserflow.SetCookie(w, flowCookie, flow.State, int(m.config.FlowTTL.Seconds()), secure)
		location, err := m.client.AuthorizationURL(flow)
		if err != nil {
			authme.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		http.Redirect(w, r, location.String(), http.StatusFound)
	})
}

func (m *Method) CallbackHandler(issuer authme.RedirectContext) http.Handler {
	secure := issuer.Secure()
	flowCookie := browserflow.CookieName(m.config.ID+":"+m.config.ClientID, secure)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		external, ok := issuer.ExternalURL(r)
		if !ok {
			authme.WriteError(w, http.StatusBadRequest, "untrusted_host", "Untrusted request host")
			return
		}
		state := r.URL.Query().Get("state")
		cookie, cookieErr := r.Cookie(flowCookie)
		browserflow.ClearCookie(w, flowCookie, secure)
		flow, flowErr := m.flows.Consume(r.Context(), state)
		if cookieErr != nil || cookie.Value != state || flowErr != nil || flow.Origin != external.String() || r.URL.Query().Get("code") == "" {
			authme.WriteError(w, http.StatusBadRequest, "invalid_oidc_flow", "Invalid or expired login")
			return
		}
		identity, err := m.client.Exchange(r.Context(), oidc.Flow{State: flow.State, Nonce: flow.Nonce, Verifier: flow.Verifier, RedirectURI: flow.RedirectURI}, r.URL.Query().Get("code"))
		if err != nil {
			if errors.Is(err, oidc.ErrExchange) {
				authme.WriteError(w, http.StatusBadGateway, "oidc_exchange_failed", "Login failed")
				return
			}
			authme.WriteError(w, http.StatusUnauthorized, "invalid_oidc_identity", "Invalid OIDC identity")
			return
		}
		principal, err := mapClaims(identity.Claims)
		if err != nil {
			authme.WriteError(w, http.StatusUnauthorized, "invalid_oidc_identity", "Invalid OIDC identity")
			return
		}
		expiresAt := identity.IssuedAt.Add(m.config.SessionTTL)
		if identity.ExpiresAt.Before(expiresAt) {
			expiresAt = identity.ExpiresAt
		}
		if !expiresAt.After(m.options.now()) {
			authme.WriteError(w, http.StatusUnauthorized, "expired_oidc_identity", "OIDC identity expired")
			return
		}
		if err := issuer.IssueSession(w, authme.Session{CredentialID: principal.Subject, IssuedAt: identity.IssuedAt, ExpiresAt: expiresAt, Principal: principal}); err != nil {
			authme.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
	})
}

func (m *Method) ClearCookies(w http.ResponseWriter) {
	base := m.config.ID + ":" + m.config.ClientID
	browserflow.ClearCookie(w, browserflow.CookieName(base, false), false)
	browserflow.ClearCookie(w, browserflow.CookieName(base, true), true)
}

func (m *Method) ValidateSession(_ context.Context, session authme.Session) (authme.Principal, error) {
	if session.Principal.Subject == "" || session.Principal.Provider != "github" || session.Principal.ProviderUserID == "" {
		return authme.Principal{}, authme.ErrUnauthenticated
	}
	return session.Principal, nil
}

type claims struct {
	Subject           string `json:"sub"`
	Username          string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	FederatedIdentity struct {
		ConnectorID string `json:"connector_id"`
		UserID      string `json:"user_id"`
	} `json:"federated_claims"`
}

func mapClaims(raw json.RawMessage) (authme.Principal, error) {
	var value claims
	if err := json.Unmarshal(raw, &value); err != nil {
		return authme.Principal{}, err
	}
	value.Username = strings.TrimSpace(value.Username)
	value.FederatedIdentity.UserID = strings.TrimSpace(value.FederatedIdentity.UserID)
	if value.Subject == "" || value.Username == "" || value.FederatedIdentity.ConnectorID != "github" || value.FederatedIdentity.UserID == "" {
		return authme.Principal{}, errors.New("required Dex GitHub identity claims missing")
	}
	return authme.Principal{Subject: value.Subject, Username: value.Username, Name: value.Name, Email: value.Email, AvatarURL: "https://avatars.githubusercontent.com/u/" + url.PathEscape(value.FederatedIdentity.UserID) + "?v=4", Provider: "github", ProviderUserID: value.FederatedIdentity.UserID}, nil
}
