package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/lwmacct/260711-go-pkg-httpauth"
	"golang.org/x/oauth2"
)

const (
	flowTTL             = 5 * time.Minute
	maxIdentityTokenLen = 16 << 10
)

type IdentityMapper interface {
	MapIdentity(context.Context, json.RawMessage) (httpauth.Principal, error)
}

type IdentityMapperFunc func(context.Context, json.RawMessage) (httpauth.Principal, error)

func (f IdentityMapperFunc) MapIdentity(ctx context.Context, claims json.RawMessage) (httpauth.Principal, error) {
	return f(ctx, claims)
}

type Options struct {
	HTTPClient     *http.Client
	Logger         *slog.Logger
	IdentityMapper IdentityMapper
	FlowStore      FlowStore
	ExtraScopes    []string
	Random         io.Reader
	Now            func() time.Time
}

type Method struct {
	config       Config
	options      Options
	oauth        oauth2.Config
	verifier     *coreoidc.IDTokenVerifier
	externalURLs map[string]*url.URL
	callbackPath string
	flowCookie   string
	secure       bool
}

type baseClaims struct {
	IssuedAt int64 `json:"iat"`
}

func New(ctx context.Context, config Config, options Options) (*Method, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	if options.IdentityMapper == nil {
		return nil, fmt.Errorf("%w: identity mapper is required", ErrInvalidConfig)
	}
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.FlowStore == nil {
		options.FlowStore = NewMemoryFlowStore()
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	providerCtx := coreoidc.ClientContext(ctx, options.HTTPClient)
	provider, err := coreoidc.NewProvider(providerCtx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if config.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	} else {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	scopes := append([]string{coreoidc.ScopeOpenID, "profile"}, options.ExtraScopes...)
	return &Method{
		config:     config,
		options:    options,
		oauth:      oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: endpoint, Scopes: scopes},
		verifier:   provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}),
		flowCookie: "httpauth_flow_" + shortHash(config.ID+":"+config.ClientID),
	}, nil
}

func (m *Method) Info() httpauth.MethodInfo {
	return httpauth.MethodInfo{ID: m.config.ID, Flow: httpauth.LoginFlowRedirect, Label: m.config.Label}
}

func (m *Method) BindRoutes(config httpauth.RouteConfig) error {
	urls := make(map[string]*url.URL, len(config.ExternalURLs))
	secure := false
	for index, value := range config.ExternalURLs {
		parsed, err := url.Parse(strings.TrimRight(value, "/"))
		if err != nil || parsed.Host == "" {
			return ErrInvalidConfig
		}
		if index == 0 {
			secure = parsed.Scheme == "https"
		}
		urls[strings.ToLower(parsed.Host)] = parsed
	}
	m.externalURLs = urls
	m.callbackPath = strings.TrimRight(config.PathPrefix, "/") + "/callback/" + m.config.ID
	m.secure = secure
	if secure {
		m.flowCookie = "__Host-" + m.flowCookie
	}
	return nil
}

func (m *Method) LoginHandler(_ httpauth.SessionIssuer) http.Handler {
	return http.HandlerFunc(m.login)
}

func (m *Method) CallbackHandler(issuer httpauth.SessionIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.callback(issuer, w, r) })
}

func (m *Method) ValidateSession(_ context.Context, session httpauth.Session) (httpauth.Principal, error) {
	if session.Method != m.config.ID || session.Principal.Subject == "" {
		return httpauth.Principal{}, httpauth.ErrUnauthenticated
	}
	return session.Principal, nil
}

func (m *Method) ClearCookies(w http.ResponseWriter) {
	m.setFlowCookie(w, "", -1)
}

func (m *Method) login(w http.ResponseWriter, r *http.Request) {
	externalURL, ok := m.externalURL(r)
	if !ok {
		httpauth.WriteError(w, http.StatusBadRequest, "untrusted_host", "Untrusted request host")
		return
	}
	returnTo, err := normalizeReturnTo(r.URL.Query().Get("return_to"))
	if err != nil {
		httpauth.WriteError(w, http.StatusBadRequest, "invalid_return_to", "Invalid return path")
		return
	}
	state, err := randomToken(m.options.Random)
	if err != nil {
		httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
		return
	}
	nonce, err := randomToken(m.options.Random)
	if err != nil {
		httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
		return
	}
	verifier, err := randomToken(m.options.Random)
	if err != nil {
		httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
		return
	}
	flow := LoginFlow{State: state, Nonce: nonce, Verifier: verifier, ExternalURL: externalURL.String(), ReturnTo: returnTo, ExpiresAt: m.options.Now().Add(flowTTL)}
	if err := m.options.FlowStore.Create(r.Context(), flow); err != nil {
		httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
		return
	}
	m.setFlowCookie(w, state, int(flowTTL.Seconds()))
	challenge := sha256.Sum256([]byte(verifier))
	oauthConfig := m.oauthFor(externalURL)
	location := oauthConfig.AuthCodeURL(state, coreoidc.Nonce(nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, r, location, http.StatusFound)
}

func (m *Method) callback(issuer httpauth.SessionIssuer, w http.ResponseWriter, r *http.Request) {
	externalURL, ok := m.externalURL(r)
	if !ok {
		httpauth.WriteError(w, http.StatusBadRequest, "untrusted_host", "Untrusted request host")
		return
	}
	state := r.URL.Query().Get("state")
	flowCookie, cookieErr := r.Cookie(m.flowCookie)
	m.setFlowCookie(w, "", -1)
	flow, flowErr := m.options.FlowStore.Consume(r.Context(), state)
	if cookieErr != nil || flowCookie.Value != state || flowErr != nil || flow.ExternalURL != externalURL.String() || r.URL.Query().Get("code") == "" {
		httpauth.WriteError(w, http.StatusBadRequest, "invalid_oidc_flow", "Invalid or expired login")
		return
	}
	ctx := coreoidc.ClientContext(r.Context(), m.options.HTTPClient)
	oauthConfig := m.oauthFor(externalURL)
	token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", flow.Verifier))
	if err != nil {
		m.options.Logger.Warn("OIDC code exchange failed", "error", err)
		httpauth.WriteError(w, http.StatusBadGateway, "oidc_exchange_failed", "Login failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" || len(rawIDToken) > maxIdentityTokenLen {
		httpauth.WriteError(w, http.StatusBadGateway, "oidc_identity_missing", "OIDC identity missing")
		return
	}
	idToken, principal, claims, err := m.verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != flow.Nonce {
		m.options.Logger.Warn("OIDC identity validation failed", "error", err)
		httpauth.WriteError(w, http.StatusUnauthorized, "invalid_oidc_identity", "Invalid OIDC identity")
		return
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := issuedAt.Add(m.config.SessionTTL)
	if idToken.Expiry.Before(expiresAt) {
		expiresAt = idToken.Expiry
	}
	if !expiresAt.After(m.options.Now()) {
		httpauth.WriteError(w, http.StatusUnauthorized, "expired_oidc_identity", "OIDC identity expired")
		return
	}
	if err := issuer.IssueSession(w, httpauth.Session{Method: m.config.ID, CredentialID: principal.Subject, IssuedAt: issuedAt, ExpiresAt: expiresAt, Principal: principal}); err != nil {
		httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
		return
	}
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func (m *Method) verify(ctx context.Context, raw string) (*coreoidc.IDToken, httpauth.Principal, baseClaims, error) {
	idToken, err := m.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, httpauth.Principal{}, baseClaims{}, err
	}
	var claims baseClaims
	if err := idToken.Claims(&claims); err != nil || claims.IssuedAt == 0 {
		return nil, httpauth.Principal{}, claims, errors.New("identity token issued-at claim missing")
	}
	var rawClaims json.RawMessage
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, httpauth.Principal{}, claims, err
	}
	principal, err := m.options.IdentityMapper.MapIdentity(ctx, rawClaims)
	if err != nil || principal.Subject == "" {
		return nil, httpauth.Principal{}, claims, errors.New("map OIDC identity")
	}
	return idToken, principal, claims, nil
}

func (m *Method) externalURL(r *http.Request) (*url.URL, bool) {
	externalURL, ok := m.externalURLs[strings.ToLower(r.Host)]
	return externalURL, ok
}

func (m *Method) oauthFor(externalURL *url.URL) oauth2.Config {
	config := m.oauth
	config.RedirectURL = externalURL.String() + m.callbackPath
	return config
}

func (m *Method) setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: m.flowCookie, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode})
}

func normalizeReturnTo(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(value, "\\") {
		return "", errors.New("return path must be same-origin")
	}
	return parsed.String(), nil
}

func randomToken(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:6])
}
