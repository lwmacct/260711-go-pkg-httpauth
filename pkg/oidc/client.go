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
	"net/http"
	"net/url"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidFlow     = errors.New("invalid OIDC flow")
	ErrExchange        = errors.New("OIDC code exchange failed")
	ErrInvalidIdentity = errors.New("invalid OIDC identity")
)

const maxIdentityTokenLen = 16 << 10

type Flow struct {
	State       string
	Nonce       string
	Verifier    string
	RedirectURI string
}

type Identity struct {
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Claims    json.RawMessage
}

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

type Client struct {
	options  options
	oauth    oauth2.Config
	verifier *coreoidc.IDTokenVerifier
}

func New(ctx context.Context, config Config, opts ...Option) (*Client, error) {
	var runtime options
	for index, option := range opts {
		if option == nil {
			return nil, fmt.Errorf("oidc: option %d is nil", index)
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
	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, runtime.httpClient), normalized.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if normalized.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	} else {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	return &Client{
		options:  runtime,
		oauth:    oauth2.Config{ClientID: normalized.ClientID, ClientSecret: normalized.ClientSecret, Endpoint: endpoint, Scopes: append([]string(nil), normalized.Scopes...)},
		verifier: provider.Verifier(&coreoidc.Config{ClientID: normalized.ClientID}),
	}, nil
}

func (c *Client) NewFlow(redirectURI string) (Flow, error) {
	redirectURI = strings.TrimSpace(redirectURI)
	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Flow{}, fmt.Errorf("%w: redirect URI", ErrInvalidFlow)
	}
	state, err := randomToken(c.options.random)
	if err != nil {
		return Flow{}, fmt.Errorf("generate OIDC state: %w", err)
	}
	nonce, err := randomToken(c.options.random)
	if err != nil {
		return Flow{}, fmt.Errorf("generate OIDC nonce: %w", err)
	}
	verifier, err := randomToken(c.options.random)
	if err != nil {
		return Flow{}, fmt.Errorf("generate OIDC PKCE verifier: %w", err)
	}
	return Flow{State: state, Nonce: nonce, Verifier: verifier, RedirectURI: redirectURI}, nil
}

func (c *Client) AuthorizationURL(flow Flow) (*url.URL, error) {
	if err := validateFlow(flow); err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(flow.Verifier))
	config := c.oauth
	config.RedirectURL = flow.RedirectURI
	value := config.AuthCodeURL(flow.State,
		coreoidc.Nonce(flow.Nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	return url.Parse(value)
}

func (c *Client) Exchange(ctx context.Context, flow Flow, code string) (Identity, error) {
	if err := validateFlow(flow); err != nil {
		return Identity{}, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return Identity{}, fmt.Errorf("%w: authorization code", ErrInvalidFlow)
	}
	config := c.oauth
	config.RedirectURL = flow.RedirectURI
	token, err := config.Exchange(coreoidc.ClientContext(ctx, c.options.httpClient), code, oauth2.SetAuthURLParam("code_verifier", flow.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" || len(raw) > maxIdentityTokenLen {
		return Identity{}, fmt.Errorf("%w: ID token missing", ErrInvalidIdentity)
	}
	idToken, err := c.verifier.Verify(coreoidc.ClientContext(ctx, c.options.httpClient), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: verify ID token: %v", ErrInvalidIdentity, err)
	}
	if idToken.Nonce != flow.Nonce {
		return Identity{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidIdentity)
	}
	var claims struct {
		Subject  string `json:"sub"`
		IssuedAt int64  `json:"iat"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.IssuedAt == 0 {
		return Identity{}, fmt.Errorf("%w: required claims missing", ErrInvalidIdentity)
	}
	var rawClaims json.RawMessage
	if err := idToken.Claims(&rawClaims); err != nil {
		return Identity{}, fmt.Errorf("%w: decode claims: %v", ErrInvalidIdentity, err)
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	if !idToken.Expiry.After(c.options.now()) {
		return Identity{}, fmt.Errorf("%w: ID token expired", ErrInvalidIdentity)
	}
	return Identity{Subject: claims.Subject, IssuedAt: issuedAt, ExpiresAt: idToken.Expiry, Claims: rawClaims}, nil
}

func validateFlow(flow Flow) error {
	if flow.State == "" || flow.Nonce == "" || flow.Verifier == "" || flow.RedirectURI == "" {
		return fmt.Errorf("%w: missing state, nonce, verifier or redirect URI", ErrInvalidFlow)
	}
	return nil
}

func randomToken(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
