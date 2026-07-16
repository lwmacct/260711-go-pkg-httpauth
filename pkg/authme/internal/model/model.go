package model

import (
	"context"
	"time"
)

type SessionKey struct {
	ID     string `json:"id" desc:"Session key ID"`
	Secret string `json:"secret" desc:"Base64url-encoded 32-byte AES key"`
}

type SessionConfig struct {
	Keys       []SessionKey  `json:"keys" desc:"Session encryption key ring; first key writes, all keys read"`
	TTL        time.Duration `json:"ttl" desc:"Maximum browser session lifetime"`
	CookieName string        `json:"cookie-name" desc:"Optional browser session cookie name"`
}

type LoginFlow string

const (
	LoginFlowRedirect LoginFlow = "redirect"
	LoginFlowSecret   LoginFlow = "secret"
)

type MethodInfo struct {
	ID    string    `json:"id"`
	Flow  LoginFlow `json:"flow"`
	Label string    `json:"label"`
}

type Principal struct {
	Subject        string `json:"subject"`
	Username       string `json:"username"`
	Name           string `json:"name,omitempty"`
	Email          string `json:"email,omitempty"`
	AvatarURL      string `json:"avatar_url,omitempty"`
	Provider       string `json:"provider,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
}

type Session struct {
	CredentialID string
	Revision     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Principal    Principal
}

type Transport string

const (
	TransportBearer  Transport = "bearer"
	TransportSession Transport = "session"
)

type Authentication struct {
	Method       string    `json:"method"`
	Transport    Transport `json:"transport"`
	CredentialID string    `json:"-"`
	Principal    Principal `json:"identity"`
}

type Authorizer interface {
	Authorize(context.Context, Authentication) error
}
type contextKey struct{}

func ContextWithAuthentication(ctx context.Context, authentication Authentication) context.Context {
	return context.WithValue(ctx, contextKey{}, authentication)
}
func AuthenticationFromContext(ctx context.Context) (Authentication, bool) {
	value, ok := ctx.Value(contextKey{}).(Authentication)
	return value, ok
}
