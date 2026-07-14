package httpauth

import (
	"context"
	"net/http"
	"time"
)

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

type Session struct {
	Method       string
	CredentialID string
	Revision     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Principal    Principal
}

type SessionIssuer interface {
	IssueSession(http.ResponseWriter, Session) error
}

type Method interface {
	Info() MethodInfo
	LoginHandler(SessionIssuer) http.Handler
	ValidateSession(context.Context, Session) (Principal, error)
}

type RouteConfig struct {
	PathPrefix   string
	ExternalURLs []string
}

type RouteBinder interface {
	BindRoutes(RouteConfig) error
}

type CallbackMethod interface {
	CallbackHandler(SessionIssuer) http.Handler
}

type BearerMethod interface {
	AuthenticateBearer(context.Context, string) (Session, error)
}

type CookieCleaner interface {
	ClearCookies(http.ResponseWriter)
}
