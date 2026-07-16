package authme

import (
	"context"
	"net/http"
	"net/url"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/internal/model"
)

type LoginFlow = model.LoginFlow

const (
	LoginFlowRedirect = model.LoginFlowRedirect
	LoginFlowSecret   = model.LoginFlowSecret
)

type MethodInfo = model.MethodInfo
type Session = model.Session
type SessionKey = model.SessionKey
type SessionConfig = model.SessionConfig
type Transport = model.Transport

const (
	TransportBearer  = model.TransportBearer
	TransportSession = model.TransportSession
)

type Principal = model.Principal
type Authentication = model.Authentication
type Authorizer = model.Authorizer
type AuthorizerFunc func(context.Context, Authentication) error

func (f AuthorizerFunc) Authorize(ctx context.Context, authentication Authentication) error {
	return f(ctx, authentication)
}
func Chain(authorizers ...Authorizer) Authorizer {
	configured := append([]Authorizer(nil), authorizers...)
	return AuthorizerFunc(func(ctx context.Context, authentication Authentication) error {
		for _, authorizer := range configured {
			if authorizer != nil {
				if err := authorizer.Authorize(ctx, authentication); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func AuthenticationFromContext(ctx context.Context) (Authentication, bool) {
	return model.AuthenticationFromContext(ctx)
}

type SessionIssuer interface {
	IssueSession(http.ResponseWriter, Session) error
}

// RedirectContext exposes the route information needed by a redirect adapter.
type RedirectContext interface {
	SessionIssuer
	ExternalURL(*http.Request) (*url.URL, bool)
	Prefix() string
	Secure() bool
}
type Method interface {
	Info() MethodInfo
	ValidateSession(context.Context, Session) (Principal, error)
}
type BearerMethod interface {
	AuthenticateBearer(context.Context, string) (Session, error)
}
type LoginMethod interface {
	LoginHandler(SessionIssuer) http.Handler
}
type RedirectMethod interface {
	LoginHandler(RedirectContext) http.Handler
	CallbackHandler(RedirectContext) http.Handler
}
type CookieCleaner interface{ ClearCookies(http.ResponseWriter) }
