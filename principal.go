package httpauth

import "context"

type Transport string

const (
	TransportBearer  Transport = "bearer"
	TransportSession Transport = "session"
)

type Principal struct {
	Subject        string `json:"subject"`
	Username       string `json:"username"`
	Name           string `json:"name,omitempty"`
	Email          string `json:"email,omitempty"`
	AvatarURL      string `json:"avatar_url,omitempty"`
	Provider       string `json:"provider,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
}

type Authentication struct {
	Method       string    `json:"method"`
	Transport    Transport `json:"transport"`
	CredentialID string    `json:"-"`
	Principal    Principal `json:"identity"`
}

type Authorizer interface {
	Authorize(context.Context, Authentication) error
}

type AuthorizerFunc func(context.Context, Authentication) error

func (f AuthorizerFunc) Authorize(ctx context.Context, authentication Authentication) error {
	return f(ctx, authentication)
}

func AuthorizeAll(authorizers ...Authorizer) Authorizer {
	return AuthorizerFunc(func(ctx context.Context, authentication Authentication) error {
		for _, authorizer := range authorizers {
			if authorizer != nil {
				if err := authorizer.Authorize(ctx, authentication); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

type authenticationContextKey struct{}

func AuthenticationFromContext(ctx context.Context) (Authentication, bool) {
	authentication, ok := ctx.Value(authenticationContextKey{}).(Authentication)
	return authentication, ok
}

func contextWithAuthentication(ctx context.Context, authentication Authentication) context.Context {
	return context.WithValue(ctx, authenticationContextKey{}, authentication)
}
