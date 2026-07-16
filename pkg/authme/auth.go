package authme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/internal/model"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/internal/session"
)

type Auth struct {
	prefix         string
	origins        trustedOrigins
	codec          *session.Codec
	authorizer     Authorizer
	methods        []Method
	infos          []MethodInfo
	byID           map[string]Method
	routes         http.Handler
	cookieCleaners []func(http.ResponseWriter)
}

func New(config Config, options ...Option) (*Auth, error) {
	runtime := authOptions{}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("authme: option %d is nil", index)
		}
		if err := option.apply(&runtime); err != nil {
			return nil, fmt.Errorf("authme: apply option %d: %w", index, err)
		}
	}
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	origins, err := parseTrustedOrigins(normalized.Origins)
	if err != nil {
		return nil, err
	}
	if len(runtime.methods) == 0 {
		return nil, fmt.Errorf("%w: authentication methods are required", ErrInvalidConfig)
	}
	if runtime.clock == nil {
		runtime.clock = ClockFunc(time.Now)
	}
	codec, err := session.New(normalized.Session, origins.Secure(), runtime.random, runtime.clock.Now)
	if err != nil {
		return nil, err
	}
	auth := &Auth{prefix: normalized.Prefix, origins: origins, codec: codec, authorizer: runtime.authorizer, methods: append([]Method(nil), runtime.methods...), byID: make(map[string]Method, len(runtime.methods))}
	for _, method := range auth.methods {
		if method == nil {
			return nil, fmt.Errorf("%w: nil authentication method", ErrInvalidConfig)
		}
		info := method.Info()
		if info.ID == "" || info.Label == "" || (info.Flow != LoginFlowRedirect && info.Flow != LoginFlowSecret) || strings.ContainsAny(info.ID, "/?#") {
			return nil, fmt.Errorf("%w: authentication method", ErrInvalidConfig)
		}
		if _, exists := auth.byID[info.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate authentication method %q", ErrInvalidConfig, info.ID)
		}
		auth.byID[info.ID], auth.infos = method, append(auth.infos, info)
	}
	auth.routes, err = auth.buildHandler()
	if err != nil {
		return nil, err
	}
	return auth, nil
}

type boundIssuer struct {
	auth   *Auth
	method string
}

func (i boundIssuer) IssueSession(w http.ResponseWriter, session Session) error {
	return i.auth.codec.Issue(w, i.method, session)
}
func (i boundIssuer) ExternalURL(r *http.Request) (*url.URL, bool) {
	return i.auth.origins.ExternalURL(r)
}
func (i boundIssuer) Prefix() string { return i.auth.prefix }
func (i boundIssuer) Secure() bool   { return i.auth.origins.Secure() }
func (a *Auth) buildHandler() (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+a.prefix+"/session", a.session)
	mux.HandleFunc("DELETE "+a.prefix+"/session", a.logout)
	for _, method := range a.methods {
		info := method.Info()
		issuer := boundIssuer{auth: a, method: info.ID}
		switch info.Flow {
		case LoginFlowSecret:
			login, ok := method.(LoginMethod)
			if !ok {
				return nil, fmt.Errorf("%w: method %q secret routes", ErrInvalidConfig, info.ID)
			}
			mux.Handle("POST "+a.prefix+"/login/"+info.ID, a.requireSameOrigin(login.LoginHandler(issuer)))
		case LoginFlowRedirect:
			redirect, ok := method.(RedirectMethod)
			if !ok {
				return nil, fmt.Errorf("%w: method %q redirect routes", ErrInvalidConfig, info.ID)
			}
			mux.Handle("GET "+a.prefix+"/login/"+info.ID, redirect.LoginHandler(issuer))
			mux.Handle("GET "+a.prefix+"/callback/"+info.ID, redirect.CallbackHandler(issuer))
		}
		if cleaner, ok := method.(CookieCleaner); ok {
			a.cookieCleaners = append(a.cookieCleaners, cleaner.ClearCookies)
		}
	}
	return noStore(mux), nil
}
func (a *Auth) Handler() http.Handler { return a.routes }
func (a *Auth) Methods() []MethodInfo { return append([]MethodInfo(nil), a.infos...) }
func (a *Auth) Authenticate(r *http.Request) (Authentication, error) {
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		token, ok := bearerToken(authorization)
		if !ok {
			return Authentication{}, ErrUnauthenticated
		}
		for _, method := range a.methods {
			bearer, ok := method.(BearerMethod)
			if !ok {
				continue
			}
			session, err := bearer.AuthenticateBearer(r.Context(), token)
			if err == nil {
				return Authentication{Method: method.Info().ID, Transport: TransportBearer, CredentialID: session.CredentialID, Principal: session.Principal}, nil
			}
			if !errors.Is(err, ErrUnauthenticated) {
				return Authentication{}, err
			}
		}
		return Authentication{}, ErrUnauthenticated
	}
	envelope, err := a.codec.Read(r)
	if err != nil {
		return Authentication{}, ErrUnauthenticated
	}
	method, exists := a.byID[envelope.Method]
	if !exists {
		return Authentication{}, ErrUnauthenticated
	}
	principal, err := method.ValidateSession(r.Context(), envelope.Session)
	if err != nil {
		return Authentication{}, err
	}
	return Authentication{Method: envelope.Method, Transport: TransportSession, CredentialID: envelope.Session.CredentialID, Principal: principal}, nil
}
func (a *Auth) Authorize(ctx context.Context, authentication Authentication) error {
	if a.authorizer == nil {
		return nil
	}
	if err := a.authorizer.Authorize(ctx, authentication); err != nil {
		return fmt.Errorf("%w: %w", ErrForbidden, err)
	}
	return nil
}
func (a *Auth) RequireAuthenticated(next http.Handler) http.Handler { return a.require(next, false) }
func (a *Auth) RequireAccess(next http.Handler) http.Handler        { return a.require(next, true) }
func (a *Auth) require(next http.Handler, authorize bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authentication, err := a.Authenticate(r)
		if err != nil {
			if strings.TrimSpace(r.Header.Get("Authorization")) != "" && !errors.Is(err, ErrUnauthenticated) {
				WriteError(w, http.StatusServiceUnavailable, "authentication_unavailable", "Authentication unavailable")
				return
			}
			WriteError(w, http.StatusUnauthorized, "authentication_required", "Authentication required")
			return
		}
		if authentication.Transport == TransportSession && isUnsafeMethod(r.Method) && !a.origins.SameOrigin(r) {
			WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
			return
		}
		if authorize {
			if err := a.Authorize(r.Context(), authentication); err != nil {
				if errors.Is(err, ErrForbidden) {
					WriteError(w, http.StatusForbidden, "access_forbidden", "Access forbidden")
				} else {
					WriteError(w, http.StatusServiceUnavailable, "authorization_unavailable", "Authorization unavailable")
				}
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(model.ContextWithAuthentication(r.Context(), authentication)))
	})
}

type SessionStatus string
type AccessStatus string

const (
	SessionStatusAuthenticated SessionStatus = "authenticated"
	SessionStatusSignedOut     SessionStatus = "signed-out"
	AccessStatusGranted        AccessStatus  = "granted"
	AccessStatusDenied         AccessStatus  = "denied"
)

type SessionResponse struct {
	Status   SessionStatus `json:"status"`
	Method   string        `json:"method,omitempty"`
	Access   AccessStatus  `json:"access,omitempty"`
	Methods  []MethodInfo  `json:"methods"`
	Identity *Principal    `json:"identity,omitempty"`
}

func (a *Auth) session(w http.ResponseWriter, r *http.Request) {
	response := SessionResponse{Status: SessionStatusSignedOut, Methods: a.Methods()}
	authentication, err := a.Authenticate(r)
	if err != nil {
		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			WriteError(w, http.StatusUnauthorized, "invalid_bearer_token", "Invalid bearer token")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	response.Status, response.Method, response.Identity, response.Access = SessionStatusAuthenticated, authentication.Method, &authentication.Principal, AccessStatusGranted
	if err := a.Authorize(r.Context(), authentication); err != nil {
		response.Access = AccessStatusDenied
	}
	writeJSON(w, http.StatusOK, response)
}
func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if !a.origins.SameOrigin(r) {
		WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
		return
	}
	a.codec.Clear(w)
	for _, cleaner := range a.cookieCleaners {
		cleaner(w)
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *Auth) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.origins.SameOrigin(r) {
			WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func bearerToken(value string) (string, bool) {
	scheme, token, found := strings.Cut(value, " ")
	return token, found && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t\r\n")
}
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
