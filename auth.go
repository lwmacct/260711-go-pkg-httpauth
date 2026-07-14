package httpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	ExternalURLs []string      `json:"external-urls" desc:"Trusted browser origins"`
	PathPrefix   string        `json:"path-prefix"   desc:"Authentication HTTP path prefix"`
	Session      SessionConfig `json:"session"       desc:"Browser session configuration"`
}

type Options struct {
	Authorizer Authorizer
	Random     io.Reader
	Now        func() time.Time
}

type Auth struct {
	prefix     string
	origins    trustedOrigins
	codec      *sessionCodec
	authorizer Authorizer
	methods    []Method
	byID       map[string]Method
}

func (c Config) Validate() (Config, error) {
	origins, err := parseTrustedOrigins(c.ExternalURLs)
	if err != nil {
		return c, err
	}
	c.PathPrefix = strings.TrimRight(strings.TrimSpace(c.PathPrefix), "/")
	if c.PathPrefix == "" {
		c.PathPrefix = "/auth"
	}
	if !strings.HasPrefix(c.PathPrefix, "/") || strings.ContainsAny(c.PathPrefix, "?#") {
		return c, fmt.Errorf("%w: path prefix", ErrInvalidConfig)
	}
	for index, externalURL := range c.ExternalURLs {
		c.ExternalURLs[index] = strings.TrimRight(strings.TrimSpace(externalURL), "/")
	}
	if _, err := newSessionCodec(c.Session, origins.secure, strings.NewReader(strings.Repeat("x", 64)), time.Now); err != nil {
		return c, err
	}
	return c, nil
}

func New(config Config, methods []Method, options Options) (*Auth, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	origins, err := parseTrustedOrigins(config.ExternalURLs)
	if err != nil {
		return nil, err
	}
	prefix := config.PathPrefix
	codec, err := newSessionCodec(config.Session, origins.secure, options.Random, options.Now)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: authentication methods are required", ErrInvalidConfig)
	}
	byID := make(map[string]Method, len(methods))
	for _, method := range methods {
		if method == nil {
			return nil, fmt.Errorf("%w: nil authentication method", ErrInvalidConfig)
		}
		info := method.Info()
		if info.ID == "" || info.Label == "" || (info.Flow != LoginFlowRedirect && info.Flow != LoginFlowSecret) || strings.Contains(info.ID, "/") {
			return nil, fmt.Errorf("%w: authentication method", ErrInvalidConfig)
		}
		if _, exists := byID[info.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate authentication method %q", ErrInvalidConfig, info.ID)
		}
		if binder, ok := method.(RouteBinder); ok {
			if err := binder.BindRoutes(RouteConfig{PathPrefix: prefix, ExternalURLs: append([]string(nil), config.ExternalURLs...)}); err != nil {
				return nil, fmt.Errorf("bind authentication method %q routes: %w", info.ID, err)
			}
		}
		byID[info.ID] = method
	}
	return &Auth{prefix: prefix, origins: origins, codec: codec, authorizer: options.Authorizer, methods: append([]Method(nil), methods...), byID: byID}, nil
}

func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+a.prefix+"/session", a.session)
	mux.HandleFunc("DELETE "+a.prefix+"/session", a.logout)
	for _, method := range a.methods {
		info := method.Info()
		if info.Flow == LoginFlowSecret {
			mux.Handle("POST "+a.prefix+"/login/"+info.ID, a.requireSameOrigin(method.LoginHandler(a)))
		} else {
			mux.Handle("GET "+a.prefix+"/login/"+info.ID, method.LoginHandler(a))
		}
		if callback, ok := method.(CallbackMethod); ok {
			mux.Handle("GET "+a.prefix+"/callback/"+info.ID, callback.CallbackHandler(a))
		}
	}
	return noStore(mux)
}

func (a *Auth) IssueSession(w http.ResponseWriter, session Session) error {
	if _, exists := a.byID[session.Method]; !exists {
		return ErrInvalidSession
	}
	return a.codec.issue(w, session)
}

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
				return Authentication{Method: session.Method, Transport: TransportBearer, CredentialID: session.CredentialID, Principal: session.Principal}, nil
			}
		}
		return Authentication{}, ErrUnauthenticated
	}
	session, err := a.codec.read(r)
	if err != nil {
		return Authentication{}, ErrUnauthenticated
	}
	method, exists := a.byID[session.Method]
	if !exists {
		return Authentication{}, ErrUnauthenticated
	}
	principal, err := method.ValidateSession(r.Context(), session)
	if err != nil {
		return Authentication{}, ErrUnauthenticated
	}
	return Authentication{Method: session.Method, Transport: TransportSession, CredentialID: session.CredentialID, Principal: principal}, nil
}

func (a *Auth) Authorize(ctx context.Context, authentication Authentication) error {
	if a.authorizer == nil {
		return nil
	}
	if err := a.authorizer.Authorize(ctx, authentication); err != nil {
		return fmt.Errorf("%w: %v", ErrForbidden, err)
	}
	return nil
}

func (a *Auth) RequireAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authentication, err := a.Authenticate(r)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, "authentication_required", "Authentication required")
			return
		}
		if a.Authorize(r.Context(), authentication) != nil {
			WriteError(w, http.StatusForbidden, "access_forbidden", "Access forbidden")
			return
		}
		if authentication.Transport == TransportSession && isUnsafeMethod(r.Method) && !a.origins.sameOrigin(r) {
			WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithAuthentication(r.Context(), authentication)))
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
	response := SessionResponse{Status: SessionStatusSignedOut, Methods: a.methodInfos()}
	authentication, err := a.Authenticate(r)
	if err != nil {
		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			WriteError(w, http.StatusUnauthorized, "invalid_bearer_token", "Invalid bearer token")
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	access := AccessStatusGranted
	if a.Authorize(r.Context(), authentication) != nil {
		access = AccessStatusDenied
	}
	response.Status = SessionStatusAuthenticated
	response.Method = authentication.Method
	response.Access = access
	response.Identity = &authentication.Principal
	writeJSON(w, http.StatusOK, response)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if !a.origins.sameOrigin(r) {
		WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
		return
	}
	a.codec.clear(w)
	for _, method := range a.methods {
		if cleaner, ok := method.(CookieCleaner); ok {
			cleaner.ClearCookies(w)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.origins.sameOrigin(r) {
			WriteError(w, http.StatusForbidden, "invalid_origin", "Invalid request origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) methodInfos() []MethodInfo {
	infos := make([]MethodInfo, len(a.methods))
	for index, method := range a.methods {
		infos[index] = method.Info()
	}
	return infos
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
