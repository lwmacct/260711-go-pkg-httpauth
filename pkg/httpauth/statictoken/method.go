package statictoken

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth"
)

const maxTokenBytes = 64 << 10

type Method struct {
	credentials []storedCredential
	byID        map[string]storedCredential
}

type storedCredential struct {
	id       string
	name     string
	digest   [sha256.Size]byte
	revision string
}

func New(config Config) (*Method, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	method := &Method{credentials: make([]storedCredential, len(config.Credentials)), byID: make(map[string]storedCredential, len(config.Credentials))}
	for index, credential := range config.Credentials {
		digest := sha256.Sum256([]byte(credential.Secret))
		stored := storedCredential{id: credential.ID, name: credential.Name, digest: digest, revision: base64.RawURLEncoding.EncodeToString(digest[:12])}
		method.credentials[index] = stored
		method.byID[stored.id] = stored
	}
	return method, nil
}

func (m *Method) Info() httpauth.MethodInfo {
	return httpauth.MethodInfo{ID: "token", Flow: httpauth.LoginFlowSecret, Label: "Access token"}
}

func (m *Method) LoginHandler(issuer httpauth.SessionIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxTokenBytes+256)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request struct {
			Token string `json:"token"`
		}
		if err := decoder.Decode(&request); err != nil {
			httpauth.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			httpauth.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
			return
		}
		credential, ok := m.authenticate(strings.TrimSpace(request.Token))
		if !ok {
			httpauth.WriteError(w, http.StatusUnauthorized, "invalid_access_token", "Invalid access token")
			return
		}
		session := m.session(credential)
		if err := issuer.IssueSession(w, session); err != nil {
			httpauth.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (m *Method) AuthenticateBearer(_ context.Context, token string) (httpauth.Session, error) {
	credential, ok := m.authenticate(token)
	if !ok {
		return httpauth.Session{}, httpauth.ErrUnauthenticated
	}
	return m.session(credential), nil
}

func (m *Method) ValidateSession(_ context.Context, session httpauth.Session) (httpauth.Principal, error) {
	credential, exists := m.byID[session.CredentialID]
	if !exists || subtle.ConstantTimeCompare([]byte(credential.revision), []byte(session.Revision)) != 1 {
		return httpauth.Principal{}, httpauth.ErrUnauthenticated
	}
	return principal(credential), nil
}

func (m *Method) authenticate(token string) (storedCredential, bool) {
	if len(token) < 16 || len(token) > maxTokenBytes {
		return storedCredential{}, false
	}
	digest := sha256.Sum256([]byte(token))
	matched := 0
	matchIndex := 0
	for index, credential := range m.credentials {
		equal := subtle.ConstantTimeCompare(digest[:], credential.digest[:])
		matched |= equal
		matchIndex = subtle.ConstantTimeSelect(equal, index, matchIndex)
	}
	return m.credentials[matchIndex], matched == 1
}

func (m *Method) session(credential storedCredential) httpauth.Session {
	return httpauth.Session{Method: "token", CredentialID: credential.id, Revision: credential.revision, Principal: principal(credential)}
}

func principal(credential storedCredential) httpauth.Principal {
	return httpauth.Principal{Subject: credential.id, Username: credential.id, Name: credential.name, Provider: "token"}
}
