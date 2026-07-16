package statictoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
)

type Method struct {
	byDigest map[[sha256.Size]byte]storedCredential
	byID     map[string]storedCredential
	id       string
	label    string
}

type storedCredential struct {
	id       string
	name     string
	revision string
}

func New(config Config) (*Method, error) {
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	validated, err := normalized.validate()
	if err != nil {
		return nil, err
	}
	byDigest := make(map[[sha256.Size]byte]storedCredential, len(validated))
	byID := make(map[string]storedCredential, len(validated))
	for _, credential := range validated {
		stored := storedCredential{
			id: credential.id, name: credential.name,
			revision: hex.EncodeToString(credential.digest[:]),
		}
		byDigest[credential.digest] = stored
		byID[credential.id] = stored
	}
	return &Method{byDigest: byDigest, byID: byID, id: normalized.ID, label: normalized.Label}, nil
}

func (m *Method) Info() authme.MethodInfo {
	return authme.MethodInfo{ID: m.id, Flow: authme.LoginFlowSecret, Label: m.label}
}

func (m *Method) LoginHandler(issuer authme.SessionIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxTokenBytes+256)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request struct {
			Token string `json:"token"`
		}
		if err := decoder.Decode(&request); err != nil {
			authme.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			authme.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
			return
		}
		credential, ok := m.authenticate(request.Token)
		if !ok {
			authme.WriteError(w, http.StatusUnauthorized, "invalid_access_token", "Invalid access token")
			return
		}
		if err := issuer.IssueSession(w, m.session(credential)); err != nil {
			authme.WriteError(w, http.StatusInternalServerError, "login_unavailable", "Login unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (m *Method) AuthenticateBearer(_ context.Context, token string) (authme.Session, error) {
	credential, ok := m.authenticate(token)
	if !ok {
		return authme.Session{}, authme.ErrUnauthenticated
	}
	return m.session(credential), nil
}

func (m *Method) ValidateSession(_ context.Context, session authme.Session) (authme.Principal, error) {
	credential, exists := m.byID[session.CredentialID]
	if !exists || credential.revision != session.Revision {
		return authme.Principal{}, authme.ErrUnauthenticated
	}
	return principal(credential), nil
}

func (m *Method) authenticate(token string) (storedCredential, bool) {
	if !validToken(token) {
		return storedCredential{}, false
	}
	digest := sha256.Sum256([]byte(token))
	credential, exists := m.byDigest[digest]
	if !exists {
		return storedCredential{}, false
	}
	return credential, true
}

func validToken(token string) bool {
	if token == "" || len(token) > MaxTokenBytes {
		return false
	}
	for _, char := range token {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func (m *Method) session(credential storedCredential) authme.Session {
	return authme.Session{CredentialID: credential.id, Revision: credential.revision, Principal: principal(credential)}
}

func principal(credential storedCredential) authme.Principal {
	return authme.Principal{Subject: credential.id, Username: credential.id, Name: credential.name, Provider: "token"}
}
