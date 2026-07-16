package statictoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
)

type Method struct {
	namespace   string
	credentials map[string]storedCredential
	id          string
	label       string
}

type storedCredential struct {
	id       string
	name     string
	digest   [sha256.Size]byte
	revision string
}

type Generated struct {
	Token       string
	TokenSHA256 string
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
	credentials := make(map[string]storedCredential, len(validated))
	for id, credential := range validated {
		credentials[id] = storedCredential{
			id: id, name: credential.name, digest: credential.digest,
			revision: hex.EncodeToString(credential.digest[:]),
		}
	}
	return &Method{namespace: normalized.Namespace, credentials: credentials, id: normalized.ID, label: normalized.Label}, nil
}

func Generate(namespace, id string) (Generated, error) {
	if !validNamespace(namespace) || !validCredentialID(id) {
		return Generated{}, fmt.Errorf("%w: token identity", ErrInvalidConfig)
	}
	secret := make([]byte, SecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return Generated{}, fmt.Errorf("generate access token: %w", err)
	}
	token := strings.Join([]string{namespace, tokenVersion, id, base64.RawURLEncoding.EncodeToString(secret)}, ".")
	if len(token) > MaxTokenBytes {
		return Generated{}, fmt.Errorf("%w: token is too long", ErrInvalidConfig)
	}
	return Generated{Token: token, TokenSHA256: digestToken(token)}, nil
}

func Digest(namespace, token string) (string, error) {
	_, ok := parse(namespace, token)
	if !ok {
		return "", fmt.Errorf("%w: token", ErrInvalidConfig)
	}
	return digestToken(token), nil
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
	credential, exists := m.credentials[session.CredentialID]
	if !exists || subtle.ConstantTimeCompare([]byte(credential.revision), []byte(session.Revision)) != 1 {
		return authme.Principal{}, authme.ErrUnauthenticated
	}
	return principal(credential), nil
}

func (m *Method) authenticate(token string) (storedCredential, bool) {
	id, ok := parse(m.namespace, token)
	if !ok {
		return storedCredential{}, false
	}
	credential, exists := m.credentials[id]
	if !exists {
		return storedCredential{}, false
	}
	digest := sha256.Sum256([]byte(token))
	return credential, subtle.ConstantTimeCompare(digest[:], credential.digest[:]) == 1
}

func parse(namespace, token string) (string, bool) {
	if len(token) > MaxTokenBytes || token != strings.TrimSpace(token) {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != namespace || parts[1] != tokenVersion || !validCredentialID(parts[2]) {
		return "", false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(secret) != SecretBytes || base64.RawURLEncoding.EncodeToString(secret) != parts[3] {
		return "", false
	}
	return parts[2], true
}

func digestToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (m *Method) session(credential storedCredential) authme.Session {
	return authme.Session{CredentialID: credential.id, Revision: credential.revision, Principal: principal(credential)}
}

func principal(credential storedCredential) authme.Principal {
	return authme.Principal{Subject: credential.id, Username: credential.id, Name: credential.name, Provider: "token"}
}
