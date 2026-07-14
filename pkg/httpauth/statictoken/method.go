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

	"github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth"
)

type Method struct {
	namespace   string
	credentials map[string]storedCredential
}

type storedCredential struct {
	id       string
	name     string
	digest   [sha256.Size]byte
	revision string
}

type Generated struct {
	Token        string
	SecretSHA256 string
}

func New(namespace string, config Config) (*Method, error) {
	if !validNamespace(namespace) {
		return nil, fmt.Errorf("%w: namespace", ErrInvalidConfig)
	}
	validated, err := config.validate()
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
	return &Method{namespace: namespace, credentials: credentials}, nil
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
	return Generated{Token: token, SecretSHA256: digestSecret(secret)}, nil
}

func Digest(namespace, token string) (string, error) {
	_, secret, ok := parse(namespace, token)
	if !ok {
		return "", fmt.Errorf("%w: token", ErrInvalidConfig)
	}
	return digestSecret(secret), nil
}

func (m *Method) Info() httpauth.MethodInfo {
	return httpauth.MethodInfo{ID: "token", Flow: httpauth.LoginFlowSecret, Label: "Access token"}
}

func (m *Method) LoginHandler(issuer httpauth.SessionIssuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxTokenBytes+256)
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
		credential, ok := m.authenticate(request.Token)
		if !ok {
			httpauth.WriteError(w, http.StatusUnauthorized, "invalid_access_token", "Invalid access token")
			return
		}
		if err := issuer.IssueSession(w, m.session(credential)); err != nil {
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
	credential, exists := m.credentials[session.CredentialID]
	if !exists || subtle.ConstantTimeCompare([]byte(credential.revision), []byte(session.Revision)) != 1 {
		return httpauth.Principal{}, httpauth.ErrUnauthenticated
	}
	return principal(credential), nil
}

func (m *Method) authenticate(token string) (storedCredential, bool) {
	id, secret, ok := parse(m.namespace, token)
	if !ok {
		return storedCredential{}, false
	}
	credential, exists := m.credentials[id]
	if !exists {
		return storedCredential{}, false
	}
	digest := sha256.Sum256(secret)
	return credential, subtle.ConstantTimeCompare(digest[:], credential.digest[:]) == 1
}

func parse(namespace, token string) (string, []byte, bool) {
	if len(token) > MaxTokenBytes || token != strings.TrimSpace(token) {
		return "", nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != namespace || parts[1] != tokenVersion || !validCredentialID(parts[2]) {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(secret) != SecretBytes || base64.RawURLEncoding.EncodeToString(secret) != parts[3] {
		return "", nil, false
	}
	return parts[2], secret, true
}

func digestSecret(secret []byte) string {
	digest := sha256.Sum256(secret)
	return hex.EncodeToString(digest[:])
}

func (m *Method) session(credential storedCredential) httpauth.Session {
	return httpauth.Session{Method: "token", CredentialID: credential.id, Revision: credential.revision, Principal: principal(credential)}
}

func principal(credential storedCredential) httpauth.Principal {
	return httpauth.Principal{Subject: credential.id, Username: credential.id, Name: credential.name, Provider: "token"}
}
