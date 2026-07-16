package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/internal/model"
)

const maxCookieBytes = 3800

type Codec struct {
	keys       map[string]cipher.AEAD
	primaryID  string
	primary    cipher.AEAD
	random     io.Reader
	now        func() time.Time
	ttl        time.Duration
	cookieName string
	secure     bool
}
type payload struct {
	Version      int             `json:"v"`
	Method       string          `json:"m"`
	CredentialID string          `json:"c,omitempty"`
	Revision     string          `json:"r,omitempty"`
	IssuedAt     int64           `json:"iat"`
	ExpiresAt    int64           `json:"exp"`
	Principal    model.Principal `json:"p"`
}
type Envelope struct {
	Method  string
	Session model.Session
}

func New(config model.SessionConfig, secure bool, random io.Reader, now func() time.Time) (*Codec, error) {
	if config.TTL <= 0 || len(config.Keys) == 0 {
		return nil, fmt.Errorf("session TTL and keys are required")
	}
	if random == nil {
		random = rand.Reader
	}
	if now == nil {
		now = time.Now
	}
	codec := &Codec{keys: make(map[string]cipher.AEAD, len(config.Keys)), random: random, now: now, ttl: config.TTL, secure: secure}
	for index, key := range config.Keys {
		key.ID = strings.TrimSpace(key.ID)
		secret, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key.Secret))
		if err != nil || key.ID == "" || strings.Contains(key.ID, ".") || len(secret) != 32 {
			return nil, fmt.Errorf("invalid session key")
		}
		if _, exists := codec.keys[key.ID]; exists {
			return nil, fmt.Errorf("duplicate session key ID")
		}
		block, _ := aes.NewCipher(secret)
		aead, _ := cipher.NewGCM(block)
		codec.keys[key.ID] = aead
		if index == 0 {
			codec.primaryID, codec.primary = key.ID, aead
		}
	}
	codec.cookieName = strings.TrimSpace(config.CookieName)
	if codec.cookieName == "" {
		codec.cookieName = "authme"
		if secure {
			codec.cookieName = "__Host-authme"
		}
	}
	if strings.ContainsAny(codec.cookieName, "\x00\r\n\t ;,") {
		return nil, fmt.Errorf("invalid session cookie name")
	}
	return codec, nil
}
func (c *Codec) Issue(w http.ResponseWriter, method string, value model.Session) error {
	now := c.now()
	if value.IssuedAt.IsZero() {
		value.IssuedAt = now
	}
	maxExpiry := value.IssuedAt.Add(c.ttl)
	if value.ExpiresAt.IsZero() || value.ExpiresAt.After(maxExpiry) {
		value.ExpiresAt = maxExpiry
	}
	if method == "" || value.Principal.Subject == "" || !value.ExpiresAt.After(now) {
		return fmt.Errorf("invalid session")
	}
	raw, err := json.Marshal(payload{Version: 1, Method: method, CredentialID: value.CredentialID, Revision: value.Revision, IssuedAt: value.IssuedAt.Unix(), ExpiresAt: value.ExpiresAt.Unix(), Principal: value.Principal})
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	nonce := make([]byte, c.primary.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return fmt.Errorf("generate session nonce: %w", err)
	}
	sealed := c.primary.Seal(nil, nonce, raw, []byte(c.primaryID))
	encoded := c.primaryID + "." + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...))
	if len(encoded) > maxCookieBytes {
		return fmt.Errorf("session cookie too large")
	}
	http.SetCookie(w, &http.Cookie{Name: c.cookieName, Value: encoded, Path: "/", MaxAge: int(value.ExpiresAt.Sub(now).Seconds()), HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
	return nil
}
func (c *Codec) Read(r *http.Request) (Envelope, error) {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil || len(cookie.Value) > maxCookieBytes {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	keyID, encoded, found := strings.Cut(cookie.Value, ".")
	aead, exists := c.keys[keyID]
	if !found || !exists {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) <= aead.NonceSize() {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	raw, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(keyID))
	if err != nil {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	var value payload
	if err := json.Unmarshal(raw, &value); err != nil || value.Version != 1 || value.Method == "" || value.Principal.Subject == "" {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	issued, expires, now := time.Unix(value.IssuedAt, 0), time.Unix(value.ExpiresAt, 0), c.now()
	if issued.After(now) || !expires.After(now) || expires.After(issued.Add(c.ttl)) {
		return Envelope{}, fmt.Errorf("invalid session")
	}
	return Envelope{Method: value.Method, Session: model.Session{CredentialID: value.CredentialID, Revision: value.Revision, IssuedAt: issued, ExpiresAt: expires, Principal: value.Principal}}, nil
}
func (c *Codec) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: c.cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
}
