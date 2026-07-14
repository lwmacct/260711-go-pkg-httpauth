package httpauth

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
)

const maxSessionCookieBytes = 3800

type SessionKey struct {
	ID     string `json:"id" desc:"Session key ID"`
	Secret string `json:"secret" desc:"Base64url-encoded 32-byte AES key"`
}

type SessionConfig struct {
	Keys       []SessionKey  `json:"keys"        desc:"Session encryption key ring; first key writes, all keys read"`
	TTL        time.Duration `json:"ttl"         desc:"Maximum browser session lifetime"`
	CookieName string        `json:"cookie-name" desc:"Optional browser session cookie name"`
}

type sessionCodec struct {
	keys       map[string]cipher.AEAD
	primaryID  string
	primary    cipher.AEAD
	random     io.Reader
	now        func() time.Time
	ttl        time.Duration
	cookieName string
	secure     bool
}

type sessionPayload struct {
	Version      int       `json:"v"`
	Method       string    `json:"m"`
	CredentialID string    `json:"c,omitempty"`
	Revision     string    `json:"r,omitempty"`
	IssuedAt     int64     `json:"iat"`
	ExpiresAt    int64     `json:"exp"`
	Principal    Principal `json:"p"`
}

func newSessionCodec(config SessionConfig, secure bool, random io.Reader, now func() time.Time) (*sessionCodec, error) {
	if config.TTL <= 0 || len(config.Keys) == 0 {
		return nil, fmt.Errorf("%w: session TTL and keys are required", ErrInvalidConfig)
	}
	if random == nil {
		random = rand.Reader
	}
	if now == nil {
		now = time.Now
	}
	codec := &sessionCodec{keys: make(map[string]cipher.AEAD, len(config.Keys)), random: random, now: now, ttl: config.TTL, secure: secure}
	for index, key := range config.Keys {
		key.ID = strings.TrimSpace(key.ID)
		secret, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key.Secret))
		if err != nil || key.ID == "" || strings.Contains(key.ID, ".") || len(secret) != 32 {
			return nil, fmt.Errorf("%w: session key", ErrInvalidConfig)
		}
		if _, exists := codec.keys[key.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate session key ID", ErrInvalidConfig)
		}
		block, _ := aes.NewCipher(secret)
		aead, _ := cipher.NewGCM(block)
		codec.keys[key.ID] = aead
		if index == 0 {
			codec.primaryID = key.ID
			codec.primary = aead
		}
	}
	codec.cookieName = strings.TrimSpace(config.CookieName)
	if codec.cookieName == "" {
		codec.cookieName = "httpauth"
		if secure {
			codec.cookieName = "__Host-httpauth"
		}
	}
	if strings.ContainsAny(codec.cookieName, "\x00\r\n\t ;,") {
		return nil, fmt.Errorf("%w: session cookie name", ErrInvalidConfig)
	}
	return codec, nil
}

func (c *sessionCodec) issue(w http.ResponseWriter, session Session) error {
	now := c.now()
	if session.IssuedAt.IsZero() {
		session.IssuedAt = now
	}
	maximumExpiry := session.IssuedAt.Add(c.ttl)
	if session.ExpiresAt.IsZero() || session.ExpiresAt.After(maximumExpiry) {
		session.ExpiresAt = maximumExpiry
	}
	if session.Method == "" || session.Principal.Subject == "" || !session.ExpiresAt.After(now) {
		return ErrInvalidSession
	}
	payload, err := json.Marshal(sessionPayload{Version: 1, Method: session.Method, CredentialID: session.CredentialID, Revision: session.Revision, IssuedAt: session.IssuedAt.Unix(), ExpiresAt: session.ExpiresAt.Unix(), Principal: session.Principal})
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	nonce := make([]byte, c.primary.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return fmt.Errorf("generate session nonce: %w", err)
	}
	ciphertext := c.primary.Seal(nil, nonce, payload, []byte(c.primaryID))
	value := c.primaryID + "." + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
	if len(value) > maxSessionCookieBytes {
		return fmt.Errorf("%w: session cookie too large", ErrInvalidSession)
	}
	maxAge := int(session.ExpiresAt.Sub(now).Seconds())
	http.SetCookie(w, &http.Cookie{Name: c.cookieName, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
	return nil
}

func (c *sessionCodec) read(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil || len(cookie.Value) > maxSessionCookieBytes {
		return Session{}, ErrInvalidSession
	}
	keyID, encoded, found := strings.Cut(cookie.Value, ".")
	aead, exists := c.keys[keyID]
	if !found || !exists {
		return Session{}, ErrInvalidSession
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) <= aead.NonceSize() {
		return Session{}, ErrInvalidSession
	}
	payload, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(keyID))
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	var value sessionPayload
	if err := json.Unmarshal(payload, &value); err != nil || value.Version != 1 || value.Method == "" || value.Principal.Subject == "" {
		return Session{}, ErrInvalidSession
	}
	issuedAt := time.Unix(value.IssuedAt, 0)
	expiresAt := time.Unix(value.ExpiresAt, 0)
	now := c.now()
	if issuedAt.After(now) || !expiresAt.After(now) || expiresAt.After(issuedAt.Add(c.ttl)) {
		return Session{}, ErrInvalidSession
	}
	return Session{Method: value.Method, CredentialID: value.CredentialID, Revision: value.Revision, IssuedAt: issuedAt, ExpiresAt: expiresAt, Principal: value.Principal}, nil
}

func (c *sessionCodec) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: c.cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
}
