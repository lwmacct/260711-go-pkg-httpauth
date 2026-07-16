package browserflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrInvalidFlow = errors.New("invalid or expired browser flow")

type Flow struct {
	State       string
	Nonce       string
	Verifier    string
	RedirectURI string
	Origin      string
	ReturnTo    string
	ExpiresAt   time.Time
}

type Store interface {
	Create(context.Context, Flow) error
	Consume(context.Context, string) (Flow, error)
}

type MemoryStore struct {
	mu    sync.Mutex
	flows map[string]Flow
	now   func() time.Time
	max   int
}

type StoreOption func(*MemoryStore)

func WithMaxFlows(max int) StoreOption {
	return func(store *MemoryStore) {
		if max > 0 {
			store.max = max
		}
	}
}

func WithClock(now func() time.Time) StoreOption {
	return func(store *MemoryStore) {
		if now != nil {
			store.now = now
		}
	}
}

func NewMemoryStore(options ...StoreOption) *MemoryStore {
	store := &MemoryStore{flows: make(map[string]Flow), now: time.Now, max: 4096}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store
}

func (s *MemoryStore) Create(_ context.Context, flow Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flow.State == "" || !flow.ExpiresAt.After(s.now()) {
		return ErrInvalidFlow
	}
	s.purgeLocked()
	if _, exists := s.flows[flow.State]; exists {
		return ErrInvalidFlow
	}
	if len(s.flows) >= s.max {
		return ErrInvalidFlow
	}
	s.flows[flow.State] = flow
	return nil
}

func (s *MemoryStore) Consume(_ context.Context, state string) (Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.flows[state]
	delete(s.flows, state)
	if !ok || !flow.ExpiresAt.After(s.now()) {
		return Flow{}, ErrInvalidFlow
	}
	return flow, nil
}

func (s *MemoryStore) PurgeExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeLocked()
}

func (s *MemoryStore) purgeLocked() int {
	now := s.now()
	removed := 0
	for state, flow := range s.flows {
		if !flow.ExpiresAt.After(now) {
			delete(s.flows, state)
			removed++
		}
	}
	return removed
}

func NormalizeReturnTo(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(value, "\\") {
		return "", fmt.Errorf("return path must be same-origin")
	}
	return parsed.String(), nil
}

func Token(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func CookieName(id string, secure bool) string {
	digest := sha256.Sum256([]byte(id))
	name := "authme_flow_" + base64.RawURLEncoding.EncodeToString(digest[:6])
	if secure {
		return "__Host-" + name
	}
	return name
}

func SetCookie(w http.ResponseWriter, name, value string, maxAge int, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func ClearCookie(w http.ResponseWriter, name string, secure bool) { SetCookie(w, name, "", -1, secure) }
