package oidc

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrInvalidFlow = errors.New("invalid or expired OIDC flow")

type LoginFlow struct {
	State       string
	Nonce       string
	Verifier    string
	ExternalURL string
	ReturnTo    string
	ExpiresAt   time.Time
}

type FlowStore interface {
	Create(context.Context, LoginFlow) error
	Consume(context.Context, string) (LoginFlow, error)
}

type MemoryFlowStore struct {
	mu    sync.Mutex
	flows map[string]LoginFlow
	now   func() time.Time
}

func NewMemoryFlowStore() *MemoryFlowStore {
	return &MemoryFlowStore{flows: make(map[string]LoginFlow), now: time.Now}
}

func (s *MemoryFlowStore) Create(_ context.Context, flow LoginFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flow.State == "" || !flow.ExpiresAt.After(s.now()) {
		return ErrInvalidFlow
	}
	s.flows[flow.State] = flow
	return nil
}

func (s *MemoryFlowStore) Consume(_ context.Context, state string) (LoginFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, exists := s.flows[state]
	delete(s.flows, state)
	if !exists || !flow.ExpiresAt.After(s.now()) {
		return LoginFlow{}, ErrInvalidFlow
	}
	return flow, nil
}
