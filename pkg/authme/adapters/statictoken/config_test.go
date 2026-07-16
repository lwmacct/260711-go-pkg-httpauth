package statictoken

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnabledIsApplicationSwitch(t *testing.T) {
	config := DefaultConfig()
	if config.Enabled {
		t.Fatal("static token auth is enabled by default")
	}
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &config); err != nil {
		t.Fatal(err)
	}
	if !config.Enabled {
		t.Fatal("static token enabled flag was not decoded")
	}
}

func TestOpaqueTokenAuth(t *testing.T) {
	token := "opaque-token/with.punctuation~1"
	method, err := New(Config{Credentials: []Credential{
		{ID: "admin", Name: "Administrator", Token: token},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if credential, ok := method.authenticate(token); !ok || credential.id != "admin" {
		t.Fatal("opaque token did not authenticate")
	}
}

func TestAcceptsOpaqueTokens(t *testing.T) {
	token := "legacy-style.token/with+symbols"
	method, err := New(Config{Credentials: []Credential{
		{ID: "admin", Name: "Administrator", Token: token},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"0123456789abcdef0123456789abcdef", "550e8400-e29b-41d4-a716-446655440000"} {
		candidateMethod, err := New(Config{Credentials: []Credential{{ID: "candidate", Name: "Candidate", Token: candidate}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := candidateMethod.authenticate(candidate); !ok {
			t.Fatalf("opaque token was rejected: %q", candidate)
		}
	}
	for _, candidate := range []string{"", " token", "token ", "token\n", strings.Repeat("x", MaxTokenBytes+1)} {
		if _, ok := method.authenticate(candidate); ok {
			t.Fatalf("invalid transport token was accepted: %q", candidate)
		}
	}
}

func TestValidateRejectsInvalidCredentials(t *testing.T) {
	for _, config := range []Config{
		{},
		{Credentials: []Credential{{ID: "Admin", Name: "Administrator", Token: "test-token"}}},
		{Credentials: []Credential{{ID: "-admin", Name: "Administrator", Token: "test-token"}}},
		{Credentials: []Credential{{ID: "admin", Name: " Administrator", Token: "test-token"}}},
		{Credentials: []Credential{{ID: "admin", Name: "Administrator", Token: ""}}},
		{Credentials: []Credential{{ID: "admin", Name: "Administrator", Token: "test-token\n"}}},
		{Credentials: []Credential{{ID: "admin", Name: "Administrator", Token: strings.Repeat("x", MaxTokenBytes+1)}}},
		{Credentials: []Credential{
			{ID: "admin", Name: "Administrator", Token: "test-token"},
			{ID: "admin", Name: "Automation", Token: strings.Repeat("b", 64)},
		}},
		{Credentials: []Credential{
			{ID: "admin", Name: "Administrator", Token: "test-token"},
			{ID: "automation", Name: "Automation", Token: "test-token"},
		}},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid config was accepted: %#v", config)
		}
	}
}
