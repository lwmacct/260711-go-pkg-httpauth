package dexgithub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
)

func TestEnabledIsApplicationSwitch(t *testing.T) {
	config := DefaultConfig()
	if config.Enabled {
		t.Fatal("Dex GitHub auth is enabled by default")
	}
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &config); err != nil {
		t.Fatal(err)
	}
	if !config.Enabled {
		t.Fatal("Dex GitHub enabled flag was not decoded")
	}
}

func TestMapClaimsAndUsernameAuthorizer(t *testing.T) {
	principal, err := mapClaims(json.RawMessage(`{
		"sub":"dex-subject","preferred_username":"LwMacct","name":"User",
		"federated_claims":{"connector_id":"github","user_id":"42"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Provider != "github" || principal.ProviderUserID != "42" || principal.AvatarURL != "https://avatars.githubusercontent.com/u/42?v=4" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
	authorizer, err := NewUsernameAuthorizer([]string{"lwmacct"})
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(context.Background(), authme.Authentication{Principal: principal}); err != nil {
		t.Fatalf("allowed principal was rejected: %v", err)
	}
	principal.Username = "visitor"
	if err := authorizer.Authorize(context.Background(), authme.Authentication{Principal: principal}); !errors.Is(err, authme.ErrForbidden) {
		t.Fatalf("unexpected denied error: %v", err)
	}
}

func TestMapClaimsRejectsNonGitHubIdentity(t *testing.T) {
	_, err := mapClaims(json.RawMessage(`{
		"sub":"subject","preferred_username":"user",
		"federated_claims":{"connector_id":"ldap","user_id":"42"}
	}`))
	if err == nil {
		t.Fatal("non-GitHub identity was accepted")
	}
}
