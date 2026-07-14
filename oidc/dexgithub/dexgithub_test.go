package dexgithub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lwmacct/260711-go-pkg-httpauth"
)

func TestMapperAndUsernameAuthorizer(t *testing.T) {
	principal, err := (Mapper{}).MapIdentity(t.Context(), json.RawMessage(`{
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
	if err := authorizer.Authorize(context.Background(), httpauth.Authentication{Principal: principal}); err != nil {
		t.Fatalf("allowed principal was rejected: %v", err)
	}
	principal.Username = "visitor"
	if err := authorizer.Authorize(context.Background(), httpauth.Authentication{Principal: principal}); !errors.Is(err, httpauth.ErrForbidden) {
		t.Fatalf("unexpected denied error: %v", err)
	}
}

func TestMapperRejectsNonGitHubIdentity(t *testing.T) {
	_, err := (Mapper{}).MapIdentity(t.Context(), json.RawMessage(`{
		"sub":"subject","preferred_username":"user",
		"federated_claims":{"connector_id":"ldap","user_id":"42"}
	}`))
	if err == nil {
		t.Fatal("non-GitHub identity was accepted")
	}
}
