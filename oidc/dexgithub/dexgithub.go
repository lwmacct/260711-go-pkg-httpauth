package dexgithub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lwmacct/260711-go-pkg-httpauth"
	"github.com/lwmacct/260711-go-pkg-httpauth/oidc"
)

func New(ctx context.Context, config oidc.Config, options oidc.Options) (*oidc.Method, error) {
	options.IdentityMapper = Mapper{}
	options.ExtraScopes = append(options.ExtraScopes, "federated:id")
	return oidc.New(ctx, config, options)
}

type Mapper struct{}

type claims struct {
	Subject           string `json:"sub"`
	Username          string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	FederatedIdentity struct {
		ConnectorID string `json:"connector_id"`
		UserID      string `json:"user_id"`
	} `json:"federated_claims"`
}

func (Mapper) MapIdentity(_ context.Context, raw json.RawMessage) (httpauth.Principal, error) {
	var value claims
	if err := json.Unmarshal(raw, &value); err != nil {
		return httpauth.Principal{}, err
	}
	value.Username = strings.TrimSpace(value.Username)
	value.FederatedIdentity.UserID = strings.TrimSpace(value.FederatedIdentity.UserID)
	if value.Subject == "" || value.Username == "" || value.FederatedIdentity.ConnectorID != "github" || value.FederatedIdentity.UserID == "" {
		return httpauth.Principal{}, errors.New("required Dex GitHub identity claims missing")
	}
	return httpauth.Principal{
		Subject:        value.Subject,
		Username:       value.Username,
		Name:           value.Name,
		Email:          value.Email,
		AvatarURL:      "https://avatars.githubusercontent.com/u/" + url.PathEscape(value.FederatedIdentity.UserID) + "?v=4",
		Provider:       "github",
		ProviderUserID: value.FederatedIdentity.UserID,
	}, nil
}

type UsernameAuthorizer struct {
	allowed map[string]struct{}
}

func NewUsernameAuthorizer(values []string) (UsernameAuthorizer, error) {
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		username := strings.ToLower(strings.TrimSpace(value))
		if username == "" {
			return UsernameAuthorizer{}, errors.New("allowed GitHub username is empty")
		}
		if _, exists := allowed[username]; exists {
			return UsernameAuthorizer{}, fmt.Errorf("duplicate allowed GitHub username %q", username)
		}
		allowed[username] = struct{}{}
	}
	if len(allowed) == 0 {
		return UsernameAuthorizer{}, errors.New("allowed GitHub users are required")
	}
	return UsernameAuthorizer{allowed: allowed}, nil
}

func (a UsernameAuthorizer) Authorize(_ context.Context, authentication httpauth.Authentication) error {
	if authentication.Principal.Provider != "github" {
		return nil
	}
	if _, ok := a.allowed[strings.ToLower(strings.TrimSpace(authentication.Principal.Username))]; !ok {
		return httpauth.ErrForbidden
	}
	return nil
}
