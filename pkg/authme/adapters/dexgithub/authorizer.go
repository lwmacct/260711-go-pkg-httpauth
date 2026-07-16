package dexgithub

import (
	"context"
	"fmt"
	"strings"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
)

type UsernameAuthorizer struct{ allowed map[string]struct{} }

func NewUsernameAuthorizer(values []string) (UsernameAuthorizer, error) {
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		username := strings.ToLower(strings.TrimSpace(value))
		if username == "" {
			return UsernameAuthorizer{}, fmt.Errorf("allowed GitHub username is empty")
		}
		if _, exists := allowed[username]; exists {
			return UsernameAuthorizer{}, fmt.Errorf("duplicate allowed GitHub username %q", username)
		}
		allowed[username] = struct{}{}
	}
	if len(allowed) == 0 {
		return UsernameAuthorizer{}, fmt.Errorf("allowed GitHub users are required")
	}
	return UsernameAuthorizer{allowed: allowed}, nil
}

func (a UsernameAuthorizer) Authorize(_ context.Context, authentication authme.Authentication) error {
	if authentication.Principal.Provider != "github" {
		return nil
	}
	if _, ok := a.allowed[strings.ToLower(strings.TrimSpace(authentication.Principal.Username))]; !ok {
		return authme.ErrForbidden
	}
	return nil
}
