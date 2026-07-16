package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var ErrInvalidConfig = errors.New("invalid OIDC config")

// Config describes the provider-facing part of an OIDC client.
type Config struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client-id"`
	ClientSecret string   `json:"client-secret"`
	Scopes       []string `json:"scopes"`
}

func DefaultConfig() Config { return Config{Scopes: []string{"openid", "profile"}} }

func (c Config) Normalize() (Config, error) {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	c.Scopes = append([]string(nil), c.Scopes...)
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile"}
	} else {
		seen := make(map[string]struct{}, len(c.Scopes))
		result := make([]string, 0, len(c.Scopes)+1)
		for _, scope := range c.Scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				return Config{}, fmt.Errorf("%w: empty scope", ErrInvalidConfig)
			}
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			result = append(result, scope)
		}
		c.Scopes = result
		if _, ok := seen["openid"]; !ok {
			c.Scopes = append([]string{"openid"}, c.Scopes...)
		}
	}
	if c.Issuer == "" || c.ClientID == "" {
		return Config{}, fmt.Errorf("%w: issuer and client ID are required", ErrInvalidConfig)
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.Opaque != "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return Config{}, fmt.Errorf("%w: issuer must be an HTTPS origin", ErrInvalidConfig)
	}
	return c, nil
}

func (c Config) Validate() error { _, err := c.Normalize(); return err }
