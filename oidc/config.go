package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidConfig = errors.New("invalid OIDC config")

type Config struct {
	ID           string        `json:"id"            desc:"Authentication method ID"`
	Label        string        `json:"label"         desc:"Authentication method display label"`
	Issuer       string        `json:"issuer"        desc:"OIDC issuer URL"`
	ClientID     string        `json:"client-id"     desc:"OIDC client ID"`
	ClientSecret string        `json:"client-secret" desc:"OIDC confidential client secret; empty for public clients"`
	SessionTTL   time.Duration `json:"session-ttl"   desc:"Maximum OIDC browser session lifetime"`
}

func (c Config) Validate() (Config, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Label = strings.TrimSpace(c.Label)
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	if c.ID == "" || c.Label == "" || c.Issuer == "" || c.ClientID == "" || c.SessionTTL <= 0 || strings.ContainsAny(c.ID, "/?#") {
		return c, ErrInvalidConfig
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return c, fmt.Errorf("%w: issuer", ErrInvalidConfig)
	}
	return c, nil
}
