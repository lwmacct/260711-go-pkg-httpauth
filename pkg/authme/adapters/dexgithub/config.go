package dexgithub

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidConfig = errors.New("invalid Dex GitHub config")

type Config struct {
	ID           string        `json:"id" desc:"Authentication method ID"`
	Label        string        `json:"label" desc:"Authentication method display label"`
	Issuer       string        `json:"issuer" desc:"Dex OIDC issuer URL"`
	ClientID     string        `json:"client-id" desc:"OIDC client ID"`
	ClientSecret string        `json:"client-secret" desc:"OIDC client secret"`
	SessionTTL   time.Duration `json:"session-ttl" desc:"Maximum browser session lifetime"`
	FlowTTL      time.Duration `json:"flow-ttl" desc:"Login flow lifetime"`
}

func DefaultConfig() Config {
	return Config{ID: "github", Label: "GitHub", SessionTTL: 24 * time.Hour, FlowTTL: 5 * time.Minute}
}

func (c Config) Normalize() (Config, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Label = strings.TrimSpace(c.Label)
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	if c.ID == "" {
		c.ID = "github"
	}
	if c.Label == "" {
		c.Label = "GitHub"
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 24 * time.Hour
	}
	if c.FlowTTL == 0 {
		c.FlowTTL = 5 * time.Minute
	}
	if c.ID == "" || c.Label == "" || c.ClientID == "" || c.SessionTTL <= 0 || c.FlowTTL <= 0 || strings.ContainsAny(c.ID, "/?#") {
		return Config{}, fmt.Errorf("%w: method identity and TTL are required", ErrInvalidConfig)
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return Config{}, fmt.Errorf("%w: issuer", ErrInvalidConfig)
	}
	return c, nil
}

func (c Config) Validate() error { _, err := c.Normalize(); return err }
