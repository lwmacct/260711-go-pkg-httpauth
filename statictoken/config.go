package statictoken

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidConfig = errors.New("invalid static token config")

type Credential struct {
	ID     string `json:"id"     desc:"Stable credential ID"`
	Name   string `json:"name"   desc:"Display name"`
	Secret string `json:"secret" desc:"Access token secret"`
}

type Config struct {
	Credentials []Credential `json:"credentials" desc:"Named static access tokens"`
}

func (c Config) Validate() (Config, error) {
	if len(c.Credentials) == 0 {
		return c, fmt.Errorf("%w: credentials are required", ErrInvalidConfig)
	}
	seen := make(map[string]struct{}, len(c.Credentials))
	for index := range c.Credentials {
		credential := &c.Credentials[index]
		credential.ID = strings.TrimSpace(credential.ID)
		credential.Name = strings.TrimSpace(credential.Name)
		credential.Secret = strings.TrimSpace(credential.Secret)
		if credential.ID == "" || credential.Name == "" || len(credential.Secret) < 16 || strings.ContainsAny(credential.ID, "/?#") {
			return c, fmt.Errorf("%w: credential", ErrInvalidConfig)
		}
		if _, exists := seen[credential.ID]; exists {
			return c, fmt.Errorf("%w: duplicate credential ID", ErrInvalidConfig)
		}
		seen[credential.ID] = struct{}{}
	}
	return c, nil
}
