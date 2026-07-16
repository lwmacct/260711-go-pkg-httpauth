package statictoken

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxTokenBytes        = 4 << 10
	maxCredentialIDBytes = 56
)

var ErrInvalidConfig = errors.New("invalid static token config")

// Credential describes one configured access token identity.
type Credential struct {
	ID    string `json:"id" desc:"Credential ID"`
	Name  string `json:"name" desc:"Display name"`
	Token string `json:"token" desc:"Opaque access token"`
}

// Config contains file- and CLI-friendly static token settings. Runtime
// authentication uses a private map built by New.
type Config struct {
	Enabled     bool         `json:"enabled" desc:"Whether to enable static token authentication"`
	ID          string       `json:"id" desc:"Authentication method ID"`
	Label       string       `json:"label" desc:"Authentication method display label"`
	Credentials []Credential `json:"credentials" desc:"Static access token credentials"`
}

func DefaultConfig() Config { return Config{ID: "token", Label: "Access token"} }

func (c Config) Normalize() (Config, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Label = strings.TrimSpace(c.Label)
	if c.Credentials != nil {
		c.Credentials = append([]Credential(nil), c.Credentials...)
	}
	if c.ID == "" {
		c.ID = "token"
	}
	if c.Label == "" {
		c.Label = "Access token"
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

type validatedCredential struct {
	id     string
	name   string
	digest [sha256.Size]byte
}

func (c Config) Validate() error {
	if c.ID == "" || c.Label == "" || strings.ContainsAny(c.ID, "/?#") {
		return fmt.Errorf("%w: method identity", ErrInvalidConfig)
	}
	if _, err := c.validate(); err != nil {
		return err
	}
	return nil
}

func (c Config) validate() (map[string]validatedCredential, error) {
	if len(c.Credentials) == 0 {
		return nil, fmt.Errorf("%w: credentials are required", ErrInvalidConfig)
	}
	validated := make(map[string]validatedCredential, len(c.Credentials))
	seenDigests := make(map[[sha256.Size]byte]struct{}, len(c.Credentials))
	for _, credential := range c.Credentials {
		if !validCredentialID(credential.ID) || credential.Name == "" || credential.Name != strings.TrimSpace(credential.Name) || !validToken(credential.Token) {
			return nil, fmt.Errorf("%w: credential %q", ErrInvalidConfig, credential.ID)
		}
		if _, exists := validated[credential.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate credential %q", ErrInvalidConfig, credential.ID)
		}
		digest := sha256.Sum256([]byte(credential.Token))
		if _, exists := seenDigests[digest]; exists {
			return nil, fmt.Errorf("%w: duplicate credential token", ErrInvalidConfig)
		}
		seenDigests[digest] = struct{}{}
		validated[credential.ID] = validatedCredential{id: credential.ID, name: credential.Name, digest: digest}
	}
	return validated, nil
}

func validCredentialID(id string) bool {
	return validIdentifier(id, maxCredentialIDBytes)
}

func validIdentifier(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	if !isLowerAlphaNumeric(value[0]) || !isLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := range len(value) {
		char := value[index]
		if !isLowerAlphaNumeric(char) && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func isLowerAlphaNumeric(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
}
