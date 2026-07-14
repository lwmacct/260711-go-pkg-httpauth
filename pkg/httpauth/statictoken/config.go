package statictoken

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	SecretBytes          = 24
	MaxTokenBytes        = 128
	tokenVersion         = "10"
	maxNamespaceBytes    = 32
	maxCredentialIDBytes = 56
)

var ErrInvalidConfig = errors.New("invalid static token config")

type Credential struct {
	Name         string `json:"name"          desc:"Display name"`
	SecretSHA256 string `json:"secret-sha256" desc:"Lowercase hexadecimal SHA-256 digest of the decoded token secret"`
}

type Config struct {
	Credentials map[string]Credential `json:"credentials" desc:"Static access tokens keyed by credential ID"`
}

type validatedCredential struct {
	id     string
	name   string
	digest [sha256.Size]byte
}

func (c Config) Validate() (Config, error) {
	if _, err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) validate() (map[string]validatedCredential, error) {
	if len(c.Credentials) == 0 {
		return nil, fmt.Errorf("%w: credentials are required", ErrInvalidConfig)
	}
	validated := make(map[string]validatedCredential, len(c.Credentials))
	seenDigests := make([][sha256.Size]byte, 0, len(c.Credentials))
	for id, credential := range c.Credentials {
		if !validCredentialID(id) || credential.Name == "" || credential.Name != strings.TrimSpace(credential.Name) {
			return nil, fmt.Errorf("%w: credential %q", ErrInvalidConfig, id)
		}
		rawDigest, err := hex.DecodeString(credential.SecretSHA256)
		if err != nil || len(rawDigest) != sha256.Size || hex.EncodeToString(rawDigest) != credential.SecretSHA256 {
			return nil, fmt.Errorf("%w: credential %q digest", ErrInvalidConfig, id)
		}
		var digest [sha256.Size]byte
		copy(digest[:], rawDigest)
		for _, seen := range seenDigests {
			if subtle.ConstantTimeCompare(digest[:], seen[:]) == 1 {
				return nil, fmt.Errorf("%w: duplicate credential digest", ErrInvalidConfig)
			}
		}
		seenDigests = append(seenDigests, digest)
		validated[id] = validatedCredential{id: id, name: credential.Name, digest: digest}
	}
	return validated, nil
}

func validCredentialID(id string) bool {
	return validIdentifier(id, maxCredentialIDBytes)
}

func validNamespace(namespace string) bool {
	return validIdentifier(namespace, maxNamespaceBytes)
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
