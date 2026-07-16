package statictoken

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateAndValidate(t *testing.T) {
	generated, err := Generate("example", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Token) != len("example.10.admin.")+32 || !strings.HasPrefix(generated.Token, "example.10.admin.") || len(generated.TokenSHA256) != 64 {
		t.Fatalf("unexpected generated token: %#v", generated)
	}
	expectedDigest := sha256.Sum256([]byte(generated.Token))
	if generated.TokenSHA256 != hex.EncodeToString(expectedDigest[:]) {
		t.Fatalf("digest does not cover the complete token: %#v", generated)
	}
	method, err := New(Config{Namespace: "example", Credentials: []Credential{
		{ID: "admin", Name: "Administrator", TokenSHA256: generated.TokenSHA256},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if credential, ok := method.authenticate(generated.Token); !ok || credential.id != "admin" {
		t.Fatal("generated token did not authenticate")
	}
}

func TestRejectsLegacyAndMalformedTokens(t *testing.T) {
	token := testToken("example", "admin", "a")
	digest, err := Digest("example", token)
	if err != nil {
		t.Fatal(err)
	}
	method, err := New(Config{Namespace: "example", Credentials: []Credential{
		{ID: "admin", Name: "Administrator", TokenSHA256: digest},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"0123456789abcdef0123456789abcdef",
		"550e8400-e29b-41d4-a716-446655440000",
		" " + token,
		token + " ",
		"other.10.admin." + strings.Repeat("Y", 32),
		"example.1.admin." + strings.Repeat("Y", 32),
		"example.10.admin.short",
	} {
		if _, ok := method.authenticate(candidate); ok {
			t.Fatalf("malformed token was accepted: %q", candidate)
		}
	}
}

func TestValidateRejectsInvalidCredentials(t *testing.T) {
	validDigest, err := Digest("example", testToken("example", "admin", "a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []Config{
		{},
		{Credentials: []Credential{{ID: "Admin", Name: "Administrator", TokenSHA256: validDigest}}},
		{Credentials: []Credential{{ID: "-admin", Name: "Administrator", TokenSHA256: validDigest}}},
		{Credentials: []Credential{{ID: "admin", Name: " Administrator", TokenSHA256: validDigest}}},
		{Credentials: []Credential{{ID: "admin", Name: "Administrator", TokenSHA256: "invalid"}}},
		{Credentials: []Credential{{ID: "admin", Name: "Administrator", TokenSHA256: strings.ToUpper(validDigest)}}},
		{Credentials: []Credential{
			{ID: "admin", Name: "Administrator", TokenSHA256: validDigest},
			{ID: "admin", Name: "Automation", TokenSHA256: strings.Repeat("b", 64)},
		}},
		{Credentials: []Credential{
			{ID: "admin", Name: "Administrator", TokenSHA256: validDigest},
			{ID: "automation", Name: "Automation", TokenSHA256: validDigest},
		}},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid config was accepted: %#v", config)
		}
	}
}

func testToken(namespace, id, fill string) string {
	return namespace + ".10." + id + "." + strings.Repeat(fill, 32)
}
