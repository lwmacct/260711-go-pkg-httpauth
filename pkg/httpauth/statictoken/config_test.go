package statictoken

import "testing"

func TestValidateRejectsDuplicateCredentialSecret(t *testing.T) {
	_, err := (Config{Credentials: []Credential{
		{ID: "admin", Name: "Administrator", Secret: "shared-secret-value"},
		{ID: "automation", Name: "Automation", Secret: "shared-secret-value"},
	}}).Validate()
	if err == nil {
		t.Fatal("duplicate credential secret was accepted")
	}
}
