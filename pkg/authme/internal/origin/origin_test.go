package origin

import (
	"strings"
	"testing"
)

func TestParseRejectsMixedSchemesWithConflictingOrigins(t *testing.T) {
	_, err := Parse([]string{"http://localhost:23199", "https://2310.s.lwmacct.com:23109"})
	if err == nil {
		t.Fatal("mixed origin schemes were accepted")
	}
	want := `trusted origins must use one scheme: origin[1]="https://2310.s.lwmacct.com:23109" conflicts with origin[0]="http://localhost:23199"`
	if err.Error() != want {
		t.Fatalf("unexpected error:\nwant: %s\n got: %s", want, err)
	}
}

func TestParseReportsInvalidOriginIndexAndValue(t *testing.T) {
	_, err := Parse([]string{"https://tool.example.com", "https://tool.example.com/path"})
	if err == nil {
		t.Fatal("origin path was accepted")
	}
	if message := err.Error(); !strings.Contains(message, `origin[1] "https://tool.example.com/path"`) {
		t.Fatalf("error does not identify invalid origin: %s", message)
	}
}
