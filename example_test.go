package httpauth_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-httpauth"
	"github.com/lwmacct/260711-go-pkg-httpauth/statictoken"
)

func Example() {
	tokenMethod, _ := statictoken.New(statictoken.Config{Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", Secret: "example-access-token-secret"},
	}})
	auth, _ := httpauth.New(httpauth.Config{
		ExternalURLs: []string{"https://tool.example.com"},
		Session: httpauth.SessionConfig{
			TTL:  time.Hour,
			Keys: []httpauth.SessionKey{{ID: "primary", Secret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}},
		},
	}, []httpauth.Method{tokenMethod}, httpauth.Options{})

	mux := http.NewServeMux()
	mux.Handle("/auth/", auth.Handler())
	mux.Handle("/api/", auth.RequireAccess(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
}
