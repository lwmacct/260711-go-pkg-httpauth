package authme_test

import (
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme"
	"github.com/lwmacct/260711-go-pkg-authme/pkg/authme/adapters/statictoken"
)

func Example() {
	sessionKey := os.Getenv("AUTHME_SESSION_KEY")
	if sessionKey == "" {
		sessionKey = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	}
	tokenMethod, _ := statictoken.New(statictoken.Config{Credentials: []statictoken.Credential{
		{ID: "admin", Name: "Administrator", Token: "example-access-token"},
	}})
	auth, _ := authme.New(authme.Config{
		Origins: []string{"https://tool.example.com"},
		Session: authme.SessionConfig{
			TTL:  time.Hour,
			Keys: []authme.SessionKey{{ID: "primary", Secret: sessionKey}},
		},
	}, authme.WithMethods(tokenMethod))

	mux := http.NewServeMux()
	mux.Handle(auth.PathPrefix()+"/", auth.Handler())
	mux.Handle("/api/", auth.RequireAccess(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
}
