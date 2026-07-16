package httpauth

import (
	"fmt"
	"net/http"

	internalorigin "github.com/lwmacct/260711-go-pkg-httpauth/pkg/httpauth/internal/origin"
)

type trustedOrigins = internalorigin.Origins

func parseTrustedOrigins(values []string) (trustedOrigins, error) {
	parsed, err := internalorigin.Parse(values)
	if err != nil {
		return parsed, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return parsed, nil
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}
