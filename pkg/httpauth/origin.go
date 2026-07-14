package httpauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type trustedOrigins struct {
	values map[string]*url.URL
	secure bool
}

func parseTrustedOrigins(values []string) (trustedOrigins, error) {
	origins := trustedOrigins{values: make(map[string]*url.URL, len(values))}
	if len(values) == 0 {
		return origins, fmt.Errorf("%w: external URLs are required", ErrInvalidConfig)
	}
	for index, value := range values {
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return origins, fmt.Errorf("%w: external URL", ErrInvalidConfig)
		}
		secure := parsed.Scheme == "https"
		loopback := parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if !secure && !loopback {
			return origins, fmt.Errorf("%w: external URL must use HTTPS except on loopback", ErrInvalidConfig)
		}
		if index == 0 {
			origins.secure = secure
		} else if origins.secure != secure {
			return origins, fmt.Errorf("%w: external URLs must use the same scheme", ErrInvalidConfig)
		}
		host := strings.ToLower(parsed.Host)
		if _, exists := origins.values[host]; exists {
			return origins, fmt.Errorf("%w: duplicate external URL host", ErrInvalidConfig)
		}
		origins.values[host] = parsed
	}
	return origins, nil
}

func (o trustedOrigins) externalURL(r *http.Request) (*url.URL, bool) {
	externalURL, ok := o.values[strings.ToLower(r.Host)]
	return externalURL, ok
}

func (o trustedOrigins) sameOrigin(r *http.Request) bool {
	expected, ok := o.externalURL(r)
	parsed, err := url.Parse(strings.TrimSpace(r.Header.Get("Origin")))
	return ok && err == nil && parsed.User == nil && parsed.Opaque == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" &&
		parsed.Scheme == expected.Scheme && strings.EqualFold(parsed.Host, expected.Host)
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}
