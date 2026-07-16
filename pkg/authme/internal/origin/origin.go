package origin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Origins struct {
	values map[string]*url.URL
	secure bool
}

func Parse(values []string) (Origins, error) {
	result := Origins{values: make(map[string]*url.URL, len(values))}
	if len(values) == 0 {
		return result, fmt.Errorf("trusted origins are required")
	}
	for index, value := range values {
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return result, fmt.Errorf("invalid trusted origin")
		}
		secure := parsed.Scheme == "https"
		loopback := parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if !secure && !loopback {
			return result, fmt.Errorf("trusted origin must use HTTPS except on loopback")
		}
		if index == 0 {
			result.secure = secure
		} else if result.secure != secure {
			return result, fmt.Errorf("trusted origins must use the same scheme")
		}
		host := strings.ToLower(parsed.Host)
		if _, exists := result.values[host]; exists {
			return result, fmt.Errorf("duplicate trusted origin host")
		}
		result.values[host] = parsed
	}
	return result, nil
}
func (o Origins) Secure() bool { return o.secure }
func (o Origins) ExternalURL(r *http.Request) (*url.URL, bool) {
	value, ok := o.values[strings.ToLower(r.Host)]
	return value, ok
}
func (o Origins) SameOrigin(r *http.Request) bool {
	expected, ok := o.ExternalURL(r)
	parsed, err := url.Parse(strings.TrimSpace(r.Header.Get("Origin")))
	return ok && err == nil && parsed.User == nil && parsed.Opaque == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && parsed.Scheme == expected.Scheme && strings.EqualFold(parsed.Host, expected.Host)
}
