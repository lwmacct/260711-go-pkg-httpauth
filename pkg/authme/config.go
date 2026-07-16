package authme

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

type Config struct {
	Enabled bool          `json:"enabled" desc:"由调用方决定是否启用认证"`
	Origins []string      `json:"origins" desc:"可信浏览器 origin 列表"`
	Prefix  string        `json:"path-prefix" desc:"认证 HTTP 路由前缀"`
	Session SessionConfig `json:"session" desc:"浏览器 Session 配置"`
}

func DefaultConfig() Config {
	return Config{Prefix: "/authme"}
}

func (c Config) Normalize() (Config, error) {
	c.Origins = append([]string(nil), c.Origins...)
	c.Prefix = strings.TrimRight(strings.TrimSpace(c.Prefix), "/")
	if c.Prefix == "" {
		c.Prefix = "/authme"
	}
	if c.Session.TTL == 0 {
		c.Session.TTL = 24 * time.Hour
	}
	for index, origin := range c.Origins {
		c.Origins[index] = strings.TrimRight(strings.TrimSpace(origin), "/")
	}
	if !strings.HasPrefix(c.Prefix, "/") || strings.ContainsAny(c.Prefix, "?#") {
		return Config{}, fmt.Errorf("%w: path prefix", ErrInvalidConfig)
	}
	if _, err := parseTrustedOrigins(c.Origins); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error { _, err := c.Normalize(); return err }

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Option interface{ apply(*authOptions) error }
type authOptions struct {
	methods    []Method
	authorizer Authorizer
	random     io.Reader
	clock      Clock
	logger     *slog.Logger
}
type optionFunc func(*authOptions) error

func (f optionFunc) apply(options *authOptions) error { return f(options) }
func WithMethods(methods ...Method) Option {
	configured := append([]Method(nil), methods...)
	return optionFunc(func(options *authOptions) error { options.methods = append([]Method(nil), configured...); return nil })
}
func WithAuthorizer(authorizer Authorizer) Option {
	return optionFunc(func(options *authOptions) error { options.authorizer = authorizer; return nil })
}
func WithRandom(random io.Reader) Option {
	return optionFunc(func(options *authOptions) error { options.random = random; return nil })
}
func WithClock(clock Clock) Option {
	return optionFunc(func(options *authOptions) error { options.clock = clock; return nil })
}

// WithLogger is reserved for integrations that add runtime diagnostics.
// Authme request errors are returned to the caller and are not logged here.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(options *authOptions) error { options.logger = logger; return nil })
}
