// Package config defines keyforge's typed runtime configuration and the loader
// that assembles it from a YAML file plus KEYFORGE_* environment variables.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// EnvPrefix is the prefix env vars must carry to override config keys.
// e.g. KEYFORGE_SERVER__ADDR overrides server.addr.
const EnvPrefix = "KEYFORGE_"

// Config is keyforge's full runtime configuration.
type Config struct {
	Server   ServerConfig   `koanf:"server"   validate:"required"`
	Database DatabaseConfig `koanf:"database" validate:"required"`
	JWKS     JWKSConfig     `koanf:"jwks"     validate:"required"`
	OIDC     OIDCConfig     `koanf:"oidc"     validate:"required"`
	Logging  LoggingConfig  `koanf:"logging"`
	Tracing  TracingConfig  `koanf:"tracing"`
	Security SecurityConfig `koanf:"security"`
	Mail     MailConfig     `koanf:"mail"`
}

// ServerConfig governs the public HTTP listeners.
type ServerConfig struct {
	Addr              string        `koanf:"addr"                validate:"required"`
	AdminAddr         string        `koanf:"admin_addr"          validate:"required"`
	MTLSAddr          string        `koanf:"mtls_addr"`
	ReadHeaderTimeout time.Duration `koanf:"read_header_timeout" validate:"required"`
	IdleTimeout       time.Duration `koanf:"idle_timeout"        validate:"required"`
	ShutdownTimeout   time.Duration `koanf:"shutdown_timeout"    validate:"required"`
}

// DatabaseConfig points at the keyforge Postgres database.
type DatabaseConfig struct {
	URL             string        `koanf:"url"               validate:"required"`
	MaxOpenConns    int           `koanf:"max_open_conns"    validate:"min=1"`
	MaxIdleConns    int           `koanf:"max_idle_conns"    validate:"min=0"`
	ConnMaxLifetime time.Duration `koanf:"conn_max_lifetime" validate:"required"`
}

// JWKSConfig controls signing key lifecycle.
type JWKSConfig struct {
	MasterKey         string        `koanf:"master_key"          validate:"required,min=32"`
	RotateAfter       time.Duration `koanf:"rotate_after"        validate:"required"`
	RetainAfterRotate time.Duration `koanf:"retain_after_rotate" validate:"required"`
	DefaultAlg        string        `koanf:"default_alg"         validate:"required,oneof=RS256 ES256 EdDSA"`
}

// OIDCConfig sets issuer-wide OIDC properties.
type OIDCConfig struct {
	Issuer            string        `koanf:"issuer"             validate:"required,url"`
	AccessTokenTTL    time.Duration `koanf:"access_token_ttl"   validate:"required"`
	RefreshTokenTTL   time.Duration `koanf:"refresh_token_ttl"  validate:"required"`
	IDTokenTTL        time.Duration `koanf:"id_token_ttl"       validate:"required"`
	AuthorizeCodeTTL  time.Duration `koanf:"authorize_code_ttl" validate:"required"`
	PARRequestURITTL  time.Duration `koanf:"par_request_uri_ttl" validate:"required"`
	DeviceCodeTTL     time.Duration `koanf:"device_code_ttl"    validate:"required"`
	DPoPProofMaxSkew  time.Duration `koanf:"dpop_proof_max_skew" validate:"required"`
	SessionTTL        time.Duration `koanf:"session_ttl"        validate:"required"`
	SessionCookieName string        `koanf:"session_cookie_name" validate:"required"`
}

// LoggingConfig controls slog setup.
type LoggingConfig struct {
	Level  string `koanf:"level"  validate:"oneof=debug info warn error"`
	Format string `koanf:"format" validate:"oneof=json text"`
	Source bool   `koanf:"source"`
}

// TracingConfig governs OpenTelemetry export.
type TracingConfig struct {
	Enabled     bool    `koanf:"enabled"`
	ServiceName string  `koanf:"service_name"`
	Endpoint    string  `koanf:"endpoint"`
	SampleRatio float64 `koanf:"sample_ratio" validate:"gte=0,lte=1"`
}

// SecurityConfig holds cross-cutting security settings.
type SecurityConfig struct {
	TrustedProxies   []string `koanf:"trusted_proxies"`
	WebAuthnOrigins  []string `koanf:"webauthn_origins"`
	MTLSHeaderName   string   `koanf:"mtls_header_name"`
	MTLSHeaderFormat string   `koanf:"mtls_header_format" validate:"omitempty,oneof=rfc9440 xfcc pem"`
}

// MailConfig governs outbound transactional email.
type MailConfig struct {
	SMTPAddr string `koanf:"smtp_addr"`
	From     string `koanf:"from"`
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	StartTLS bool   `koanf:"starttls"`
	Insecure bool   `koanf:"insecure"`
}

// Defaults returns a Config with reasonable defaults that still need to be
// merged with file/env to satisfy required validations.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Addr:              ":8080",
			AdminAddr:         ":9090",
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			ShutdownTimeout:   30 * time.Second,
		},
		Database: DatabaseConfig{
			MaxOpenConns:    20,
			MaxIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
		},
		JWKS: JWKSConfig{
			RotateAfter:       90 * 24 * time.Hour,
			RetainAfterRotate: 30 * 24 * time.Hour,
			DefaultAlg:        "RS256",
		},
		OIDC: OIDCConfig{
			AccessTokenTTL:    15 * time.Minute,
			RefreshTokenTTL:   30 * 24 * time.Hour,
			IDTokenTTL:        15 * time.Minute,
			AuthorizeCodeTTL:  60 * time.Second,
			PARRequestURITTL:  90 * time.Second,
			DeviceCodeTTL:     10 * time.Minute,
			DPoPProofMaxSkew:  60 * time.Second,
			SessionTTL:        24 * time.Hour,
			SessionCookieName: "__Host-kf_sid",
		},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		Tracing: TracingConfig{ServiceName: "keyforge", SampleRatio: 0.1},
	}
}

// Load assembles configuration from the given YAML file (if non-empty) overlaid
// with KEYFORGE_* environment variables, then validates the result.
func Load(path string) (Config, error) {
	cfg := Defaults()
	k := koanf.New(".")

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("load yaml %q: %w", path, err)
		}
	}

	envProv := env.ProviderWithValue(EnvPrefix, ".", func(key, value string) (string, interface{}) {
		key = strings.TrimPrefix(key, EnvPrefix)
		key = strings.ReplaceAll(strings.ToLower(key), "__", ".")
		return key, value
	})
	if err := k.Load(envProv, nil); err != nil {
		return Config{}, fmt.Errorf("load env: %w", err)
	}

	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal: %w", err)
	}

	if err := validator.New(validator.WithRequiredStructEnabled()).Struct(cfg); err != nil {
		return Config{}, fmt.Errorf("validate: %w", err)
	}

	return cfg, nil
}
