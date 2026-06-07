package oidc

import (
	"log/slog"
	"net/http"
)

// DiscoveryConfig captures the runtime knobs the discovery doc reflects.
// Most fields mirror config.OIDCConfig / SecurityConfig; the booleans
// describe which optional spec extensions are enabled.
type DiscoveryConfig struct {
	IssuerOverride           string
	BasePath                 string
	ScopesSupported          []string
	GrantTypesSupported      []string
	ResponseTypesSupported   []string
	ResponseModesSupported   []string
	TokenEndpointAuthMethods []string
	IDTokenSigningAlgValues  []string
	SubjectTypesSupported    []string
	ClaimsSupported          []string
	CodeChallengeMethods     []string
	ServiceDocumentationURL  string
	UILocalesSupported       []string

	// Optional spec extensions
	PARSupported                  bool
	RequirePARByDefault           bool
	JARSupported                  bool
	RequestObjectAlgValues        []string
	JARMSupported                 bool
	JARMAlgValues                 []string
	DPoPSupported                 bool
	DPoPSigningAlgValues          []string
	MTLSBoundTokensSupported      bool
	DeviceFlowSupported           bool
	CIBASupported                 bool
	BackchannelTokenDeliveryModes []string
	BackchannelAuthAlgValues      []string
}

// DiscoveryHandler emits /.well-known/openid-configuration tailored to the
// resolving tenant and the runtime configuration.
type DiscoveryHandler struct {
	Resolver TenantResolver
	Cfg      DiscoveryConfig
	logger   *slog.Logger
}

// NewDiscoveryHandler constructs the handler.
func NewDiscoveryHandler(resolver TenantResolver, cfg DiscoveryConfig, logger *slog.Logger) *DiscoveryHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DiscoveryHandler{Resolver: resolver, Cfg: cfg, logger: logger}
}

// ServeHTTP implements http.Handler.
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.Resolver.Resolve(r.Context(), r)
	if err != nil {
		h.logger.Warn("discovery tenant resolution failed", slog.Any("error", err))
		http.Error(w, "tenant not configured", http.StatusNotFound)
		return
	}
	issuer := h.Cfg.IssuerOverride
	if issuer == "" {
		issuer = tenant.Issuer
	}
	base := issuer + h.Cfg.BasePath

	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"introspection_endpoint":                base + "/oauth/introspect",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"end_session_endpoint":                  base + "/oauth/logout",
		"scopes_supported":                      orDefault(h.Cfg.ScopesSupported, []string{"openid", "profile", "email", "offline_access"}),
		"grant_types_supported":                 orDefault(h.Cfg.GrantTypesSupported, []string{"authorization_code", "refresh_token", "client_credentials"}),
		"response_types_supported":              orDefault(h.Cfg.ResponseTypesSupported, []string{"code"}),
		"response_modes_supported":              orDefault(h.Cfg.ResponseModesSupported, []string{"query", "fragment", "form_post"}),
		"token_endpoint_auth_methods_supported": orDefault(h.Cfg.TokenEndpointAuthMethods, []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth", "none"}),
		"id_token_signing_alg_values_supported": orDefault(h.Cfg.IDTokenSigningAlgValues, []string{"RS256", "ES256", "EdDSA"}),
		"subject_types_supported":               orDefault(h.Cfg.SubjectTypesSupported, []string{"public"}),
		"claims_supported":                      orDefault(h.Cfg.ClaimsSupported, []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "email", "email_verified", "name", "preferred_username"}),
		"code_challenge_methods_supported":      orDefault(h.Cfg.CodeChallengeMethods, []string{"S256"}),
		"require_pushed_authorization_requests": h.Cfg.RequirePARByDefault,
	}
	if len(h.Cfg.UILocalesSupported) > 0 {
		doc["ui_locales_supported"] = h.Cfg.UILocalesSupported
	}
	if h.Cfg.ServiceDocumentationURL != "" {
		doc["service_documentation"] = h.Cfg.ServiceDocumentationURL
	}

	if h.Cfg.PARSupported {
		doc["pushed_authorization_request_endpoint"] = base + "/oauth/par"
	}
	if h.Cfg.JARSupported {
		doc["request_parameter_supported"] = true
		doc["request_uri_parameter_supported"] = true
		doc["request_object_signing_alg_values_supported"] = orDefault(h.Cfg.RequestObjectAlgValues, []string{"RS256", "ES256", "EdDSA"})
	}
	if h.Cfg.JARMSupported {
		doc["response_modes_supported"] = appendUnique(
			doc["response_modes_supported"].([]string),
			"jwt", "query.jwt", "fragment.jwt", "form_post.jwt",
		)
		doc["authorization_signing_alg_values_supported"] = orDefault(h.Cfg.JARMAlgValues, []string{"RS256", "ES256", "EdDSA"})
	}
	if h.Cfg.DPoPSupported {
		doc["dpop_signing_alg_values_supported"] = orDefault(h.Cfg.DPoPSigningAlgValues, []string{"ES256", "RS256", "EdDSA"})
	}
	if h.Cfg.MTLSBoundTokensSupported {
		doc["tls_client_certificate_bound_access_tokens"] = true
		doc["mtls_endpoint_aliases"] = map[string]string{
			"token_endpoint":         base + "/oauth/token",
			"userinfo_endpoint":      base + "/oauth/userinfo",
			"introspection_endpoint": base + "/oauth/introspect",
			"revocation_endpoint":    base + "/oauth/revoke",
		}
	}
	if h.Cfg.DeviceFlowSupported {
		doc["device_authorization_endpoint"] = base + "/device_authorization"
	}
	if h.Cfg.CIBASupported {
		doc["backchannel_authentication_endpoint"] = base + "/bc-authorize"
		doc["backchannel_token_delivery_modes_supported"] = orDefault(h.Cfg.BackchannelTokenDeliveryModes, []string{"poll"})
		doc["backchannel_authentication_request_signing_alg_values_supported"] = orDefault(h.Cfg.BackchannelAuthAlgValues, []string{"RS256", "ES256", "EdDSA"})
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

func orDefault[T any](v, def []T) []T {
	if len(v) == 0 {
		return def
	}
	return v
}

func appendUnique(base []string, more ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(more))
	out := make([]string, 0, len(base)+len(more))
	for _, s := range base {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range more {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
