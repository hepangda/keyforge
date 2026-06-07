// Package app — wiring.go is the composition root that connects every
// OAuth/OIDC handler to the public router. It deliberately lives in a
// separate file from app.go so the original bootstrap (config + logger +
// HTTP server lifecycle) stays small and reviewable.
//
// Everything in this file is best-effort plumbing: any subsystem that
// fails to construct logs a warning and is omitted, so a partially-
// configured environment (e.g. no jwks key yet) still produces a
// running HTTP server with health endpoints.
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/admin"
	adminclients "github.com/hepangda/keyforge/internal/admin/clients"
	"github.com/hepangda/keyforge/internal/audit"
	"github.com/hepangda/keyforge/internal/auth/authz"
	"github.com/hepangda/keyforge/internal/auth/mfa"
	"github.com/hepangda/keyforge/internal/config"
	kcrypto "github.com/hepangda/keyforge/internal/crypto"
	"github.com/hepangda/keyforge/internal/httpx/oidc"
	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/authflow"
	"github.com/hepangda/keyforge/internal/oauth/ciba"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/device"
	"github.com/hepangda/keyforge/internal/oauth/dpop"
	"github.com/hepangda/keyforge/internal/oauth/jar"
	"github.com/hepangda/keyforge/internal/oauth/jarm"
	"github.com/hepangda/keyforge/internal/oauth/par"
	"github.com/hepangda/keyforge/internal/oauth/tokenapi"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
	portal "github.com/hepangda/keyforge/internal/portal/api"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// bootstrapTenantID matches the UUID seeded by migration 0002. For now
// every request resolves to this tenant; multi-tenant routing is
// pending a host-header / issuer-resolver wire-up.
var bootstrapTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// wireOAuth attaches every OAuth/OIDC handler to publicRouter. Returns
// nil on success; on partial failures it logs and continues (the caller
// will still have a working /healthz).
func wireOAuth(ctx context.Context, cfg config.Config, logger *slog.Logger, publicRouter chi.Router, adminRouter chi.Router) error {
	pool, err := postgres.NewPool(ctx, cfg.Database)
	if err != nil {
		logger.Warn("OAuth wiring skipped: pool open failed", slog.Any("error", err))
		return nil
	}
	if err := postgres.Migrate(pool); err != nil {
		logger.Warn("migrations failed", slog.Any("error", err))
	}

	kekBytes, err := kcrypto.ParseMasterKey(cfg.JWKS.MasterKey)
	if err != nil {
		logger.Warn("OAuth wiring skipped: master key invalid", slog.Any("error", err))
		return nil
	}
	env, err := kcrypto.NewEnvelope(kekBytes)
	if err != nil {
		logger.Warn("OAuth wiring skipped: envelope construct failed", slog.Any("error", err))
		return nil
	}

	q := db.New(pool)
	tenantsRepo := tenants.New(pool)
	clientsRepo := clients.New(pool)
	usersRepo := users.New(pool)
	sessionStore := session.NewPostgresStore(pool)

	tenantFor := func(*http.Request) (uuid.UUID, error) {
		return bootstrapTenantID, nil
	}

	// ---- JWKS + signer ----------------------------------------------
	jwksStore := jwks.NewPostgresStore(pool, env, jwks.SystemClock())
	if _, err := jwksStore.EnsureActive(ctx, uuid.Nil, kcrypto.AlgRS256, jwks.UseSig); err != nil {
		logger.Warn("JWKS ensure active failed", slog.Any("error", err))
	}
	signer := jwks.NewSigner(jwksStore)
	jwksHandler := oidc.NewJWKSHandler(jwksStore, logger, func(*http.Request) uuid.UUID { return uuid.Nil })

	// ---- Discovery --------------------------------------------------
	resolver := oidc.NewDefaultTenantResolver(tenantsRepo, "default")
	discoveryHandler := oidc.NewDiscoveryHandler(resolver, oidc.DiscoveryConfig{
		IssuerOverride:           cfg.OIDC.Issuer,
		ScopesSupported:          []string{"openid", "profile", "email", "offline_access", "kf:portal", "kf:admin"},
		GrantTypesSupported:      []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba"},
		ResponseTypesSupported:   []string{"code"},
		ResponseModesSupported:   []string{"query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"},
		TokenEndpointAuthMethods: []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"},
		IDTokenSigningAlgValues:  []string{"RS256", "ES256"},
		SubjectTypesSupported:    []string{"public"},
		CodeChallengeMethods:     []string{"S256"},
	}, logger)

	// ---- client-auth dispatcher ------------------------------------
	lookup := &tenantedClientLookup{repo: clientsRepo, tenantFor: tenantFor}
	authenticator := clientauth.NewAuthenticator(
		lookup,
		clientauth.NewSecretBasicMethod(),
		clientauth.NewSecretPostMethod(),
		clientauth.NewPrivateKeyJWTMethod(cfg.OIDC.Issuer+"/oauth/token", nil),
		clientauth.NewNoneMethod(),
	)

	// ---- token issuer + tokenapi ------------------------------------
	issuer, err := tokens.NewIssuer(tokens.Config{
		Pool:           pool,
		Signer:         signer,
		UsersRepo:      usersRepo,
		Issuer:         cfg.OIDC.Issuer,
		AccessTokenTTL: cfg.OIDC.AccessTokenTTL,
	})
	if err != nil {
		logger.Warn("issuer construct failed", slog.Any("error", err))
		return nil
	}

	dpopValidator := dpop.New(cfg.OIDC.DPoPProofMaxSkew, dpop.NewMemoryReplay())

	// ---- authflow (authorize + login + consent + MFA) ---------------
	jarmResp, err := jarm.New(jarm.Config{Signer: signer, Issuer: cfg.OIDC.Issuer, TTL: 2 * time.Minute})
	if err != nil {
		logger.Warn("JARM construct failed", slog.Any("error", err))
	}
	authflowH, err := authflow.New(authflow.Config{
		Pool:          pool,
		ClientsRepo:   clientsRepo,
		UsersRepo:     usersRepo,
		SessionStore:  sessionStore,
		JARParser:     jar.New(cfg.OIDC.Issuer + "/oauth/authorize"),
		JARMResponder: jarmResp,
		Logger:        logger,
		TenantFor:     tenantFor,
		AuthReqTTL:    10 * time.Minute,
		CodeTTL:       cfg.OIDC.AuthorizeCodeTTL,
	})
	if err != nil {
		logger.Warn("authflow construct failed", slog.Any("error", err))
		return nil
	}
	wa, werr := mfa.NewWebAuthn(mfa.Config{
		RPID:          rpIDFromIssuer(cfg.OIDC.Issuer),
		RPDisplayName: "keyforge",
		RPOrigins:     []string{cfg.OIDC.Issuer},
	}, q)
	if werr != nil {
		logger.Warn("webauthn factor construct failed", slog.Any("error", werr))
	}
	authflowH.SetMFAFactors(authflow.MFAFactors{
		TOTP:     mfa.NewTOTP(q, env, "keyforge"),
		Recovery: mfa.NewRecovery(q),
		WebAuthn: wa,
	})

	tokenH, err := tokenapi.New(tokenapi.Config{
		Queries:       q,
		Issuer:        issuer,
		Authenticator: authenticator,
		ClientsRepo:   clientsRepo,
		UsersRepo:     usersRepo,
		DPoPValidator: dpopValidator,
		TenantFor:     tenantFor,
	})
	if err != nil {
		logger.Warn("tokenapi construct failed", slog.Any("error", err))
		return nil
	}

	parH, err := par.New(par.Config{
		Queries: q, Authenticator: authenticator, TenantFor: tenantFor, TTL: cfg.OIDC.PARRequestURITTL,
	})
	if err != nil {
		logger.Warn("PAR construct failed", slog.Any("error", err))
	}
	deviceH, err := device.New(device.Config{
		Queries: q, Authenticator: authenticator, TenantFor: tenantFor,
		CodeTTL: cfg.OIDC.DeviceCodeTTL, PollInterval: 5 * time.Second,
	})
	if err != nil {
		logger.Warn("device construct failed", slog.Any("error", err))
	}
	cibaH, err := ciba.New(ciba.Config{
		Queries: q, Authenticator: authenticator, UsersRepo: usersRepo, TenantFor: tenantFor,
		TTL: 5 * time.Minute, PollInterval: 5 * time.Second,
	})
	if err != nil {
		logger.Warn("CIBA construct failed", slog.Any("error", err))
	}

	// ---- attach to public router ------------------------------------
	publicRouter.Handle("/.well-known/openid-configuration", discoveryHandler)
	publicRouter.Handle("/.well-known/jwks.json", jwksHandler)

	mountStdlib(publicRouter, authflowH.Routes)
	mountStdlib(publicRouter, tokenH.Routes)
	if parH != nil {
		mountStdlib(publicRouter, parH.Routes)
	}
	if deviceH != nil {
		mountStdlib(publicRouter, deviceH.Routes)
	}
	if cibaH != nil {
		mountStdlib(publicRouter, cibaH.Routes)
	}
	authflowH.MountMFA(stdlibMux(publicRouter))

	// ---- portal API -------------------------------------------------
	auditor := audit.NewRecorder(audit.NewPostgresSink(q), logger)
	authn := authz.NewAuthenticator(q)
	portal.New(portal.Config{
		Queries:       q,
		UsersRepo:     usersRepo,
		SessionStore:  sessionStore,
		TOTP:          mfa.NewTOTP(q, env, "keyforge"),
		Recovery:      mfa.NewRecovery(q),
		WebAuthn:      wa,
		Auditor:       auditor,
		Authenticator: authn,
		TenantFor:     tenantFor,
	}).Mount(publicRouter, "/portal/api/v1")

	// ---- admin API (on admin listener so /metrics + admin share port) ----
	adminclients.NewHandler(clientsRepo).Mount(adminRouter)
	admin.New(admin.Config{
		Queries:       q,
		UsersRepo:     usersRepo,
		SessionStore:  sessionStore,
		Auditor:       auditor,
		Authenticator: authn,
		TenantFor:     tenantFor,
	}).Mount(adminRouter, "/admin/api/v1")

	logger.Info("OAuth subsystem wired",
		slog.String("issuer", cfg.OIDC.Issuer),
		slog.String("tenant", bootstrapTenantID.String()))
	return nil
}

// mountStdlib adapts a Handler.Routes(mux) signature (which expects the
// stdlib http.ServeMux interface) onto a chi.Router. We pass it a tiny
// shim that translates HandleFunc calls into chi.Router.Method calls.
func mountStdlib(r chi.Router, fn func(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
})) {
	fn(stdlibMux(r))
}

// stdlibMux returns a HandleFunc-style adapter over a chi.Router. The
// pattern shape "METHOD /path" is what every keyforge handler uses, so
// we split on the first space and dispatch via the appropriate chi
// method. This keeps the handler packages free of any chi dependency
// while still letting the composition root mount them on a chi tree.
func stdlibMux(r chi.Router) chiMux {
	return chiMux{r: r}
}

type chiMux struct{ r chi.Router }

func (m chiMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	method, path := splitMethodAndPath(pattern)
	if method == "" {
		m.r.HandleFunc(path, h)
		return
	}
	m.r.MethodFunc(method, path, h)
}

func splitMethodAndPath(pattern string) (method, path string) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[:i], pattern[i+1:]
		}
	}
	return "", pattern
}

// tenantedClientLookup adapts clients.Repository to clientauth.ClientLookup
// by stamping the current tenant onto the context before the lookup.
type tenantedClientLookup struct {
	repo      *clients.Repository
	tenantFor func(*http.Request) (uuid.UUID, error)
}

func (t *tenantedClientLookup) GetByClientID(ctx context.Context, clientID string) (*clients.Client, error) {
	return t.repo.GetByClientID(postgres.ContextWithTenant(ctx, bootstrapTenantID), clientID)
}

// guard unused import when pool isn't otherwise referenced
var _ = (*pgxpool.Pool)(nil)

// rpIDFromIssuer extracts the host (without port) from the configured
// issuer URL. WebAuthn's Relying Party ID must be a registrable
// domain or the exact hostname — never include a port or scheme.
func rpIDFromIssuer(issuer string) string {
	s := issuer
	if i := indexOf(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := indexOf(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := indexOf(s, ":"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "localhost"
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
