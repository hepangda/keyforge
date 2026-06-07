// Package tokenapi hosts the four token-related HTTP endpoints:
//
//   - POST /oauth/token       (auth-code + refresh_token grants)
//   - POST /oauth/introspect  (RFC 7662)
//   - POST /oauth/revoke      (RFC 7009)
//   - GET/POST /oauth/userinfo (OIDC Core §5.3)
//
// All four go through the same clientauth.Authenticator for the request's
// client, then dispatch to the appropriate grant handler or token lookup.
package tokenapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/oauth/ciba"
	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/oauth/device"
	"github.com/hepangda/keyforge/internal/oauth/dpop"
	"github.com/hepangda/keyforge/internal/oauth/mtls"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/oauth/scope"
	"github.com/hepangda/keyforge/internal/oauth/tokens"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Handler wires the four endpoints.
type Handler struct {
	q                  *db.Queries
	issuer             *tokens.Issuer
	authenticator      *clientauth.Authenticator
	clientsRepo        *clients.Repository
	usersRepo          *users.Repository
	catalog            scope.Catalog
	policy             *scope.Policy
	dpopValidator      *dpop.Validator
	mtlsExtractor      mtls.CertExtractor
	tenantFor          func(*http.Request) (uuid.UUID, error)
	codeTTL            time.Duration
	devicePollInterval time.Duration
}

// Config configures the Handler.
type Config struct {
	Queries       *db.Queries
	Issuer        *tokens.Issuer
	Authenticator *clientauth.Authenticator
	ClientsRepo   *clients.Repository
	UsersRepo     *users.Repository
	Catalog       scope.Catalog
	// DPoPValidator, when non-nil, enables RFC 9449 DPoP-bound access
	// tokens. A proof at /oauth/token causes the AT to carry cnf.jkt;
	// /userinfo and /introspect then require a matching proof.
	DPoPValidator *dpop.Validator
	// MTLSExtractor, when non-nil, enables RFC 8705 §3 certificate-bound
	// access tokens. When a client presents a TLS client cert at
	// /oauth/token (either directly or via a trusted-proxy header), the
	// issued AT carries cnf.x5t#S256; /userinfo and /introspect then
	// require the same cert.
	MTLSExtractor mtls.CertExtractor
	TenantFor     func(*http.Request) (uuid.UUID, error)
	CodeTTL       time.Duration
	// DevicePollMinInterval is the minimum time between successive
	// /oauth/token polls per device_code (RFC 8628 §3.5 slow_down).
	// Defaults to 5s if zero.
	DevicePollMinInterval time.Duration
}

// New constructs a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Issuer == nil || cfg.Authenticator == nil || cfg.ClientsRepo == nil ||
		cfg.UsersRepo == nil || cfg.Queries == nil {
		return nil, errors.New("tokenapi: incomplete config")
	}
	if cfg.Catalog == nil {
		cfg.Catalog = scope.StandardCatalog()
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 60 * time.Second
	}
	if cfg.DevicePollMinInterval == 0 {
		cfg.DevicePollMinInterval = 5 * time.Second
	}
	return &Handler{
		q:                  cfg.Queries,
		issuer:             cfg.Issuer,
		authenticator:      cfg.Authenticator,
		clientsRepo:        cfg.ClientsRepo,
		usersRepo:          cfg.UsersRepo,
		catalog:            cfg.Catalog,
		policy:             scope.NewPolicy(cfg.Queries),
		dpopValidator:      cfg.DPoPValidator,
		mtlsExtractor:      cfg.MTLSExtractor,
		tenantFor:          cfg.TenantFor,
		codeTTL:            cfg.CodeTTL,
		devicePollInterval: cfg.DevicePollMinInterval,
	}, nil
}

// Routes registers handlers on mux.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("POST /oauth/token", h.Token)
	mux.HandleFunc("POST /oauth/introspect", h.Introspect)
	mux.HandleFunc("POST /oauth/revoke", h.Revoke)
	mux.HandleFunc("GET /oauth/userinfo", h.UserInfo)
	mux.HandleFunc("POST /oauth/userinfo", h.UserInfo)
}

// =====================================================================
// /oauth/token
// =====================================================================

// Token implements the OAuth 2.0 token endpoint.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse body")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	authRes, err := h.authenticator.Authenticate(ctx, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.tokenAuthCode(w, r, ctx, tid, authRes.Client)
	case "refresh_token":
		h.tokenRefresh(w, r, ctx, tid, authRes.Client)
	case "client_credentials":
		h.tokenClientCredentials(w, r, ctx, tid, authRes.Client)
	case device.GrantType:
		h.tokenDeviceCode(w, r, ctx, tid, authRes.Client)
	case ciba.GrantType:
		h.tokenCIBA(w, r, ctx, tid, authRes.Client)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", grantType)
	}
}

func (h *Handler) tokenAuthCode(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, cli *clients.Client) {
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	verifier := r.PostFormValue("code_verifier")
	if code == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code or redirect_uri")
		return
	}
	codeHash := sha256Hex(code)

	req, err := h.q.GetAuthRequestByCodeHash(ctx, db.GetAuthRequestByCodeHashParams{
		CodeHash: textOpt(codeHash),
		TenantID: tid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "invalid_grant", "code not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	// Code must be unconsumed AND issued within the TTL.
	if req.CodeConsumedAt.Valid {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code already used")
		return
	}
	if !req.CodeIssuedAt.Valid || time.Since(req.CodeIssuedAt.Time) > h.codeTTL {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	if req.ClientID != cli.ID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "code belongs to a different client")
		return
	}
	if req.RedirectUri != redirectURI {
		writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if req.CodeChallenge.Valid && req.CodeChallenge.String != "" {
		method := "S256"
		if req.CodeChallengeMethod.Valid && req.CodeChallengeMethod.String != "" {
			method = req.CodeChallengeMethod.String
		}
		if verifier == "" {
			writeError(w, http.StatusBadRequest, "invalid_grant", "missing code_verifier")
			return
		}
		if err := pkce.Validate(method, req.CodeChallenge.String, verifier); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
	} else if cli.ClientType == clients.TypePublic {
		writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE required for public clients")
		return
	}
	if !req.UserID.Valid {
		writeError(w, http.StatusBadRequest, "invalid_grant", "no user attached to auth request")
		return
	}

	// Mark the code consumed (defence against parallel exchange).
	if err := h.q.MarkAuthRequestCodeConsumed(ctx, db.MarkAuthRequestCodeConsumedParams{
		ID: req.ID, TenantID: tid,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	user, err := h.usersRepo.GetByID(ctx, uuidFromPG(req.UserID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// DPoP: if the client presented a proof, bind the issued tokens.
	dpopJKT := ""
	if h.dpopValidator != nil && r.Header.Get(dpop.HeaderName) != "" {
		proof, err := h.dpopValidator.Validate(r, "", "")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
			return
		}
		dpopJKT = proof.JKT
	}
	// mTLS: if a client cert is on the request and the client authenticated
	// via tls_client_auth / self_signed_tls_client_auth, bind the AT.
	x5t := h.extractMTLSThumbprint(r)

	nonce := ""
	if req.Nonce.Valid {
		nonce = req.Nonce.String
	}
	resp, err := h.issuer.IssueForAuthCode(ctx, tokens.AuthCodeInput{
		TenantID:  tid,
		Client:    cli,
		User:      user,
		Scopes:    req.Scopes,
		Nonce:     nonce,
		AuthTime:  time.Time{},
		AMR:       nil,
		SessionID: uuidFromPG(req.LoginSessionID),
		CnfJKT:    dpopJKT,
		CnfX5T:    x5t,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, cli *clients.Client) {
	rt := r.PostFormValue("refresh_token")
	if rt == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}
	resp, err := h.issuer.RefreshIssue(ctx, tokens.RefreshInput{
		TenantID:           tid,
		Client:             cli,
		PresentedTokenHash: tokens.HashToken(rt),
	})
	if err != nil {
		if errors.Is(err, tokens.ErrInvalidGrant) {
			writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token invalid or revoked")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// tokenCIBA implements OIDC CIBA poll mode at /oauth/token. The client
// polls with grant_type=urn:openid:params:grant-type:ciba and an
// auth_req_id; we surface authorization_pending/slow_down/access_denied/
// expired_token until the user approves, then mint a token triple.
func (h *Handler) tokenCIBA(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, cli *clients.Client) {
	authReqID := r.PostFormValue("auth_req_id")
	if authReqID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing auth_req_id")
		return
	}
	res, err := ciba.Redeem(ctx, h.q, tid, authReqID, h.devicePollInterval)
	if err != nil {
		switch {
		case errors.Is(err, ciba.ErrAuthorizationPending):
			writeError(w, http.StatusBadRequest, "authorization_pending", "")
		case errors.Is(err, ciba.ErrSlowDown):
			writeError(w, http.StatusBadRequest, "slow_down", "")
		case errors.Is(err, ciba.ErrAccessDenied):
			writeError(w, http.StatusBadRequest, "access_denied", "")
		case errors.Is(err, ciba.ErrExpiredToken):
			writeError(w, http.StatusBadRequest, "expired_token", "")
		case errors.Is(err, ciba.ErrInvalidGrant):
			writeError(w, http.StatusBadRequest, "invalid_grant", "")
		default:
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		}
		return
	}
	if res.ClientPK != cli.ID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "auth_req_id does not belong to this client")
		return
	}
	user, uerr := h.usersRepo.GetByID(ctx, res.UserID)
	if uerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", uerr.Error())
		return
	}
	resp, ierr := h.issuer.IssueForAuthCode(ctx, tokens.AuthCodeInput{
		TenantID: tid,
		Client:   cli,
		User:     user,
		Scopes:   res.Scopes,
	})
	if ierr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", ierr.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// tokenDeviceCode implements RFC 8628 §3.4. The client polls /oauth/token
// with grant_type=urn:ietf:params:oauth:grant-type:device_code; we resolve
// the device_code, return one of the polling sentinels, or — on user
// approval — mint a token triple just like the auth-code path.
func (h *Handler) tokenDeviceCode(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, cli *clients.Client) {
	deviceCode := r.PostFormValue("device_code")
	if deviceCode == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing device_code")
		return
	}
	res, err := device.Redeem(ctx, h.q, tid, deviceCode, h.devicePollInterval)
	if err != nil {
		switch {
		case errors.Is(err, device.ErrAuthorizationPending):
			writeError(w, http.StatusBadRequest, "authorization_pending", "waiting for user approval")
		case errors.Is(err, device.ErrSlowDown):
			writeError(w, http.StatusBadRequest, "slow_down", "poll slower")
		case errors.Is(err, device.ErrAccessDenied):
			writeError(w, http.StatusBadRequest, "access_denied", "user denied")
		case errors.Is(err, device.ErrExpiredToken):
			writeError(w, http.StatusBadRequest, "expired_token", "device_code expired")
		case errors.Is(err, device.ErrInvalidGrant):
			writeError(w, http.StatusBadRequest, "invalid_grant", "unknown or used device_code")
		default:
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		}
		return
	}
	if res.ClientPK != cli.ID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "device_code does not belong to this client")
		return
	}
	user, uerr := h.usersRepo.GetByID(ctx, res.UserID)
	if uerr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", uerr.Error())
		return
	}
	resp, ierr := h.issuer.IssueForAuthCode(ctx, tokens.AuthCodeInput{
		TenantID: tid,
		Client:   cli,
		User:     user,
		Scopes:   res.Scopes,
	})
	if ierr != nil {
		writeError(w, http.StatusInternalServerError, "server_error", ierr.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// tokenClientCredentials implements RFC 6749 §4.4. Public clients (and
// clients registered with `none` auth) cannot use this grant; only
// confidential clients that successfully authenticated above reach here.
// The grant produces an access token only — no refresh token, no ID token.
func (h *Handler) tokenClientCredentials(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, cli *clients.Client) {
	if cli.ClientType != clients.TypeConfidential {
		writeError(w, http.StatusBadRequest, "unauthorized_client",
			"client_credentials grant requires a confidential client")
		return
	}
	if !slicesContains(cli.GrantTypes, "client_credentials") {
		writeError(w, http.StatusBadRequest, "unauthorized_client",
			"client is not configured for client_credentials grant")
		return
	}
	requested := parseSpaceList(r.PostFormValue("scope"))
	scopes, err := h.policy.ResolveScopes(requested, cli.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	resources := r.PostForm["resource"] // RFC 8707 may repeat
	audience, err := h.policy.ResolveAudiences(ctx, tid, cli.ID, cli.ClientID, resources)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	resp, err := h.issuer.IssueForClientCredentials(ctx, tokens.ClientCredentialsInput{
		TenantID:  tid,
		Client:    cli,
		Scopes:    scopes,
		Audiences: audience,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// =====================================================================
// /oauth/introspect (RFC 7662)
// =====================================================================

// Introspect returns metadata about a presented token. If the token is
// inactive (expired, revoked, or unknown), only {"active": false} is
// returned per the spec.
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if _, err := h.authenticator.Authenticate(ctx, r); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	at, err := h.q.GetAccessTokenByHash(ctx, db.GetAccessTokenByHashParams{
		TenantID: tid, TokenHash: tokens.HashToken(token),
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if time.Now().After(at.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	out := map[string]any{
		"active":     true,
		"scope":      strings.Join(at.Scopes, " "),
		"client_id":  at.ClientID.String(),
		"token_type": "Bearer",
		"exp":        at.ExpiresAt.Unix(),
		"iat":        at.IssuedAt.Unix(),
	}
	if at.UserID.Valid {
		out["sub"] = uuidFromPG(at.UserID).String()
	}
	if at.CnfJkt.Valid || at.CnfX5tS256.Valid {
		cnf := map[string]string{}
		if at.CnfJkt.Valid {
			cnf["jkt"] = at.CnfJkt.String
			out["token_type"] = "DPoP"
		}
		if at.CnfX5tS256.Valid {
			cnf["x5t#S256"] = at.CnfX5tS256.String
		}
		out["cnf"] = cnf
	}
	if len(at.Audience) > 0 {
		out["aud"] = at.Audience
	}
	writeJSON(w, http.StatusOK, out)
}

// =====================================================================
// /oauth/revoke (RFC 7009)
// =====================================================================

// Revoke marks the presented token (or its underlying refresh family) as
// revoked. Always returns 200 OK per the spec, even when the token was not
// found.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if _, err := h.authenticator.Authenticate(ctx, r); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	hint := r.PostFormValue("token_type_hint")
	hashed := tokens.HashToken(token)

	// Try AT first unless hint says otherwise.
	if hint != "refresh_token" {
		if err := h.q.RevokeAccessToken(ctx, db.RevokeAccessTokenParams{
			TenantID: tid, TokenHash: hashed,
		}); err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	if hint != "access_token" {
		// Refresh-token revocation: revoke the whole family.
		row, err := h.q.GetRefreshTokenByHash(ctx, db.GetRefreshTokenByHashParams{
			TenantID: tid, TokenHash: hashed,
		})
		if err == nil {
			_ = h.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{
				TenantID: tid, FamilyID: row.FamilyID,
			})
		}
	}
	w.WriteHeader(http.StatusOK)
}

// =====================================================================
// /oauth/userinfo (OIDC Core §5.3)
// =====================================================================

// UserInfo returns claims about the user identified by the bearer token.
// Claims are filtered by the access token's stored scope set.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="keyforge"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}
	at, err := h.q.GetAccessTokenByHash(ctx, db.GetAccessTokenByHashParams{
		TenantID: tid, TokenHash: tokens.HashToken(token),
	})
	if err != nil || time.Now().After(at.ExpiresAt) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	// DPoP enforcement: when the AT carries a jkt binding, the request MUST
	// arrive with a matching DPoP proof carrying ath = sha256(at).
	if at.CnfJkt.Valid && at.CnfJkt.String != "" {
		if h.dpopValidator == nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "DPoP-bound token but server has no validator")
			return
		}
		proof, perr := h.dpopValidator.Validate(r, "", token)
		if perr != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
			writeError(w, http.StatusUnauthorized, "invalid_dpop_proof", perr.Error())
			return
		}
		if proof.JKT != at.CnfJkt.String {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "jkt mismatch")
			return
		}
	}
	// mTLS enforcement: when the AT carries an x5t#S256 binding, the request
	// MUST arrive over a TLS connection presenting the same client cert.
	if at.CnfX5tS256.Valid && at.CnfX5tS256.String != "" {
		got := h.extractMTLSThumbprint(r)
		if got == "" || got != at.CnfX5tS256.String {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "client certificate mismatch")
			return
		}
	}
	if !at.UserID.Valid {
		writeError(w, http.StatusForbidden, "insufficient_scope", "no user attached to token")
		return
	}
	if !scope.Includes(at.Scopes, "openid") {
		writeError(w, http.StatusForbidden, "insufficient_scope", "openid scope required")
		return
	}
	user, err := h.usersRepo.GetByID(ctx, uuidFromPG(at.UserID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	out := map[string]any{"sub": user.ID.String()}
	for _, c := range h.catalog.ClaimsFor(at.Scopes) {
		switch c {
		case scope.ClaimEmail:
			out[c] = user.Email
		case scope.ClaimEmailVerified:
			out[c] = user.EmailVerified
		case scope.ClaimName:
			if user.DisplayName != "" {
				out[c] = user.DisplayName
			}
		case scope.ClaimPreferredUsername:
			out[c] = user.Email
		case scope.ClaimPicture:
			if user.PictureURL != "" {
				out[c] = user.PictureURL
			}
		case scope.ClaimLocale:
			if user.Locale != "" {
				out[c] = user.Locale
			}
		case scope.ClaimZoneinfo:
			if user.Zoneinfo != "" {
				out[c] = user.Zoneinfo
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// =====================================================================
// helpers
// =====================================================================

func (h *Handler) tenantContext(r *http.Request) (context.Context, uuid.UUID, error) {
	var tid uuid.UUID
	var err error
	if h.tenantFor != nil {
		tid, err = h.tenantFor(r)
		if err != nil {
			return nil, uuid.Nil, err
		}
	} else {
		tid = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	}
	return postgres.ContextWithTenant(r.Context(), tid), tid, nil
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "DPoP ") {
		return strings.TrimPrefix(h, "DPoP "), true
	}
	if v := r.PostFormValue("access_token"); v != "" {
		return v, true
	}
	return "", false
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func uuidFromPG(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.Nil
	}
	u, _ := uuid.FromBytes(p.Bytes[:])
	return u
}

type errBody struct {
	Error string `json:"error"`
	Desc  string `json:"error_description,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, errBody{Error: code, Desc: desc})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

// extractMTLSThumbprint returns the RFC 8705 cnf.x5t#S256 thumbprint of the
// client cert on r, or "" if none. The result is suitable for binding an
// access token at issuance and for verifying one at the resource server.
func (h *Handler) extractMTLSThumbprint(r *http.Request) string {
	if h.mtlsExtractor == nil {
		return ""
	}
	cert, err := h.mtlsExtractor.Extract(r)
	if err != nil || cert == nil {
		return ""
	}
	return mtls.Thumbprint(cert)
}

// parseSpaceList splits a space-delimited form value into trimmed fields.
func parseSpaceList(s string) []string {
	out := []string{}
	for _, f := range strings.Fields(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// slicesContains reports whether ss contains want (case sensitive).
func slicesContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
