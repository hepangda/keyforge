// Package tokens owns issuance and revocation of keyforge's hybrid token
// material:
//
//   - Access tokens are opaque (32 random bytes formatted as `kf_at_<base64>`)
//     with their sha256 hash stored in Postgres. Revoking the row makes the
//     token instantly invalid.
//   - ID tokens are signed JWTs minted via the jwks Signer. They are never
//     stored.
//   - Refresh tokens are opaque (`kf_rt_<base64>`), hashed at rest, and
//     rotated on each use. A presented RT whose row already has
//     consumed_at != NULL triggers reuse detection: the entire family is
//     revoked and the response is an OAuth2 invalid_grant.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/hepangda/keyforge/internal/jwks"
	"github.com/hepangda/keyforge/internal/oauth/scope"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Token type prefixes — clients can sniff `kf_at_` / `kf_rt_` to tell tokens
// apart without parsing them.
const (
	AccessTokenPrefix  = "kf_at_"
	RefreshTokenPrefix = "kf_rt_"
)

// Errors returned by the issuer / verifier.
var (
	ErrInvalidGrant = errors.New("tokens: invalid_grant")
	ErrTokenExpired = errors.New("tokens: token expired")
	ErrTokenRevoked = errors.New("tokens: token revoked")
	ErrNotFound     = errors.New("tokens: not found")
)

// Issuer is the token-minting service.
type Issuer struct {
	pool      *pgxpool.Pool
	q         *db.Queries
	signer    jwks.Signer
	usersRepo *users.Repository
	catalog   scope.Catalog
	issuer    string
	atTTL     time.Duration
	idTTL     time.Duration
	rtTTL     time.Duration
}

// Config configures the Issuer.
type Config struct {
	Pool            *pgxpool.Pool
	Signer          jwks.Signer
	UsersRepo       *users.Repository
	Catalog         scope.Catalog
	Issuer          string
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
}

// NewIssuer constructs an Issuer.
func NewIssuer(cfg Config) (*Issuer, error) {
	if cfg.Pool == nil || cfg.Signer == nil || cfg.UsersRepo == nil {
		return nil, errors.New("tokens: incomplete config")
	}
	if cfg.Catalog == nil {
		cfg.Catalog = scope.StandardCatalog()
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.IDTokenTTL == 0 {
		cfg.IDTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		return nil, errors.New("tokens: Issuer URL required")
	}
	return &Issuer{
		pool:      cfg.Pool,
		q:         db.New(cfg.Pool),
		signer:    cfg.Signer,
		usersRepo: cfg.UsersRepo,
		catalog:   cfg.Catalog,
		issuer:    cfg.Issuer,
		atTTL:     cfg.AccessTokenTTL,
		idTTL:     cfg.IDTokenTTL,
		rtTTL:     cfg.RefreshTokenTTL,
	}, nil
}

// Response is the JSON shape returned by /oauth/token.
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AuthCodeInput captures the parameters needed to mint a fresh token
// triple at the end of a successful auth-code exchange. The auth_request
// must already have been validated by the caller (code matched,
// redirect_uri matched, PKCE verified, client matches).
type AuthCodeInput struct {
	TenantID  uuid.UUID
	Client    *clients.Client
	User      *users.User
	Scopes    []string
	Nonce     string
	AuthTime  time.Time
	AMR       []string
	SessionID uuid.UUID
	CnfJKT    string // optional DPoP binding
	CnfX5T    string // optional mTLS binding
}

// IssueForAuthCode mints a fresh token triple.
func (i *Issuer) IssueForAuthCode(ctx context.Context, in AuthCodeInput) (*Response, error) {
	now := time.Now().UTC()
	atPlain, atHash, err := newOpaque(AccessTokenPrefix)
	if err != nil {
		return nil, err
	}
	atRow, err := i.q.InsertAccessToken(ctx, db.InsertAccessTokenParams{
		TenantID:   in.TenantID,
		TokenHash:  atHash,
		ClientID:   in.Client.ID,
		UserID:     pgtype.UUID{Bytes: in.User.ID, Valid: true},
		Scopes:     in.Scopes,
		Audience:   []string{in.Client.ClientID},
		CnfJkt:     textOpt(in.CnfJKT),
		CnfX5tS256: textOpt(in.CnfX5T),
		SessionID:  pgtype.UUID{Bytes: in.SessionID, Valid: in.SessionID != uuid.Nil},
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.atTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("insert access token: %w", err)
	}

	var rtPlain string
	if scope.Includes(in.Scopes, "offline_access") {
		family := uuid.New()
		rt, rtHash, err := newOpaque(RefreshTokenPrefix)
		if err != nil {
			return nil, err
		}
		if _, err := i.q.InsertRefreshToken(ctx, db.InsertRefreshTokenParams{
			TenantID:   in.TenantID,
			TokenHash:  rtHash,
			ClientID:   in.Client.ID,
			UserID:     in.User.ID,
			Scopes:     in.Scopes,
			FamilyID:   family,
			ParentID:   pgtype.UUID{},
			CnfJkt:     textOpt(in.CnfJKT),
			CnfX5tS256: textOpt(in.CnfX5T),
			IssuedAt:   now,
			ExpiresAt:  now.Add(i.rtTTL),
		}); err != nil {
			return nil, fmt.Errorf("insert refresh token: %w", err)
		}
		rtPlain = rt
	}

	tokenType := "Bearer"
	if in.CnfJKT != "" {
		tokenType = "DPoP"
	}

	resp := &Response{
		AccessToken:  atPlain,
		TokenType:    tokenType,
		ExpiresIn:    int(i.atTTL.Seconds()),
		RefreshToken: rtPlain,
		Scope:        strings.Join(in.Scopes, " "),
	}
	if scope.Includes(in.Scopes, "openid") {
		idTok, err := i.buildIDToken(ctx, in.TenantID, in.Client, in.User, in.Nonce, in.AuthTime, in.AMR)
		if err != nil {
			return nil, err
		}
		resp.IDToken = idTok
	}
	_ = atRow
	return resp, nil
}

// RefreshInput drives RefreshIssue.
type RefreshInput struct {
	TenantID           uuid.UUID
	Client             *clients.Client
	PresentedTokenHash string
	DPoPThumbprint     string // when client uses DPoP, must match parent
}

// ClientCredentialsInput drives IssueForClientCredentials.
type ClientCredentialsInput struct {
	TenantID  uuid.UUID
	Client    *clients.Client
	Scopes    []string
	Audiences []string
	CnfJKT    string
	CnfX5T    string
}

// IssueForClientCredentials mints an access token for a confidential
// client acting on its own behalf (RFC 6749 §4.4). No refresh token is
// minted; no ID token is minted (the grant has no end-user). The token's
// `sub` is the client_id.
func (i *Issuer) IssueForClientCredentials(ctx context.Context, in ClientCredentialsInput) (*Response, error) {
	now := time.Now().UTC()
	atPlain, atHash, err := newOpaque(AccessTokenPrefix)
	if err != nil {
		return nil, err
	}
	audience := in.Audiences
	if len(audience) == 0 {
		audience = []string{in.Client.ClientID}
	}
	if _, err := i.q.InsertAccessToken(ctx, db.InsertAccessTokenParams{
		TenantID:   in.TenantID,
		TokenHash:  atHash,
		ClientID:   in.Client.ID,
		UserID:     pgtype.UUID{}, // no user
		Scopes:     in.Scopes,
		Audience:   audience,
		CnfJkt:     textOpt(in.CnfJKT),
		CnfX5tS256: textOpt(in.CnfX5T),
		SessionID:  pgtype.UUID{},
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.atTTL),
	}); err != nil {
		return nil, fmt.Errorf("insert access token: %w", err)
	}
	tokenType := "Bearer"
	if in.CnfJKT != "" {
		tokenType = "DPoP"
	}
	return &Response{
		AccessToken: atPlain,
		TokenType:   tokenType,
		ExpiresIn:   int(i.atTTL.Seconds()),
		Scope:       strings.Join(in.Scopes, " "),
	}, nil
}

// RefreshIssue rotates a refresh token. The whole operation runs in a
// SERIALIZABLE transaction so concurrent presentation of the same RT can be
// detected reliably: if `consumed_at` was set by another transaction
// between SELECT FOR UPDATE and our UPDATE, the second commit will roll
// back, the loser retries and observes consumed_at != NULL, and we revoke
// the whole family.
func (i *Issuer) RefreshIssue(ctx context.Context, in RefreshInput) (*Response, error) {
	tx, err := i.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)

	prev, err := q.GetRefreshTokenByHash(ctx, db.GetRefreshTokenByHashParams{
		TenantID: in.TenantID, TokenHash: in.PresentedTokenHash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("load refresh token: %w", err)
	}
	if prev.RevokedAt.Valid {
		return nil, ErrInvalidGrant
	}
	if prev.ConsumedAt.Valid {
		// Reuse detection: revoke the entire family.
		if err := q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{
			TenantID: in.TenantID, FamilyID: prev.FamilyID,
		}); err != nil {
			return nil, fmt.Errorf("revoke family: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit reuse-detect: %w", err)
		}
		return nil, ErrInvalidGrant
	}
	if prev.ClientID != in.Client.ID {
		return nil, ErrInvalidGrant
	}
	if time.Now().After(prev.ExpiresAt) {
		return nil, ErrInvalidGrant
	}
	if prev.CnfJkt.Valid && prev.CnfJkt.String != in.DPoPThumbprint {
		return nil, ErrInvalidGrant
	}

	// Mark previous consumed
	if err := q.MarkRefreshTokenConsumed(ctx, db.MarkRefreshTokenConsumedParams{
		ID: prev.ID, TenantID: in.TenantID,
	}); err != nil {
		return nil, fmt.Errorf("mark consumed: %w", err)
	}

	// Mint child RT
	now := time.Now().UTC()
	rt, rtHash, err := newOpaque(RefreshTokenPrefix)
	if err != nil {
		return nil, err
	}
	if _, err := q.InsertRefreshToken(ctx, db.InsertRefreshTokenParams{
		TenantID:   in.TenantID,
		TokenHash:  rtHash,
		ClientID:   prev.ClientID,
		UserID:     prev.UserID,
		Scopes:     prev.Scopes,
		FamilyID:   prev.FamilyID,
		ParentID:   pgtype.UUID{Bytes: prev.ID, Valid: true},
		CnfJkt:     prev.CnfJkt,
		CnfX5tS256: prev.CnfX5tS256,
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.rtTTL),
	}); err != nil {
		return nil, fmt.Errorf("insert refresh token: %w", err)
	}

	// Mint child AT
	atPlain, atHash, err := newOpaque(AccessTokenPrefix)
	if err != nil {
		return nil, err
	}
	if _, err := q.InsertAccessToken(ctx, db.InsertAccessTokenParams{
		TenantID:   in.TenantID,
		TokenHash:  atHash,
		ClientID:   prev.ClientID,
		UserID:     pgtype.UUID{Bytes: prev.UserID, Valid: true},
		Scopes:     prev.Scopes,
		Audience:   []string{in.Client.ClientID},
		CnfJkt:     prev.CnfJkt,
		CnfX5tS256: prev.CnfX5tS256,
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.atTTL),
	}); err != nil {
		return nil, fmt.Errorf("insert access token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit refresh: %w", err)
	}

	tokenType := "Bearer"
	if prev.CnfJkt.Valid {
		tokenType = "DPoP"
	}
	resp := &Response{
		AccessToken:  atPlain,
		TokenType:    tokenType,
		ExpiresIn:    int(i.atTTL.Seconds()),
		RefreshToken: rt,
		Scope:        strings.Join(prev.Scopes, " "),
	}

	// Rehydrate user for an ID token if openid was in scope.
	if scope.Includes(prev.Scopes, "openid") {
		userCtx := postgres.ContextWithTenant(ctx, in.TenantID)
		user, err := i.usersRepo.GetByID(userCtx, prev.UserID)
		if err == nil {
			idTok, err := i.buildIDToken(ctx, in.TenantID, in.Client, user, "", time.Time{}, nil)
			if err == nil {
				resp.IDToken = idTok
			}
		}
	}
	return resp, nil
}

func (i *Issuer) buildIDToken(
	ctx context.Context,
	tenantID uuid.UUID,
	client *clients.Client,
	user *users.User,
	nonce string,
	authTime time.Time,
	amr []string,
) (string, error) {
	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Issuer(i.issuer).
		Subject(user.ID.String()).
		Audience([]string{client.ClientID}).
		IssuedAt(now).
		Expiration(now.Add(i.idTTL))
	if !authTime.IsZero() {
		_ = builder.Claim("auth_time", authTime.Unix())
	}
	if nonce != "" {
		_ = builder.Claim("nonce", nonce)
	}
	if len(amr) > 0 {
		_ = builder.Claim("amr", amr)
	}
	// Profile/email claims from scopes
	claims := i.catalog.ClaimsFor([]string{"profile", "email"})
	values := userClaimMap(user)
	for _, c := range claims {
		if v, ok := values[c]; ok {
			_ = builder.Claim(c, v)
		}
	}
	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("build id token: %w", err)
	}
	signed, err := i.signer.SignJWT(ctx, tenantID, tok)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}
	return signed, nil
}

func userClaimMap(u *users.User) map[string]any {
	m := map[string]any{
		"email":              u.Email,
		"email_verified":     u.EmailVerified,
		"preferred_username": u.Email,
	}
	if u.DisplayName != "" {
		m["name"] = u.DisplayName
	}
	if u.Locale != "" {
		m["locale"] = u.Locale
	}
	if u.Zoneinfo != "" {
		m["zoneinfo"] = u.Zoneinfo
	}
	if u.PictureURL != "" {
		m["picture"] = u.PictureURL
	}
	return m
}

// newOpaque mints a 32-random-byte opaque token with the given prefix,
// returning (plaintext, sha256 hex hash).
func newOpaque(prefix string) (string, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	body := base64.RawURLEncoding.EncodeToString(b[:])
	plain := prefix + body
	return plain, HashToken(plain), nil
}

// HashToken returns the canonical sha256-hex representation that the DB
// stores in `token_hash`.
func HashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }
