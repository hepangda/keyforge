// Package session manages the browser-side login session that ties a user
// to subsequent OAuth/OIDC requests.
//
// The cookie is set with the `__Host-` prefix, Secure, HttpOnly, and
// SameSite=Lax — `Lax` is required so cross-origin redirects from RPs back
// to /oauth/authorize still carry the cookie.
//
// Sessions are stored server-side in Postgres so administrators can revoke
// any specific session, and so an MFA step-up does not race with the
// cookie.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by Store.
var (
	ErrNotFound = errors.New("session: not found or expired")
)

// Session is the domain-shaped projection of a row in sessions.
type Session struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	UserID     uuid.UUID
	CSRFSecret string
	IP         string
	UserAgent  string
	MFALevel   string
	AMR        []string
	AuthTime   time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// Store is the persistence contract for browser sessions.
type Store interface {
	Create(ctx context.Context, in CreateInput) (*Session, error)
	Get(ctx context.Context, id uuid.UUID) (*Session, error)
	Touch(ctx context.Context, id uuid.UUID) error
	UpgradeMFA(ctx context.Context, id uuid.UUID, mfaLevel string, amr []string) error
	Revoke(ctx context.Context, id uuid.UUID) error
	ListForUser(ctx context.Context, userID uuid.UUID) ([]*Session, error)
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// CreateInput captures the inputs for opening a new session.
type CreateInput struct {
	UserID    uuid.UUID
	IP        string
	UserAgent string
	MFALevel  string
	AMR       []string
	TTL       time.Duration
}

// PostgresStore is the Postgres-backed Store.
type PostgresStore struct {
	q *db.Queries
}

// NewPostgresStore wraps a pgxpool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{q: db.New(pool)}
}

// Create implements Store.
func (s *PostgresStore) Create(ctx context.Context, in CreateInput) (*Session, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	row, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		TenantID:   tid,
		UserID:     in.UserID,
		CsrfSecret: csrf,
		Ip:         textOpt(in.IP),
		UserAgent:  textOpt(in.UserAgent),
		MfaLevel:   orDefault(in.MFALevel, "pwd"),
		Amr:        orDefaultSlice(in.AMR, []string{"pwd"}),
		AuthTime:   now,
		ExpiresAt:  now.Add(ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return toDomain(row), nil
}

// Get implements Store.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (*Session, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := s.q.GetSession(ctx, db.GetSessionParams{ID: id, TenantID: tid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return toDomain(row), nil
}

// Touch implements Store.
func (s *PostgresStore) Touch(ctx context.Context, id uuid.UUID) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return s.q.TouchSession(ctx, db.TouchSessionParams{ID: id, TenantID: tid})
}

// UpgradeMFA implements Store: bumps the session's mfa_level and amr after
// a successful step-up.
func (s *PostgresStore) UpgradeMFA(ctx context.Context, id uuid.UUID, mfaLevel string, amr []string) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return s.q.UpgradeSessionMFA(ctx, db.UpgradeSessionMFAParams{
		ID:       id,
		TenantID: tid,
		MfaLevel: mfaLevel,
		Amr:      amr,
	})
}

// Revoke implements Store.
func (s *PostgresStore) Revoke(ctx context.Context, id uuid.UUID) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return s.q.RevokeSession(ctx, db.RevokeSessionParams{ID: id, TenantID: tid})
}

// ListForUser implements Store.
func (s *PostgresStore) ListForUser(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListSessionsByUser(ctx, db.ListSessionsByUserParams{TenantID: tid, UserID: userID})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]*Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomain(row))
	}
	return out, nil
}

// RevokeAllForUser implements Store.
func (s *PostgresStore) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return s.q.RevokeAllSessionsForUser(ctx, db.RevokeAllSessionsForUserParams{
		TenantID: tid, UserID: userID,
	})
}

func toDomain(row *db.Session) *Session {
	return &Session{
		ID:         row.ID,
		TenantID:   row.TenantID,
		UserID:     row.UserID,
		CSRFSecret: row.CsrfSecret,
		IP:         textValue(row.Ip),
		UserAgent:  textValue(row.UserAgent),
		MFALevel:   row.MfaLevel,
		AMR:        row.Amr,
		AuthTime:   row.AuthTime,
		LastSeenAt: row.LastSeenAt,
		ExpiresAt:  row.ExpiresAt,
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func textValue(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultSlice(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

// CookieName is the canonical session cookie name. Use a __Host- prefix so
// browsers refuse to accept the cookie unless it is set with Secure,
// no Domain attribute, and Path=/.
const CookieName = "__Host-kf_sid"

// WriteCookie sets the session cookie on the response.
func WriteCookie(w http.ResponseWriter, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ReadCookie returns the session id from the cookie if present.
func ReadCookie(r *http.Request) (uuid.UUID, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.Value)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}
