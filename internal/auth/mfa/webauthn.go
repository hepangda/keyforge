package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gwa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Errors surfaced by the WebAuthn factor.
var (
	ErrWebAuthnNoCredentials = errors.New("mfa: no webauthn credentials enrolled for user")
	ErrWebAuthnChallengeGone = errors.New("mfa: webauthn challenge expired or already consumed")
	ErrWebAuthnFinishFailed  = errors.New("mfa: webauthn ceremony failed")
)

// Ceremony identifiers stored on webauthn_challenges.
const (
	ceremonyRegister = "register"
	ceremonyAssert   = "assert"
)

// ChallengeTTL bounds how long an unfinished register/assert challenge
// survives. Specification recommends "a few minutes"; we pick 5.
const ChallengeTTL = 5 * time.Minute

// WebAuthnFactor wraps go-webauthn/webauthn against keyforge's persisted
// credentials and challenge table.
type WebAuthnFactor struct {
	wa *gwa.WebAuthn
	q  *db.Queries
}

// Config configures the relying party for new credentials.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// NewWebAuthn constructs the factor.
func NewWebAuthn(cfg Config, q *db.Queries) (*WebAuthnFactor, error) {
	wa, err := gwa.New(&gwa.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	return &WebAuthnFactor{wa: wa, q: q}, nil
}

// userView is the in-memory view we hand to go-webauthn for a user. It
// implements gwa.User by adapting our DB rows; calls into Begin/Finish
// receive the user's existing credentials so the library can populate
// allowedCredentials and check duplicates.
type userView struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []gwa.Credential
}

func (u *userView) WebAuthnID() []byte                       { return u.id[:] }
func (u *userView) WebAuthnName() string                     { return u.name }
func (u *userView) WebAuthnDisplayName() string              { return u.displayName }
func (u *userView) WebAuthnCredentials() []gwa.Credential    { return u.creds }
func (u *userView) WebAuthnIcon() string                     { return "" }

func (f *WebAuthnFactor) loadUserView(ctx context.Context, tenantID, userID uuid.UUID, name, displayName string) (*userView, error) {
	rows, err := f.q.ListWebAuthnCredentialsForUser(ctx, db.ListWebAuthnCredentialsForUserParams{
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	creds := make([]gwa.Credential, 0, len(rows))
	for _, row := range rows {
		transports := make([]protocol.AuthenticatorTransport, 0, len(row.Transports))
		for _, t := range row.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		var attestation string
		if row.AttestationType.Valid {
			attestation = row.AttestationType.String
		}
		creds = append(creds, gwa.Credential{
			ID:              row.CredentialID,
			PublicKey:       row.PublicKey,
			AttestationType: attestation,
			Transport:       transports,
			Authenticator: gwa.Authenticator{
				AAGUID:    row.Aaguid,
				SignCount: clampUint32(row.SignCount),
			},
		})
	}
	return &userView{
		id:          userID,
		name:        name,
		displayName: displayName,
		creds:       creds,
	}, nil
}

// RegisterBegin starts a registration ceremony. It returns the
// CredentialCreation options (for the browser) and the challenge ID
// (which the browser echoes back to RegisterFinish).
func (f *WebAuthnFactor) RegisterBegin(ctx context.Context, tenantID, userID uuid.UUID, name, displayName string) (*protocol.CredentialCreation, uuid.UUID, error) {
	u, err := f.loadUserView(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return nil, uuid.Nil, err
	}
	options, session, err := f.wa.BeginRegistration(u)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("begin registration: %w", err)
	}
	challengeID, err := f.storeChallenge(ctx, tenantID, &userID, ceremonyRegister, session)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return options, challengeID, nil
}

// RegisterFinish completes a registration ceremony and persists the
// credential. `nickname` is an optional user-friendly label (e.g.
// "YubiKey 5"). The HTTP request must carry the authenticator's response
// as posted by the browser.
func (f *WebAuthnFactor) RegisterFinish(ctx context.Context, tenantID, userID uuid.UUID, name, displayName string, challengeID uuid.UUID, nickname string, r *http.Request) (*db.UserWebauthnCredential, error) {
	session, err := f.consumeChallenge(ctx, tenantID, challengeID, ceremonyRegister)
	if err != nil {
		return nil, err
	}
	u, err := f.loadUserView(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return nil, err
	}
	cred, err := f.wa.FinishRegistration(u, *session, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWebAuthnFinishFailed, err)
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	nick := pgtype.Text{}
	if nickname != "" {
		nick = pgtype.Text{String: nickname, Valid: true}
	}
	att := pgtype.Text{}
	if cred.AttestationType != "" {
		att = pgtype.Text{String: cred.AttestationType, Valid: true}
	}
	row, err := f.q.InsertWebAuthnCredential(ctx, db.InsertWebAuthnCredentialParams{
		TenantID:        tenantID,
		UserID:          userID,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		SignCount:       int64(cred.Authenticator.SignCount),
		Aaguid:          cred.Authenticator.AAGUID,
		Transports:      transports,
		AttestationType: att,
		Nickname:        nick,
	})
	if err != nil {
		return nil, fmt.Errorf("persist webauthn credential: %w", err)
	}
	return row, nil
}

// LoginBegin starts an assertion (step-up) ceremony.
func (f *WebAuthnFactor) LoginBegin(ctx context.Context, tenantID, userID uuid.UUID, name, displayName string) (*protocol.CredentialAssertion, uuid.UUID, error) {
	u, err := f.loadUserView(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if len(u.creds) == 0 {
		return nil, uuid.Nil, ErrWebAuthnNoCredentials
	}
	options, session, err := f.wa.BeginLogin(u)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("begin login: %w", err)
	}
	challengeID, err := f.storeChallenge(ctx, tenantID, &userID, ceremonyAssert, session)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return options, challengeID, nil
}

// LoginFinish completes an assertion. On success the matched credential's
// sign_count is bumped (forensic anti-clone) and nil is returned.
func (f *WebAuthnFactor) LoginFinish(ctx context.Context, tenantID, userID uuid.UUID, name, displayName string, challengeID uuid.UUID, r *http.Request) error {
	session, err := f.consumeChallenge(ctx, tenantID, challengeID, ceremonyAssert)
	if err != nil {
		return err
	}
	u, err := f.loadUserView(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return err
	}
	cred, err := f.wa.FinishLogin(u, *session, r)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWebAuthnFinishFailed, err)
	}
	rows, err := f.q.ListWebAuthnCredentialsForUser(ctx, db.ListWebAuthnCredentialsForUserParams{
		TenantID: tenantID, UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("reload webauthn credentials: %w", err)
	}
	for _, row := range rows {
		if string(row.CredentialID) != string(cred.ID) {
			continue
		}
		return f.q.UpdateWebAuthnSignCount(ctx, db.UpdateWebAuthnSignCountParams{
			ID:        row.ID,
			TenantID:  tenantID,
			SignCount: int64(cred.Authenticator.SignCount),
		})
	}
	// FinishLogin returned a credential not in our store — should be impossible.
	return fmt.Errorf("webauthn finish: credential %x not in store", cred.ID)
}

// IsEnrolled reports whether the user has at least one registered passkey.
func (f *WebAuthnFactor) IsEnrolled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	rows, err := f.q.ListWebAuthnCredentialsForUser(ctx, db.ListWebAuthnCredentialsForUserParams{
		TenantID: tenantID, UserID: userID,
	})
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// Remove deletes a credential by ID.
func (f *WebAuthnFactor) Remove(ctx context.Context, tenantID, credentialRowID uuid.UUID) error {
	return f.q.DeleteWebAuthnCredential(ctx, db.DeleteWebAuthnCredentialParams{
		ID: credentialRowID, TenantID: tenantID,
	})
}

func (f *WebAuthnFactor) storeChallenge(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, ceremony string, session *gwa.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal session data: %w", err)
	}
	uid := pgtype.UUID{}
	if userID != nil {
		uid = pgtype.UUID{Bytes: *userID, Valid: true}
	}
	row, err := f.q.InsertWebAuthnChallenge(ctx, db.InsertWebAuthnChallengeParams{
		TenantID:    tenantID,
		UserID:      uid,
		Ceremony:    ceremony,
		SessionData: raw,
		ExpiresAt:   time.Now().Add(ChallengeTTL),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("store webauthn challenge: %w", err)
	}
	return row.ID, nil
}

func (f *WebAuthnFactor) consumeChallenge(ctx context.Context, tenantID, challengeID uuid.UUID, want string) (*gwa.SessionData, error) {
	row, err := f.q.ConsumeWebAuthnChallenge(ctx, db.ConsumeWebAuthnChallengeParams{
		ID: challengeID, TenantID: tenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrWebAuthnChallengeGone
		}
		return nil, fmt.Errorf("consume webauthn challenge: %w", err)
	}
	if !strings.EqualFold(row.Ceremony, want) {
		return nil, fmt.Errorf("webauthn challenge: ceremony mismatch (got %q want %q)", row.Ceremony, want)
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrWebAuthnChallengeGone
	}
	var session gwa.SessionData
	if err := json.Unmarshal(row.SessionData, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}
	return &session, nil
}

func clampUint32(n int64) uint32 {
	if n < 0 {
		return 0
	}
	if n > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(n) //nolint:gosec // bounded above
}
