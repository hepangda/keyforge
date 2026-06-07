// Package clients is the tenant-scoped repository for OAuth/OIDC client
// registrations and their redirect-URI allowlists.
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// ErrNotFound is returned when a client lookup misses in the current tenant.
var ErrNotFound = errors.New("client not found")

// ClientType enumerates the OAuth 2.1 client classifications.
type ClientType string

// Valid ClientType values.
const (
	TypePublic       ClientType = "public"
	TypeConfidential ClientType = "confidential"
)

// Client is the domain-shaped projection of a row in clients (plus the
// owning tenant's redirect-URI allowlist).
type Client struct {
	ID                                    uuid.UUID
	TenantID                              uuid.UUID
	ClientID                              string
	ClientSecretHash                      string
	ClientType                            ClientType
	Name                                  string
	Description                           string
	GrantTypes                            []string
	ResponseTypes                         []string
	ResponseModes                         []string
	Scopes                                []string
	TokenEndpointAuthMethod               string
	TokenEndpointAuthSigningAlg           string
	RequestObjectSigningAlg               string
	RequireSignedRequestObject            bool
	RequirePAR                            bool
	RequireDPoP                           bool
	DPoPBoundAccessTokens                 bool
	TLSClientAuthSubjectDN                string
	TLSClientCertificateBoundAccessTokens bool
	AuthorizationSignedResponseAlg        string
	JWKSURI                               string
	JWKS                                  json.RawMessage
	BackchannelTokenDeliveryMode          string
	BackchannelClientNotificationEndpoint string
	IsFederationClient                    bool
	Enabled                               bool
	RedirectURIs                          []string
	CreatedAt                             time.Time
	UpdatedAt                             time.Time
}

// Repository wraps the sqlc Queries with domain-shaped reads/writes.
type Repository struct {
	q *db.Queries
}

// New constructs a Repository against a pgxpool.
func New(pool *pgxpool.Pool) *Repository { return &Repository{q: db.New(pool)} }

// FromQueries lets transactional code bind a repository to its own *db.Queries.
func FromQueries(q *db.Queries) *Repository { return &Repository{q: q} }

// CreateInput captures the inputs needed for inserting a new client. Every
// field maps 1:1 with the matching column; defaults are applied by the SQL.
type CreateInput struct {
	ClientID                              string
	ClientSecretHash                      string
	ClientType                            ClientType
	Name                                  string
	Description                           string
	GrantTypes                            []string
	ResponseTypes                         []string
	ResponseModes                         []string
	Scopes                                []string
	TokenEndpointAuthMethod               string
	TokenEndpointAuthSigningAlg           string
	RequestObjectSigningAlg               string
	RequireSignedRequestObject            bool
	RequirePAR                            bool
	RequireDPoP                           bool
	DPoPBoundAccessTokens                 bool
	TLSClientAuthSubjectDN                string
	TLSClientCertificateBoundAccessTokens bool
	AuthorizationSignedResponseAlg        string
	JWKSURI                               string
	JWKS                                  json.RawMessage
	BackchannelTokenDeliveryMode          string
	BackchannelClientNotificationEndpoint string
	IsFederationClient                    bool
	RedirectURIs                          []string
}

// Create inserts a client and its redirect URIs in the current tenant.
// The redirect URIs are inserted in a follow-up statement; callers that want
// atomicity should wrap with TxRunner.WithTx.
func (r *Repository) Create(ctx context.Context, in CreateInput) (*Client, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.CreateClient(ctx, db.CreateClientParams{
		TenantID:                              tid,
		ClientID:                              in.ClientID,
		ClientSecretHash:                      text(in.ClientSecretHash),
		ClientType:                            string(in.ClientType),
		Name:                                  in.Name,
		Description:                           text(in.Description),
		GrantTypes:                            defaultSlice(in.GrantTypes, []string{"authorization_code"}),
		ResponseTypes:                         defaultSlice(in.ResponseTypes, []string{"code"}),
		ResponseModes:                         defaultSlice(in.ResponseModes, []string{"query"}),
		Scopes:                                defaultSlice(in.Scopes, []string{}),
		TokenEndpointAuthMethod:               defaultStr(in.TokenEndpointAuthMethod, "client_secret_basic"),
		TokenEndpointAuthSigningAlg:           text(in.TokenEndpointAuthSigningAlg),
		RequestObjectSigningAlg:               text(in.RequestObjectSigningAlg),
		RequireSignedRequestObject:            in.RequireSignedRequestObject,
		RequirePAR:                            in.RequirePAR,
		RequireDPoP:                           in.RequireDPoP,
		DPoPBoundAccessTokens:                 in.DPoPBoundAccessTokens,
		TLSClientAuthSubjectDN:                text(in.TLSClientAuthSubjectDN),
		TLSClientCertificateBoundAccessTokens: in.TLSClientCertificateBoundAccessTokens,
		AuthorizationSignedResponseAlg:        text(in.AuthorizationSignedResponseAlg),
		JWKSURI:                               text(in.JWKSURI),
		Jwks:                                  jsonOrNil(in.JWKS),
		BackchannelTokenDeliveryMode:          text(in.BackchannelTokenDeliveryMode),
		BackchannelClientNotificationEndpoint: text(in.BackchannelClientNotificationEndpoint),
		IsFederationClient:                    in.IsFederationClient,
	})
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	for _, u := range in.RedirectURIs {
		if err := r.q.AddClientRedirectURI(ctx, db.AddClientRedirectURIParams{
			TenantID: tid, ClientID: row.ID, RedirectUri: u,
		}); err != nil {
			return nil, fmt.Errorf("add redirect uri: %w", err)
		}
	}
	out := toDomain(row)
	out.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	return out, nil
}

// GetByID returns a client by primary key in the current tenant, hydrated
// with its redirect-URI list.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Client, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.GetClientByID(ctx, db.GetClientByIDParams{ID: id, TenantID: tid})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get client by id: %w", err)
	}
	return r.hydrate(ctx, row)
}

// GetByClientID returns a client by its OAuth client_id (the public
// identifier) in the current tenant.
func (r *Repository) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := r.q.GetClientByClientID(ctx, db.GetClientByClientIDParams{
		TenantID: tid, ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get client by client_id: %w", err)
	}
	return r.hydrate(ctx, row)
}

// List returns up to limit clients in the current tenant.
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]*Client, error) {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListClientsByTenant(ctx, db.ListClientsByTenantParams{
		TenantID: tid, Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	out := make([]*Client, 0, len(rows))
	for _, row := range rows {
		c, herr := r.hydrate(ctx, row)
		if herr != nil {
			return nil, herr
		}
		out = append(out, c)
	}
	return out, nil
}

// Delete removes a client and (via ON DELETE CASCADE) its redirect URIs.
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	return r.q.DeleteClient(ctx, db.DeleteClientParams{ID: id, TenantID: tid})
}

// ReplaceRedirectURIs replaces the full redirect-URI allowlist for a client.
func (r *Repository) ReplaceRedirectURIs(ctx context.Context, clientPK uuid.UUID, uris []string) error {
	tid, err := postgres.MustTenant(ctx)
	if err != nil {
		return err
	}
	if err := r.q.ReplaceClientRedirectURIs(ctx, db.ReplaceClientRedirectURIsParams{
		TenantID: tid, ClientID: clientPK,
	}); err != nil {
		return fmt.Errorf("clear redirect uris: %w", err)
	}
	for _, u := range uris {
		if err := r.q.AddClientRedirectURI(ctx, db.AddClientRedirectURIParams{
			TenantID: tid, ClientID: clientPK, RedirectUri: u,
		}); err != nil {
			return fmt.Errorf("add redirect uri: %w", err)
		}
	}
	return nil
}

func (r *Repository) hydrate(ctx context.Context, row *db.Client) (*Client, error) {
	c := toDomain(row)
	uris, err := r.q.ListClientRedirectURIs(ctx, db.ListClientRedirectURIsParams{
		TenantID: row.TenantID, ClientID: row.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("list redirect uris: %w", err)
	}
	c.RedirectURIs = uris
	return c, nil
}

func toDomain(row *db.Client) *Client {
	return &Client{
		ID:                                    row.ID,
		TenantID:                              row.TenantID,
		ClientID:                              row.ClientID,
		ClientSecretHash:                      textValue(row.ClientSecretHash),
		ClientType:                            ClientType(row.ClientType),
		Name:                                  row.Name,
		Description:                           textValue(row.Description),
		GrantTypes:                            row.GrantTypes,
		ResponseTypes:                         row.ResponseTypes,
		ResponseModes:                         row.ResponseModes,
		Scopes:                                row.Scopes,
		TokenEndpointAuthMethod:               row.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:           textValue(row.TokenEndpointAuthSigningAlg),
		RequestObjectSigningAlg:               textValue(row.RequestObjectSigningAlg),
		RequireSignedRequestObject:            row.RequireSignedRequestObject,
		RequirePAR:                            row.RequirePAR,
		RequireDPoP:                           row.RequireDPoP,
		DPoPBoundAccessTokens:                 row.DPoPBoundAccessTokens,
		TLSClientAuthSubjectDN:                textValue(row.TLSClientAuthSubjectDN),
		TLSClientCertificateBoundAccessTokens: row.TLSClientCertificateBoundAccessTokens,
		AuthorizationSignedResponseAlg:        textValue(row.AuthorizationSignedResponseAlg),
		JWKSURI:                               textValue(row.JWKSURI),
		JWKS:                                  row.Jwks,
		BackchannelTokenDeliveryMode:          textValue(row.BackchannelTokenDeliveryMode),
		BackchannelClientNotificationEndpoint: textValue(row.BackchannelClientNotificationEndpoint),
		IsFederationClient:                    row.IsFederationClient,
		Enabled:                               row.Enabled,
		CreatedAt:                             row.CreatedAt,
		UpdatedAt:                             row.UpdatedAt,
	}
}

func text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func textValue(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func defaultSlice(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func jsonOrNil(v json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return nil
	}
	return v
}
