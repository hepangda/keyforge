// Package adminclients implements the REST CRUD surface for managing
// OAuth/OIDC client registrations under /admin/api/v1/clients.
//
// All endpoints require an admin context (RBAC plumbing is added in M16; for
// now the route is mounted on the admin listener which is operator-trusted).
package adminclients

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/oauth/clientauth"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
)

// Handler exposes the REST CRUD endpoints.
type Handler struct {
	Repo *clients.Repository
}

// NewHandler constructs a Handler.
func NewHandler(repo *clients.Repository) *Handler {
	return &Handler{Repo: repo}
}

// Mount registers the routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Route("/admin/api/v1/clients", func(r chi.Router) {
		r.Get("/", h.List)
		r.Post("/", h.Create)
		r.Get("/{id}", h.Get)
		r.Patch("/{id}", h.Patch)
		r.Delete("/{id}", h.Delete)
		r.Post("/{id}/secret", h.RotateSecret)
	})
}

type clientDTO struct {
	ID                                    uuid.UUID       `json:"id"`
	TenantID                              uuid.UUID       `json:"tenant_id"`
	ClientID                              string          `json:"client_id"`
	ClientType                            string          `json:"client_type"`
	Name                                  string          `json:"name"`
	Description                           string          `json:"description,omitempty"`
	GrantTypes                            []string        `json:"grant_types"`
	ResponseTypes                         []string        `json:"response_types"`
	ResponseModes                         []string        `json:"response_modes,omitempty"`
	Scopes                                []string        `json:"scopes"`
	TokenEndpointAuthMethod               string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg           string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	RequestObjectSigningAlg               string          `json:"request_object_signing_alg,omitempty"`
	RequireSignedRequestObject            bool            `json:"require_signed_request_object"`
	RequirePAR                            bool            `json:"require_par"`
	RequireDPoP                           bool            `json:"require_dpop"`
	DPoPBoundAccessTokens                 bool            `json:"dpop_bound_access_tokens"`
	TLSClientAuthSubjectDN                string          `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientCertificateBoundAccessTokens bool            `json:"tls_client_certificate_bound_access_tokens"`
	AuthorizationSignedResponseAlg        string          `json:"authorization_signed_response_alg,omitempty"`
	JWKSURI                               string          `json:"jwks_uri,omitempty"`
	JWKS                                  json.RawMessage `json:"jwks,omitempty"`
	RedirectURIs                          []string        `json:"redirect_uris"`
	Enabled                               bool            `json:"enabled"`
}

type createRequest struct {
	ClientID                              string          `json:"client_id"`
	ClientType                            string          `json:"client_type"`
	Name                                  string          `json:"name"`
	Description                           string          `json:"description,omitempty"`
	GrantTypes                            []string        `json:"grant_types"`
	ResponseTypes                         []string        `json:"response_types"`
	ResponseModes                         []string        `json:"response_modes"`
	Scopes                                []string        `json:"scopes"`
	TokenEndpointAuthMethod               string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg           string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	RequestObjectSigningAlg               string          `json:"request_object_signing_alg,omitempty"`
	RequireSignedRequestObject            bool            `json:"require_signed_request_object"`
	RequirePAR                            bool            `json:"require_par"`
	RequireDPoP                           bool            `json:"require_dpop"`
	DPoPBoundAccessTokens                 bool            `json:"dpop_bound_access_tokens"`
	TLSClientAuthSubjectDN                string          `json:"tls_client_auth_subject_dn,omitempty"`
	TLSClientCertificateBoundAccessTokens bool            `json:"tls_client_certificate_bound_access_tokens"`
	AuthorizationSignedResponseAlg        string          `json:"authorization_signed_response_alg,omitempty"`
	JWKSURI                               string          `json:"jwks_uri,omitempty"`
	JWKS                                  json.RawMessage `json:"jwks,omitempty"`
	RedirectURIs                          []string        `json:"redirect_uris"`
}

type createResponse struct {
	Client       clientDTO `json:"client"`
	ClientSecret string    `json:"client_secret,omitempty"`
}

// Create issues a new client. For confidential clients it generates a
// random secret and returns the plaintext in the response (exactly once).
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if req.ClientID == "" || req.Name == "" || req.ClientType == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", "client_id, name and client_type are required")
		return
	}
	cType := clients.ClientType(req.ClientType)
	if cType != clients.TypePublic && cType != clients.TypeConfidential {
		writeError(w, http.StatusBadRequest, "invalid_body", "client_type must be public or confidential")
		return
	}
	if req.TokenEndpointAuthMethod == "" {
		if cType == clients.TypePublic {
			req.TokenEndpointAuthMethod = string(clientauth.MethodNone)
		} else {
			req.TokenEndpointAuthMethod = string(clientauth.MethodSecretBasic)
		}
	}

	in := clients.CreateInput{
		ClientID:                              req.ClientID,
		ClientType:                            cType,
		Name:                                  req.Name,
		Description:                           req.Description,
		GrantTypes:                            req.GrantTypes,
		ResponseTypes:                         req.ResponseTypes,
		ResponseModes:                         req.ResponseModes,
		Scopes:                                req.Scopes,
		TokenEndpointAuthMethod:               req.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:           req.TokenEndpointAuthSigningAlg,
		RequestObjectSigningAlg:               req.RequestObjectSigningAlg,
		RequireSignedRequestObject:            req.RequireSignedRequestObject,
		RequirePAR:                            req.RequirePAR,
		RequireDPoP:                           req.RequireDPoP,
		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		TLSClientAuthSubjectDN:                req.TLSClientAuthSubjectDN,
		TLSClientCertificateBoundAccessTokens: req.TLSClientCertificateBoundAccessTokens,
		AuthorizationSignedResponseAlg:        req.AuthorizationSignedResponseAlg,
		JWKSURI:                               req.JWKSURI,
		JWKS:                                  req.JWKS,
		RedirectURIs:                          req.RedirectURIs,
	}

	var plainSecret string
	if cType == clients.TypeConfidential &&
		req.TokenEndpointAuthMethod != string(clientauth.MethodPrivateKeyJWT) &&
		req.TokenEndpointAuthMethod != string(clientauth.MethodTLSClientAuth) &&
		req.TokenEndpointAuthMethod != string(clientauth.MethodSelfSignedTLSAuth) {
		gen, err := clientauth.GenerateSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "secret_gen", err.Error())
			return
		}
		hash, err := clientauth.HashSecret(gen)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "secret_hash", err.Error())
			return
		}
		in.ClientSecretHash = hash
		plainSecret = gen
	}

	created, err := h.Repo.Create(r.Context(), in)
	if err != nil {
		if errors.Is(err, postgres.ErrNoTenant) {
			writeError(w, http.StatusInternalServerError, "no_tenant", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "create_client", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{
		Client:       toDTO(created),
		ClientSecret: plainSecret,
	})
}

// Get returns one client by primary key.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := h.Repo.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "client not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_client", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDTO(c))
}

// List returns a paginated slice of clients in the tenant.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePaging(r)
	rows, err := h.Repo.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_clients", err.Error())
		return
	}
	out := make([]clientDTO, 0, len(rows))
	for _, c := range rows {
		out = append(out, toDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   out,
		"limit":  limit,
		"offset": offset,
	})
}

// Patch updates the editable fields of a client.
func (h *Handler) Patch(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	// We do a read-then-replace of redirect URIs as the simplest correct
	// semantic; finer-grained update queries are deferred.
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	existing, err := h.Repo.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "client not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_client", err.Error())
		return
	}
	// For M4 we only support replacing redirect URIs and Disabled toggle via
	// PATCH; full attribute update plumbing lands with M16 when the admin
	// API matures.
	if len(req.RedirectURIs) > 0 {
		if err := h.Repo.ReplaceRedirectURIs(r.Context(), existing.ID, req.RedirectURIs); err != nil {
			writeError(w, http.StatusInternalServerError, "replace_uris", err.Error())
			return
		}
	}
	refreshed, err := h.Repo.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload_client", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDTO(refreshed))
}

// RotateSecret issues a new client secret and returns the plaintext once.
func (h *Handler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := h.Repo.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "client not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_client", err.Error())
		return
	}
	if c.ClientType != clients.TypeConfidential {
		writeError(w, http.StatusBadRequest, "wrong_type", "only confidential clients have secrets")
		return
	}
	plain, err := clientauth.GenerateSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret_gen", err.Error())
		return
	}
	// We need a repo method to update the secret hash; for M4 we delete-and-
	// re-add through the underlying queries. The Clients repo doesn't expose
	// a Rotate helper yet, so use a raw queries call. Deferred until full
	// admin surface lands.
	_ = plain
	writeError(w, http.StatusNotImplemented, "deferred", "rotate-secret endpoint lands with M16 admin RBAC")
}

// Delete removes a client.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.Repo.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete_client", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", fmt.Sprintf("invalid id %q", raw))
		return uuid.Nil, false
	}
	return id, true
}

func parsePaging(r *http.Request) (int32, int32) {
	limit := int32(50)
	offset := int32(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = int32(n) //nolint:gosec // bounded above by the 0 < n <= 200 check
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1_000_000_000 {
			offset = int32(n) //nolint:gosec // bounded above by the n <= 1e9 check
		}
	}
	return limit, offset
}

func toDTO(c *clients.Client) clientDTO {
	return clientDTO{
		ID:                                    c.ID,
		TenantID:                              c.TenantID,
		ClientID:                              c.ClientID,
		ClientType:                            string(c.ClientType),
		Name:                                  c.Name,
		Description:                           c.Description,
		GrantTypes:                            c.GrantTypes,
		ResponseTypes:                         c.ResponseTypes,
		ResponseModes:                         c.ResponseModes,
		Scopes:                                c.Scopes,
		TokenEndpointAuthMethod:               c.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:           c.TokenEndpointAuthSigningAlg,
		RequestObjectSigningAlg:               c.RequestObjectSigningAlg,
		RequireSignedRequestObject:            c.RequireSignedRequestObject,
		RequirePAR:                            c.RequirePAR,
		RequireDPoP:                           c.RequireDPoP,
		DPoPBoundAccessTokens:                 c.DPoPBoundAccessTokens,
		TLSClientAuthSubjectDN:                c.TLSClientAuthSubjectDN,
		TLSClientCertificateBoundAccessTokens: c.TLSClientCertificateBoundAccessTokens,
		AuthorizationSignedResponseAlg:        c.AuthorizationSignedResponseAlg,
		JWKSURI:                               c.JWKSURI,
		JWKS:                                  c.JWKS,
		RedirectURIs:                          c.RedirectURIs,
		Enabled:                               c.Enabled,
	}
}

type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, errorBody{Error: code, ErrorDescription: desc})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
