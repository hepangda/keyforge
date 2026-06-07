// Package admin mounts the admin REST API at /admin/api/v1/* with RBAC
// enforcement and audit recording. Resource-specific handlers live in
// sub-packages (adminclients, adminusers, adminaudit, adminsessions).
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/audit"
	"github.com/hepangda/keyforge/internal/auth/authz"
	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Router bundles the admin endpoints behind the authz middleware. It
// reuses the global query layer; no transactional wrapping is needed
// because each request mutates exactly one resource.
type Router struct {
	q            *db.Queries
	usersRepo    *users.Repository
	sessionStore session.Store
	auditor      *audit.Recorder
	authn        *authz.Authenticator
	tenantFor    func(*http.Request) (uuid.UUID, error)
}

// Config configures the router.
type Config struct {
	Queries       *db.Queries
	UsersRepo     *users.Repository
	SessionStore  session.Store
	Auditor       *audit.Recorder
	Authenticator *authz.Authenticator
	TenantFor     func(*http.Request) (uuid.UUID, error)
}

// New constructs a Router.
func New(cfg Config) *Router {
	return &Router{
		q:            cfg.Queries,
		usersRepo:    cfg.UsersRepo,
		sessionStore: cfg.SessionStore,
		auditor:      cfg.Auditor,
		authn:        cfg.Authenticator,
		tenantFor:    cfg.TenantFor,
	}
}

// Mount registers the admin routes on the given chi router. The
// caller-supplied prefix lets you mount under /admin/api/v1 or any
// other base.
func (r *Router) Mount(parent chi.Router, prefix string) {
	parent.Route(prefix, func(s chi.Router) {
		s.Use(r.tenancyMiddleware)
		s.Use(r.authn.Middleware)

		s.With(authz.Require("users:read")).Get("/users", r.listUsers)
		s.With(authz.Require("users:read")).Get("/users/{id}/roles", r.listUserRoles)
		s.With(authz.Require("users:write")).Post("/users/{id}/roles", r.grantUserRole)
		s.With(authz.Require("users:write")).Delete("/users/{id}/roles/{roleName}", r.revokeUserRole)

		s.With(authz.Require("sessions:write")).Delete("/sessions/{id}", r.revokeSession)
		s.With(authz.Require("sessions:read")).Get("/users/{id}/sessions", r.listUserSessions)

		s.With(authz.Require("audit:read")).Get("/audit", r.listAudit)
		s.With(authz.Require("clients:read")).Get("/roles", r.listRoles)
	})
}

// tenancyMiddleware pins the tenant id on ctx before any auth/storage.
func (r *Router) tenancyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tid := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		if r.tenantFor != nil {
			t, err := r.tenantFor(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			tid = t
		}
		next.ServeHTTP(w, req.WithContext(postgres.ContextWithTenant(req.Context(), tid)))
	})
}

func (r *Router) record(req *http.Request, action, targetType, targetID string, attrs map[string]any) {
	id := authz.FromContext(req.Context())
	tid, _ := postgres.MustTenant(req.Context())
	ev := audit.Event{
		TenantID:   tid,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		IP:         httpx.RealIPFromContext(req.Context()),
		UserAgent:  req.UserAgent(),
		Attributes: attrs,
	}
	if id != nil {
		if id.UserID != uuid.Nil {
			u := id.UserID
			ev.ActorUserID = &u
		}
		if id.ClientID != uuid.Nil {
			c := id.ClientID
			ev.ActorClientID = &c
		}
	}
	r.auditor.Record(req.Context(), ev)
}

// =====================================================================
// /users/{id}/roles
// =====================================================================

func (r *Router) listUserRoles(w http.ResponseWriter, req *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(req, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	tid, _ := postgres.MustTenant(req.Context())
	roles, err := r.q.ListRolesForUser(req.Context(),
		db.ListRolesForUserParams{TenantID: tid, UserID: uid})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		out = append(out, map[string]any{
			"name":        role.Name,
			"description": role.Description,
			"permissions": role.Permissions,
		})
	}
	writeJSON(w, out)
}

type grantRoleReq struct {
	RoleName string `json:"role_name"`
}

func (r *Router) grantUserRole(w http.ResponseWriter, req *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(req, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body grantRoleReq
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	role, err := r.q.GetRoleByName(req.Context(), body.RoleName)
	if err != nil {
		http.Error(w, "unknown role", http.StatusBadRequest)
		return
	}
	tid, _ := postgres.MustTenant(req.Context())
	if err := r.q.GrantRole(req.Context(), db.GrantRoleParams{
		TenantID: tid, UserID: uid, RoleID: role.ID,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.record(req, "role.grant", "user", uid.String(), map[string]any{"role": role.Name})
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) revokeUserRole(w http.ResponseWriter, req *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(req, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	roleName := chi.URLParam(req, "roleName")
	role, err := r.q.GetRoleByName(req.Context(), roleName)
	if err != nil {
		http.Error(w, "unknown role", http.StatusBadRequest)
		return
	}
	tid, _ := postgres.MustTenant(req.Context())
	if err := r.q.RevokeRole(req.Context(), db.RevokeRoleParams{
		TenantID: tid, UserID: uid, RoleID: role.ID,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.record(req, "role.revoke", "user", uid.String(), map[string]any{"role": role.Name})
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================================
// /sessions
// =====================================================================

func (r *Router) revokeSession(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(chi.URLParam(req, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := r.sessionStore.Revoke(req.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.record(req, "session.revoke", "session", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) listUserSessions(w http.ResponseWriter, req *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(req, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	rows, err := r.sessionStore.ListForUser(req.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, s := range rows {
		out = append(out, map[string]any{
			"id":           s.ID,
			"ip":           s.IP,
			"user_agent":   s.UserAgent,
			"mfa_level":    s.MFALevel,
			"amr":          s.AMR,
			"auth_time":    s.AuthTime,
			"last_seen_at": s.LastSeenAt,
			"expires_at":   s.ExpiresAt,
		})
	}
	writeJSON(w, out)
}

// =====================================================================
// /audit
// =====================================================================

func (r *Router) listAudit(w http.ResponseWriter, req *http.Request) {
	tid, _ := postgres.MustTenant(req.Context())
	q := req.URL.Query()
	action := pgtype.Text{}
	if a := q.Get("action"); a != "" {
		action = pgtype.Text{String: a, Valid: true}
	}
	actor := pgtype.UUID{}
	if u := q.Get("actor"); u != "" {
		if id, err := uuid.Parse(u); err == nil {
			actor = pgtype.UUID{Bytes: id, Valid: true}
		}
	}
	before := time.Now()
	if t := q.Get("before"); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			before = parsed
		}
	}
	limit := int32(50)
	if l := q.Get("limit"); l != "" {
		// shrink/clamp to [1, 200]
		var n int
		if err := scanInt(l, &n); err == nil {
			if n < 1 {
				n = 1
			}
			if n > 200 {
				n = 200
			}
			limit = int32(n) //nolint:gosec // clamped above
		}
	}
	rows, err := r.q.ListAuditEvents(req.Context(), db.ListAuditEventsParams{
		TenantID:   tid,
		Action:     action,
		Actor:      actor,
		OccurredAt: before,
		Limit:      limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, e := range rows {
		out = append(out, map[string]any{
			"id":              e.ID,
			"action":          e.Action,
			"target_type":     e.TargetType,
			"target_id":       textOrEmpty(e.TargetID),
			"actor_user_id":   uuidOrZero(e.ActorUserID),
			"actor_client_id": uuidOrZero(e.ActorClientID),
			"ip":              textOrEmpty(e.Ip),
			"user_agent":      textOrEmpty(e.UserAgent),
			"request_id":      textOrEmpty(e.RequestID),
			"attributes":      e.Attributes,
			"occurred_at":     e.OccurredAt,
		})
	}
	writeJSON(w, out)
}

// =====================================================================
// /users (list)
// =====================================================================

func (r *Router) listUsers(w http.ResponseWriter, req *http.Request) {
	tid, _ := postgres.MustTenant(req.Context())
	limit, offset := paginationFrom(req)
	rows, err := r.q.ListUsersByTenant(req.Context(), db.ListUsersByTenantParams{
		TenantID: tid, Limit: limit, Offset: offset,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		out = append(out, map[string]any{
			"id":             u.ID,
			"email":          u.Email,
			"email_verified": u.EmailVerified,
			"display_name":   textOrEmpty(u.DisplayName),
			"enabled":        u.Enabled,
			"created_at":     u.CreatedAt,
		})
	}
	writeJSON(w, out)
}

// =====================================================================
// /roles (catalog)
// =====================================================================

func (r *Router) listRoles(w http.ResponseWriter, req *http.Request) {
	rows, err := r.q.ListRoles(req.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, role := range rows {
		out = append(out, map[string]any{
			"id":          role.ID,
			"name":        role.Name,
			"description": role.Description,
			"permissions": role.Permissions,
		})
	}
	writeJSON(w, out)
}

func paginationFrom(req *http.Request) (limit, offset int32) {
	limit = 50
	if l := req.URL.Query().Get("limit"); l != "" {
		var n int
		if err := scanInt(l, &n); err == nil && n >= 1 && n <= 200 {
			limit = int32(n) //nolint:gosec // clamped
		}
	}
	if o := req.URL.Query().Get("offset"); o != "" {
		var n int
		if err := scanInt(o, &n); err == nil && n >= 0 {
			offset = int32(n) //nolint:gosec // clamped
		}
	}
	return limit, offset
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func uuidOrZero(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.Nil
	}
	u, _ := uuid.FromBytes(p.Bytes[:])
	return u
}

func scanInt(s string, dst *int) error {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return errors.New("not int")
		}
		n = n*10 + int(c-'0')
	}
	*dst = n
	return nil
}
