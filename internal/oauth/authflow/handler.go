// Package authflow owns the server-rendered authorization-code flow:
// /oauth/authorize, /oauth/login, /oauth/consent.
//
// The handlers persist an `auth_request` row on first contact so the user
// can step through login + consent without losing the OAuth parameters,
// then redirect back to the client's redirect_uri with `code` + `state`.
package authflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hepangda/keyforge/internal/auth/password"
	"github.com/hepangda/keyforge/internal/httpx"
	"github.com/hepangda/keyforge/internal/httpx/csrf"
	"github.com/hepangda/keyforge/internal/oauth/jar"
	"github.com/hepangda/keyforge/internal/oauth/jarm"
	"github.com/hepangda/keyforge/internal/oauth/par"
	"github.com/hepangda/keyforge/internal/oauth/pkce"
	"github.com/hepangda/keyforge/internal/session"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
	"github.com/hepangda/keyforge/internal/storage/users"
)

// Errors surfaced to OAuth-aware callers as `error` query params.
var (
	ErrInvalidClient   = errors.New("invalid_client")
	ErrInvalidRequest  = errors.New("invalid_request")
	ErrUnauthorized    = errors.New("login_required")
	ErrAccessDenied    = errors.New("access_denied")
	ErrUnsupportedResp = errors.New("unsupported_response_type")
)

// Handler bundles the three endpoints. It deliberately owns its own
// template set rather than touching internal/httpx so the auth UI can
// evolve independently from the SPA.
type Handler struct {
	pool          *pgxpool.Pool
	q             *db.Queries
	clientsRepo   *clients.Repository
	usersRepo     *users.Repository
	sessionStore  session.Store
	scopeCatalog  ScopeCatalog
	jarParser     *jar.Parser
	jarmResponder *jarm.Responder
	logger        *slog.Logger
	tenantFor     func(*http.Request) (uuid.UUID, error)
	authReqTTL    time.Duration
	codeTTL       time.Duration
	templates     *template.Template
	mfaFactors    MFAFactors
	idpLister     IdPLister
}

// IdPLister yields the enabled upstream identity providers for the
// current tenant so /oauth/login can render IdP buttons. Optional.
type IdPLister interface {
	Enabled(ctx context.Context, tenantID uuid.UUID) ([]IdPButton, error)
}

// IdPButton is the rendered representation of an upstream IdP on the
// login page.
type IdPButton struct {
	Slug        string
	DisplayName string
}

// SetIdPLister attaches an IdPLister. Optional.
func (h *Handler) SetIdPLister(l IdPLister) { h.idpLister = l }

// Config configures the handler.
type Config struct {
	Pool         *pgxpool.Pool
	ClientsRepo  *clients.Repository
	UsersRepo    *users.Repository
	SessionStore session.Store
	ScopeCatalog ScopeCatalog
	// JARParser, when non-nil, enables RFC 9101 `request` parameter parsing.
	JARParser *jar.Parser
	// JARMResponder, when non-nil, enables JWT-secured authorization
	// responses for clients that ask for response_mode={jwt,query.jwt,
	// fragment.jwt,form_post.jwt} or whose `authorization_signed_response_alg`
	// is configured.
	JARMResponder *jarm.Responder
	Logger        *slog.Logger
	TenantFor     func(*http.Request) (uuid.UUID, error)
	AuthReqTTL    time.Duration
	CodeTTL       time.Duration
}

// ScopeCatalog yields human-readable descriptions for the consent screen.
type ScopeCatalog interface {
	Describe(scope string) string
}

// staticCatalog is a minimal catalog used until the M7 scope registry lands.
type staticCatalog struct{}

func (staticCatalog) Describe(scope string) string {
	switch scope {
	case "openid":
		return "Verify who you are."
	case "profile":
		return "See your basic profile information."
	case "email":
		return "Read your email address."
	case "offline_access":
		return "Stay signed in when you're not using the app."
	}
	return scope
}

// DefaultScopeCatalog returns the built-in catalog.
func DefaultScopeCatalog() ScopeCatalog { return staticCatalog{} }

//go:embed templates_embed
var embeddedTemplates embed.FS

// New constructs a Handler. If cfg.TenantFor is nil, every request is
// routed to the bootstrap tenant (uuid 00000000-...-001).
func New(cfg Config) (*Handler, error) {
	if cfg.Pool == nil || cfg.ClientsRepo == nil || cfg.UsersRepo == nil || cfg.SessionStore == nil {
		return nil, errors.New("authflow: incomplete config")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ScopeCatalog == nil {
		cfg.ScopeCatalog = DefaultScopeCatalog()
	}
	if cfg.AuthReqTTL == 0 {
		cfg.AuthReqTTL = 10 * time.Minute
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 60 * time.Second
	}
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	return &Handler{
		pool:          cfg.Pool,
		q:             db.New(cfg.Pool),
		clientsRepo:   cfg.ClientsRepo,
		usersRepo:     cfg.UsersRepo,
		sessionStore:  cfg.SessionStore,
		scopeCatalog:  cfg.ScopeCatalog,
		jarParser:     cfg.JARParser,
		jarmResponder: cfg.JARMResponder,
		logger:        cfg.Logger,
		tenantFor:     cfg.TenantFor,
		authReqTTL:    cfg.AuthReqTTL,
		codeTTL:       cfg.CodeTTL,
		templates:     tmpls,
	}, nil
}

func loadTemplates() (*template.Template, error) {
	// Templates live both on disk (web/templates/*.html) and embedded
	// (web/templates_embed/*.html); we prefer embedded so the binary is
	// self-contained.
	sub, err := fs.Sub(embeddedTemplates, "templates_embed")
	if err != nil {
		return nil, err
	}
	return template.New("authflow").ParseFS(sub, "*.html")
}

// Routes registers the auth-flow endpoints on mux.
func (h *Handler) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
},
) {
	mux.HandleFunc("GET /oauth/authorize", h.Authorize)
	mux.HandleFunc("POST /oauth/authorize", h.Authorize)
	mux.HandleFunc("GET /oauth/login", h.LoginGET)
	mux.HandleFunc("POST /oauth/login", h.LoginPOST)
	mux.HandleFunc("GET /oauth/consent", h.ConsentGET)
	mux.HandleFunc("POST /oauth/consent", h.ConsentPOST)
}

func (h *Handler) tenant(r *http.Request) (uuid.UUID, error) {
	if h.tenantFor != nil {
		return h.tenantFor(r)
	}
	return uuid.MustParse("00000000-0000-0000-0000-000000000001"), nil
}

func (h *Handler) tenantContext(r *http.Request) (context.Context, uuid.UUID, error) {
	tid, err := h.tenant(r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return postgres.ContextWithTenant(r.Context(), tid), tid, nil
}

// =====================================================================
// /oauth/authorize
// =====================================================================

// Authorize validates the inbound authorization request, persists it as an
// auth_requests row, and redirects to /oauth/login or /oauth/consent
// depending on the current session state.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Bad request", "Could not parse parameters.")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}

	params := r.Form // GET and POST both supported
	clientIDStr := params.Get("client_id")
	if clientIDStr == "" {
		h.renderError(w, r, http.StatusBadRequest, "Missing client_id", "")
		return
	}
	cli, err := h.clientsRepo.GetByClientID(ctx, clientIDStr)
	if err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			h.renderError(w, r, http.StatusBadRequest, "Unknown client", "")
			return
		}
		h.renderError(w, r, http.StatusInternalServerError, "Lookup failed", err.Error())
		return
	}

	// PAR: if request_uri is present, look up the pushed payload and merge
	// it into params, overriding any duplicate top-level values per
	// RFC 9126 §4: parameters in the request_uri take precedence.
	if uri := params.Get("request_uri"); uri != "" {
		clientPK, payload, perr := par.Redeem(ctx, h.q, tid, uri)
		if perr != nil {
			h.renderError(w, r, http.StatusBadRequest, "PAR request invalid", perr.Error())
			return
		}
		if clientPK != cli.ID {
			h.renderError(w, r, http.StatusBadRequest, "PAR request does not match client", "")
			return
		}
		params = mergeValues(params, payload)
		params.Del("request_uri")
	}

	// JAR: if `request` is present (after PAR merge), parse and verify the
	// signed request object and merge its claims as parameters.
	if rawJWT := params.Get("request"); rawJWT != "" {
		if h.jarParser == nil {
			h.renderError(w, r, http.StatusBadRequest, "JAR not enabled", "")
			return
		}
		claims, jerr := h.jarParser.Parse(ctx, rawJWT, cli)
		if jerr != nil {
			h.renderError(w, r, http.StatusBadRequest, "Invalid request object", jerr.Error())
			return
		}
		params = mergeClaims(params, claims)
		params.Del("request")
	}

	redirectURI := params.Get("redirect_uri")
	if !redirectURIAllowed(cli.RedirectURIs, redirectURI) {
		h.renderError(w, r, http.StatusBadRequest, "Invalid redirect_uri", "")
		return
	}
	state := params.Get("state")

	responseType := params.Get("response_type")
	if responseType != "code" {
		h.redirectOAuthError(w, r, redirectURI, state, ErrUnsupportedResp, "only response_type=code is supported")
		return
	}

	scopes := splitScopes(params.Get("scope"))
	if len(scopes) == 0 {
		h.redirectOAuthError(w, r, redirectURI, state, ErrInvalidRequest, "missing scope")
		return
	}

	codeChallenge := params.Get("code_challenge")
	codeChallengeMethod := params.Get("code_challenge_method")
	if codeChallengeMethod == "" {
		codeChallengeMethod = pkce.MethodS256
	}
	if cli.ClientType == clients.TypePublic || codeChallenge != "" {
		// PKCE mandatory for public clients (OAuth 2.1) AND for any client
		// that begins with a code_challenge.
		if codeChallenge == "" {
			h.redirectOAuthError(w, r, redirectURI, state, ErrInvalidRequest, "PKCE required: missing code_challenge")
			return
		}
		if !strings.EqualFold(codeChallengeMethod, pkce.MethodS256) {
			h.redirectOAuthError(w, r, redirectURI, state, ErrInvalidRequest, "PKCE method must be S256")
			return
		}
	}

	prompt := splitPrompt(params.Get("prompt"))
	row, err := h.q.CreateAuthRequest(ctx, db.CreateAuthRequestParams{
		TenantID:            tid,
		ClientID:            cli.ID,
		RedirectUri:         redirectURI,
		ResponseType:        responseType,
		ResponseMode:        textOpt(params.Get("response_mode")),
		Scopes:              scopes,
		State:               textOpt(state),
		Nonce:               textOpt(params.Get("nonce")),
		CodeChallenge:       textOpt(codeChallenge),
		CodeChallengeMethod: textOpt(codeChallengeMethod),
		Prompt:              prompt,
		MaxAge:              parseIntPtr(params.Get("max_age")),
		UiLocales:           textOpt(params.Get("ui_locales")),
		AcrValues:           textOpt(params.Get("acr_values")),
		LoginHint:           textOpt(params.Get("login_hint")),
		ParRequestUri:       textOpt(params.Get("request_uri")),
		RequestObjectJti:    textOpt(""),
		ExpiresAt:           time.Now().Add(h.authReqTTL),
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Persist auth request", err.Error())
		return
	}

	// Branch to login or consent based on existing session and prompt.
	if sid, ok := session.ReadCookie(r); ok && !contains(prompt, "login") {
		sess, sErr := h.sessionStore.Get(ctx, sid)
		if sErr == nil {
			if err := h.q.AttachAuthRequestSession(ctx, db.AttachAuthRequestSessionParams{
				ID:             row.ID,
				TenantID:       tid,
				LoginSessionID: pgtype.UUID{Bytes: sess.ID, Valid: true},
				UserID:         pgtype.UUID{Bytes: sess.UserID, Valid: true},
			}); err != nil {
				h.logger.Warn("attach session", slog.Any("error", err))
			}
			http.Redirect(w, r, "/oauth/consent?ar="+row.ID.String(), http.StatusFound)
			return
		}
	}
	if contains(prompt, "none") {
		h.redirectOAuthError(w, r, redirectURI, state, ErrUnauthorized, "prompt=none requires existing session")
		return
	}
	//nolint:gosec // ar query param is a uuid we just generated, not user-influenced
	http.Redirect(w, r, "/oauth/login?ar="+row.ID.String(), http.StatusFound)
}

// =====================================================================
// /oauth/login
// =====================================================================

type loginPageData struct {
	Title         string
	Tenant        struct{ DisplayName string }
	AuthRequestID string
	CSRFToken     string
	Email         string
	Error         string
	IdPs          []IdPButton
}

// LoginGET renders the email/password form.
func (h *Handler) LoginGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	data := loginPageData{Title: "Sign in", AuthRequestID: arID.String()}
	data.Tenant.DisplayName = "keyforge"
	if h.idpLister != nil {
		if ctx, tid, err := h.tenantContext(r); err == nil {
			if idps, err := h.idpLister.Enabled(ctx, tid); err == nil {
				data.IdPs = idps
			}
		}
	}
	// CSRF: when no session yet, bind the token to a transient secret =
	// the auth_request id (still HMAC-protected, still cookie-bound).
	data.CSRFToken = csrf.Issue(w, arID.String(), "login")
	h.render(w, r, "login.html", data)
}

// LoginPOST validates credentials, creates a session, redirects to consent.
func (h *Handler) LoginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Bad request", "")
		return
	}
	arID, err := uuid.Parse(r.PostFormValue("auth_request_id"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid request", "")
		return
	}
	if err := csrf.Validate(r, arID.String(), "login"); err != nil {
		h.renderError(w, r, http.StatusForbidden, "Session expired", "Please try signing in again.")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	req, err := h.q.GetAuthRequest(ctx, db.GetAuthRequestParams{ID: arID, TenantID: tid})
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Login request expired", "Please start over.")
		return
	}

	email := strings.TrimSpace(r.PostFormValue("email"))
	pwd := r.PostFormValue("password")
	if email == "" || pwd == "" {
		h.renderLoginWithError(w, r, arID, email, "Email and password are required.")
		return
	}
	user, err := h.usersRepo.GetByEmail(ctx, email)
	if err != nil {
		h.renderLoginWithError(w, r, arID, email, "Wrong email or password.")
		return
	}
	cred, err := h.usersRepo.GetCredential(ctx, user.ID)
	if err != nil {
		h.renderLoginWithError(w, r, arID, email, "Wrong email or password.")
		return
	}
	if err := password.Verify(cred.PasswordHash, pwd); err != nil {
		h.renderLoginWithError(w, r, arID, email, "Wrong email or password.")
		return
	}

	sess, err := h.sessionStore.Create(ctx, session.CreateInput{
		UserID:    user.ID,
		IP:        httpx.RealIPFromContext(r.Context()),
		UserAgent: r.UserAgent(),
		MFALevel:  "pwd",
		AMR:       []string{"pwd"},
		TTL:       24 * time.Hour,
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Session error", err.Error())
		return
	}
	session.WriteCookie(w, sess.ID.String(), 24*time.Hour)

	if err := h.q.AttachAuthRequestSession(ctx, db.AttachAuthRequestSessionParams{
		ID:             req.ID,
		TenantID:       tid,
		LoginSessionID: pgtype.UUID{Bytes: sess.ID, Valid: true},
		UserID:         pgtype.UUID{Bytes: user.ID, Valid: true},
	}); err != nil {
		h.logger.Warn("attach session", slog.Any("error", err))
	}
	if dest, err := h.stepUpRequired(ctx, tid, user.ID, req.ID); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "MFA check failed", err.Error())
		return
	} else if dest != "" {
		//nolint:gosec // destination is built from server-controlled paths and a uuid
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/oauth/consent?ar="+req.ID.String(), http.StatusFound)
}

func (h *Handler) renderLoginWithError(w http.ResponseWriter, r *http.Request, arID uuid.UUID, email, msg string) {
	data := loginPageData{
		Title:         "Sign in",
		AuthRequestID: arID.String(),
		Email:         email,
		Error:         msg,
	}
	data.Tenant.DisplayName = "keyforge"
	data.CSRFToken = csrf.Issue(w, arID.String(), "login")
	h.render(w, r, "login.html", data)
}

// =====================================================================
// /oauth/consent
// =====================================================================

type consentScope struct {
	Name        string
	Description string
}

type consentPageData struct {
	Title         string
	Tenant        struct{ DisplayName string }
	AuthRequestID string
	CSRFToken     string
	Client        struct{ Name string }
	User          struct{ Email string }
	Scopes        []consentScope
}

// ConsentGET renders the consent form, or skips it if a prior consent
// covers the requested scopes.
func (h *Handler) ConsentGET(w http.ResponseWriter, r *http.Request) {
	arID, ok := h.lookupAuthRequest(w, r)
	if !ok {
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	req, err := h.q.GetAuthRequest(ctx, db.GetAuthRequestParams{ID: arID, TenantID: tid})
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Authorization expired", "")
		return
	}
	if !req.UserID.Valid {
		//nolint:gosec // ar is a uuid we generated, not user-controlled
		http.Redirect(w, r, "/oauth/login?ar="+arID.String(), http.StatusFound)
		return
	}
	cli, err := h.clientsRepo.GetByID(ctx, req.ClientID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Client lookup failed", err.Error())
		return
	}
	user, err := h.usersRepo.GetByID(ctx, uuidFromPG(req.UserID))
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "User lookup failed", err.Error())
		return
	}

	// Skip consent screen if prior consent covers everything requested.
	hasPrompt := containsString(req.Prompt, "consent")
	if !hasPrompt {
		if cov, _ := h.priorConsentCovers(ctx, tid, user.ID, cli.ID, req.Scopes); cov {
			h.completeConsent(w, r, ctx, tid, req)
			return
		}
	}

	data := consentPageData{
		Title:         "Authorize " + cli.Name,
		AuthRequestID: arID.String(),
	}
	data.Tenant.DisplayName = "keyforge"
	data.Client.Name = cli.Name
	data.User.Email = user.Email
	for _, s := range req.Scopes {
		data.Scopes = append(data.Scopes, consentScope{Name: s, Description: h.scopeCatalog.Describe(s)})
	}
	// bind csrf to the session's csrf secret if we have one; else to the
	// auth_request id (still HMAC-keyed).
	secret := arID.String()
	if sid, ok := session.ReadCookie(r); ok {
		if sess, sErr := h.sessionStore.Get(ctx, sid); sErr == nil {
			secret = sess.CSRFSecret
		}
	}
	data.CSRFToken = csrf.Issue(w, secret, "consent")
	h.render(w, r, "consent.html", data)
}

// ConsentPOST records the decision and redirects to the client's
// redirect_uri with the authorization code (allow) or an error (deny).
func (h *Handler) ConsentPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Bad request", "")
		return
	}
	arID, err := uuid.Parse(r.PostFormValue("auth_request_id"))
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid request", "")
		return
	}
	ctx, tid, err := h.tenantContext(r)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Configuration error", err.Error())
		return
	}
	req, err := h.q.GetAuthRequest(ctx, db.GetAuthRequestParams{ID: arID, TenantID: tid})
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Authorization expired", "")
		return
	}
	// CSRF verification — same secret choice as ConsentGET.
	secret := arID.String()
	if sid, ok := session.ReadCookie(r); ok {
		if sess, sErr := h.sessionStore.Get(ctx, sid); sErr == nil {
			secret = sess.CSRFSecret
		}
	}
	if err := csrf.Validate(r, secret, "consent"); err != nil {
		h.renderError(w, r, http.StatusForbidden, "Session expired", "Please try again.")
		return
	}

	decision := r.PostFormValue("decision")
	if decision != "allow" {
		state := ""
		if req.State.Valid {
			state = req.State.String
		}
		h.redirectOAuthError(w, r, req.RedirectUri, state, ErrAccessDenied, "user denied")
		return
	}

	// Persist consent
	if req.UserID.Valid {
		if err := h.q.UpsertUserConsent(ctx, db.UpsertUserConsentParams{
			TenantID: tid,
			UserID:   uuidFromPG(req.UserID),
			ClientID: req.ClientID,
			Scopes:   req.Scopes,
		}); err != nil {
			h.logger.Warn("persist consent", slog.Any("error", err))
		}
	}

	h.completeConsent(w, r, ctx, tid, req)
}

// =====================================================================
// helpers
// =====================================================================

// completeConsent issues a fresh authorization code, persists its hash on
// the auth_request, and redirects to the client's redirect_uri with
// `code=...&state=...` (or a JARM response JWT if the request asked for one).
func (h *Handler) completeConsent(w http.ResponseWriter, r *http.Request, ctx context.Context, tid uuid.UUID, req *db.AuthRequest) {
	code, err := newCode()
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Code mint failed", err.Error())
		return
	}
	if err := h.q.MarkAuthRequestConsentedAndCode(ctx, db.MarkAuthRequestConsentedAndCodeParams{
		ID:       req.ID,
		TenantID: tid,
		CodeHash: textOpt(hashCode(code)),
	}); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Persist code", err.Error())
		return
	}

	state := ""
	if req.State.Valid {
		state = req.State.String
	}
	mode := ""
	if req.ResponseMode.Valid {
		mode = req.ResponseMode.String
	}
	// JARM path: wrap (code, state) in a signed JWT.
	if jarm.IsJARM(mode) && h.jarmResponder != nil {
		cli, cerr := h.clientsRepo.GetByID(ctx, req.ClientID)
		if cerr != nil {
			h.renderError(w, r, http.StatusInternalServerError, "Client lookup failed", cerr.Error())
			return
		}
		if err := h.jarmResponder.Send(
			ctx, w, r, jarm.ResponseMode(mode),
			tid, req.RedirectUri, cli.ClientID,
			jarm.Payload{Code: code, State: state},
		); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "JARM response failed", err.Error())
		}
		return
	}

	u, perr := url.Parse(req.RedirectUri)
	if perr != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid redirect", perr.Error())
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	//nolint:gosec // redirect URI was validated against the client's registered allowlist
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) lookupAuthRequest(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	arStr := r.URL.Query().Get("ar")
	if arStr == "" {
		arStr = r.PostFormValue("auth_request_id")
	}
	id, err := uuid.Parse(arStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "Missing authorization context", "")
		return uuid.Nil, false
	}
	return id, true
}

func (h *Handler) priorConsentCovers(ctx context.Context, tid, userID, clientID uuid.UUID, requested []string) (bool, error) {
	row, err := h.q.GetActiveUserConsent(ctx, db.GetActiveUserConsentParams{
		TenantID: tid, UserID: userID, ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	granted := map[string]struct{}{}
	for _, s := range row.Scopes {
		granted[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := granted[s]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (h *Handler) renderError(w http.ResponseWriter, _ *http.Request, status int, title, detail string) {
	w.WriteHeader(status)
	_ = h.templates.ExecuteTemplate(w, "error.html", map[string]any{
		"Title":   title,
		"Message": title,
		"Detail":  detail,
		"Tenant":  map[string]any{"DisplayName": "keyforge"},
	})
}

func (h *Handler) render(w http.ResponseWriter, _ *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		h.logger.Error("render template", slog.String("name", name), slog.Any("error", err))
	}
}

func (h *Handler) redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, oauthErr error, desc string) {
	if redirectURI == "" {
		h.renderError(w, r, http.StatusBadRequest, oauthErr.Error(), desc)
		return
	}
	u, perr := url.Parse(redirectURI)
	if perr != nil {
		h.renderError(w, r, http.StatusBadRequest, "Invalid redirect_uri", perr.Error())
		return
	}
	q := u.Query()
	q.Set("error", oauthErr.Error())
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func newCode() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func parseIntPtr(s string) pgtype.Int4 {
	if s == "" {
		return pgtype.Int4{}
	}
	var n int32
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: n, Valid: true}
}

func uuidFromPG(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.Nil
	}
	u, _ := uuid.FromBytes(p.Bytes[:])
	return u
}

func splitScopes(s string) []string {
	out := []string{}
	for _, p := range strings.Fields(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitPrompt(s string) []string {
	out := []string{}
	for _, p := range strings.Fields(s) {
		out = append(out, strings.ToLower(p))
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsString(ss []string, want string) bool { return contains(ss, want) }

// redirectURIAllowed performs exact-match validation per OAuth 2.1.
// The RFC 8252 loopback exception (varying port on http://127.0.0.1 /
// http://[::1]) is honored: a registered loopback URI matches incoming
// URIs with the same scheme/path and any port.
func redirectURIAllowed(registered []string, presented string) bool {
	if presented == "" {
		return false
	}
	for _, r := range registered {
		if r == presented {
			return true
		}
		if isLoopback(r) && loopbackMatch(r, presented) {
			return true
		}
	}
	return false
}

// mergeValues merges payload values into base. Per RFC 9126 §4, parameters
// from the request_uri payload take precedence over (overwrite) any
// top-level form parameters.
func mergeValues(base url.Values, payload map[string][]string) url.Values {
	out := url.Values{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range payload {
		out[k] = v
	}
	return out
}

// mergeClaims merges JAR-validated claims into the form values. JAR claims
// take precedence over query/form parameters (RFC 9101 §6.1). Scalar
// claims become single-element string slices; numbers are stringified.
func mergeClaims(base url.Values, claims map[string]any) url.Values {
	out := url.Values{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range claims {
		switch x := v.(type) {
		case string:
			out.Set(k, x)
		case []any:
			ss := make([]string, 0, len(x))
			for _, e := range x {
				ss = append(ss, fmt.Sprintf("%v", e))
			}
			out[k] = ss
		case []string:
			out[k] = x
		case nil:
			// skip
		default:
			out.Set(k, fmt.Sprintf("%v", v))
		}
	}
	return out
}

func isLoopback(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "[::1]" || h == "::1"
}

func loopbackMatch(registered, presented string) bool {
	ru, err1 := url.Parse(registered)
	pu, err2 := url.Parse(presented)
	if err1 != nil || err2 != nil {
		return false
	}
	if ru.Scheme != pu.Scheme || ru.Hostname() != pu.Hostname() || ru.Path != pu.Path {
		return false
	}
	// Any port matches.
	return true
}
