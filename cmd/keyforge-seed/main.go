// Command keyforge-seed populates a freshly migrated keyforge database
// with the minimum set of records needed to develop against the SPA:
//
//   - The bootstrap tenant (already present from migration 0002, looked
//     up by its canonical UUID).
//   - A public PKCE-only OAuth client "keyforge-spa" with localhost +
//     production-style redirect URIs.
//   - A demo admin user with the cross-tenant "admin" role and a random
//     argon2id-hashed password.
//
// Output is a single line of credentials on stdout. The command is
// idempotent: re-running with the same database is a no-op for the
// client; only the user's password is reset.
//
// Not for production use. The plan calls for a richer seed in M22
// (Docker Compose env); this is the slice the SPA needs today.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/auth/password"
	"github.com/hepangda/keyforge/internal/config"
	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// BootstrapTenant matches the UUID seeded by migration 0002. Hard-coded
// because the migration is hard-coded; keeping the constants in sync
// matters here.
var bootstrapTenant = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func main() {
	cfgPath := flag.String("config", "", "path to keyforge config YAML")
	flag.Parse()

	if code := run(*cfgPath); code != 0 {
		os.Exit(code)
	}
}

func run(cfgPath string) int {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("load config", slog.Any("error", err))
		return 1
	}
	pool, err := postgres.NewPool(ctx, cfg.Database)
	if err != nil {
		logger.Error("open pool", slog.Any("error", err))
		return 1
	}
	defer pool.Close()

	ctx = postgres.ContextWithTenant(ctx, bootstrapTenant)
	q := db.New(pool)
	repo := clients.FromQueries(q)

	if _, err := q.GetTenantByID(ctx, bootstrapTenant); err != nil {
		logger.Error("bootstrap tenant missing — run migrations first",
			slog.Any("error", err))
		return 1
	}

	if err := seedSPAClient(ctx, repo); err != nil {
		logger.Error("seed SPA client", slog.Any("error", err))
		return 1
	}

	creds, err := seedAdminUser(ctx, q)
	if err != nil {
		logger.Error("seed admin user", slog.Any("error", err))
		return 1
	}

	fmt.Printf("keyforge-spa registered. Admin: %s / %s\n",
		creds.email, creds.password)
	return 0
}

func seedSPAClient(ctx context.Context, repo *clients.Repository) error {
	if _, err := repo.GetByClientID(ctx, "keyforge-spa"); err == nil {
		return nil
	} else if !errors.Is(err, clients.ErrNotFound) {
		return err
	}
	_, err := repo.Create(ctx, clients.CreateInput{
		ClientID:                "keyforge-spa",
		ClientType:              clients.TypePublic,
		Name:                    "keyforge SPA",
		Description:             "First-party user portal and admin console",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access", "kf:portal", "kf:admin"},
		TokenEndpointAuthMethod: "none",
		RedirectURIs: []string{
			"http://localhost:5173/portal/callback",
			"http://localhost:8080/portal/callback",
			"https://auth.example.com/portal/callback",
		},
	})
	return err
}

type adminCreds struct {
	email    string
	password string
}

func seedAdminUser(ctx context.Context, q *db.Queries) (*adminCreds, error) {
	email := "admin@keyforge.local"
	pwd, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	hash, err := password.Hash(pwd, password.DefaultParams())
	if err != nil {
		return nil, err
	}

	user, err := q.GetUserByEmail(ctx, db.GetUserByEmailParams{
		TenantID: bootstrapTenant, Lower: email,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		user, err = q.CreateUser(ctx, db.CreateUserParams{
			TenantID:      bootstrapTenant,
			Email:         email,
			EmailVerified: true,
			DisplayName:   pgtype.Text{String: "Admin", Valid: true},
		})
		if err != nil {
			return nil, err
		}
	}

	if err := q.UpsertUserCredentials(ctx, db.UpsertUserCredentialsParams{
		UserID:       user.ID,
		TenantID:     bootstrapTenant,
		PasswordHash: hash,
		Algorithm:    "argon2id",
	}); err != nil {
		return nil, err
	}

	adminRole, err := q.GetRoleByName(ctx, "admin")
	if err != nil {
		return nil, err
	}
	if err := q.GrantRole(ctx, db.GrantRoleParams{
		TenantID: bootstrapTenant, UserID: user.ID, RoleID: adminRole.ID,
	}); err != nil {
		return nil, err
	}

	return &adminCreds{email: email, password: pwd}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
