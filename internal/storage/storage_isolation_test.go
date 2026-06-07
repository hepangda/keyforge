//go:build integration

package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/hepangda/keyforge/internal/storage/clients"
	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/tenants"
	"github.com/hepangda/keyforge/internal/storage/users"
	"github.com/hepangda/keyforge/internal/testsupport"
)

func TestCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	fx := testsupport.NewPostgres(ctx, t)

	tenantRepo := tenants.New(fx.Pool)
	clientRepo := clients.New(fx.Pool)
	userRepo := users.New(fx.Pool)

	a, err := tenantRepo.Create(ctx, "tenant-a", "Tenant A", "https://a.test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := tenantRepo.Create(ctx, "tenant-b", "Tenant B", "https://b.test")
	if err != nil {
		t.Fatal(err)
	}

	ctxA := postgres.ContextWithTenant(ctx, a.ID)
	ctxB := postgres.ContextWithTenant(ctx, b.ID)

	uA, err := userRepo.Create(ctxA, users.CreateInput{Email: "alice@a.test", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userRepo.Create(ctxB, users.CreateInput{Email: "bob@b.test"}); err != nil {
		t.Fatal(err)
	}

	// Same email may exist in both tenants without colliding.
	if _, err := userRepo.Create(ctxB, users.CreateInput{Email: "alice@a.test"}); err != nil {
		t.Fatalf("duplicate email across tenants should succeed: %v", err)
	}

	// Tenant B must not see Tenant A's user even when asked by id.
	if _, err := userRepo.GetByID(ctxB, uA.ID); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("cross-tenant read should be ErrNotFound, got %v", err)
	}

	// Tenant A should see Tenant A's user by email.
	if _, err := userRepo.GetByEmail(ctxA, "alice@a.test"); err != nil {
		t.Fatalf("same-tenant read should succeed: %v", err)
	}

	// Create a client in each tenant with the SAME client_id (must succeed).
	ca, err := clientRepo.Create(ctxA, clients.CreateInput{
		ClientID: "spa", ClientType: clients.TypePublic, Name: "SPA-A",
		RedirectURIs:            []string{"https://a.test/cb"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientRepo.Create(ctxB, clients.CreateInput{
		ClientID: "spa", ClientType: clients.TypePublic, Name: "SPA-B",
		RedirectURIs:            []string{"https://b.test/cb"},
		TokenEndpointAuthMethod: "none",
	}); err != nil {
		t.Fatalf("duplicate client_id across tenants should succeed: %v", err)
	}

	// Cross-tenant client lookup must miss.
	if _, err := clientRepo.GetByID(ctxB, ca.ID); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("cross-tenant client read should be ErrNotFound, got %v", err)
	}

	// MustTenant guard: calling without tenant in ctx must surface an error,
	// not silently return rows.
	if _, err := userRepo.GetByID(ctx, uA.ID); !errors.Is(err, postgres.ErrNoTenant) {
		t.Fatalf("call without tenant ctx should error, got %v", err)
	}

	// Lists are tenant-scoped.
	usersA, err := userRepo.List(ctxA, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(usersA) != 1 {
		t.Errorf("tenant A user list size = %d, want 1", len(usersA))
	}
	for _, u := range usersA {
		if u.TenantID != a.ID {
			t.Errorf("list returned cross-tenant user: %v in %v", u.TenantID, a.ID)
		}
	}

	// Deleting the bob user in tenant B must not affect alice.
	bob, err := userRepo.GetByEmail(ctxB, "bob@b.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := userRepo.SoftDelete(ctxB, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := userRepo.GetByEmail(ctxB, "bob@b.test"); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("soft-deleted user should be invisible, got %v", err)
	}

	// Quick sanity: tenant ids are distinct.
	if a.ID == uuid.Nil || b.ID == uuid.Nil || a.ID == b.ID {
		t.Errorf("tenant ids unexpected: a=%v b=%v", a.ID, b.ID)
	}
}
