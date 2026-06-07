package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestTenantContextRoundTrip(t *testing.T) {
	t.Parallel()
	want := uuid.New()
	ctx := ContextWithTenant(context.Background(), want)

	got, ok := TenantFromContext(ctx)
	if !ok {
		t.Fatal("TenantFromContext returned ok=false after ContextWithTenant")
	}
	if got != want {
		t.Errorf("TenantFromContext = %v, want %v", got, want)
	}

	got2, err := MustTenant(ctx)
	if err != nil {
		t.Fatalf("MustTenant: unexpected error: %v", err)
	}
	if got2 != want {
		t.Errorf("MustTenant = %v, want %v", got2, want)
	}
}

func TestMustTenantWithoutContextReturnsError(t *testing.T) {
	t.Parallel()
	_, err := MustTenant(context.Background())
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("MustTenant on bare ctx: err = %v, want ErrNoTenant", err)
	}
}

func TestTenantContextIsImmutable(t *testing.T) {
	t.Parallel()
	a, b := uuid.New(), uuid.New()
	ctxA := ContextWithTenant(context.Background(), a)
	ctxB := ContextWithTenant(ctxA, b)

	gotA, _ := TenantFromContext(ctxA)
	gotB, _ := TenantFromContext(ctxB)

	if gotA != a {
		t.Errorf("parent ctx tenant = %v, want %v (must not be mutated)", gotA, a)
	}
	if gotB != b {
		t.Errorf("child ctx tenant = %v, want %v", gotB, b)
	}
}
