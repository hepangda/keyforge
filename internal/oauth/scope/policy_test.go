package scope

import (
	"errors"
	"testing"
)

func TestResolveScopesIntersection(t *testing.T) {
	t.Parallel()
	p := Policy{}

	out, err := p.ResolveScopes([]string{"openid", "email"}, []string{"openid", "profile", "email"})
	if err != nil || len(out) != 2 || out[0] != "openid" || out[1] != "email" {
		t.Errorf("got %v err %v", out, err)
	}
}

func TestResolveScopesRejectsExtra(t *testing.T) {
	t.Parallel()
	p := Policy{}

	_, err := p.ResolveScopes([]string{"openid", "admin"}, []string{"openid", "email"})
	if !errors.Is(err, ErrInvalidScope) {
		t.Errorf("err = %v, want ErrInvalidScope", err)
	}
}

func TestResolveScopesEmptyRequestedFallsBackToAllowed(t *testing.T) {
	t.Parallel()
	p := Policy{}

	out, err := p.ResolveScopes(nil, []string{"openid", "profile"})
	if err != nil || len(out) != 2 {
		t.Errorf("got %v err %v", out, err)
	}
}

func TestResolveScopesEmptyAllowedAcceptsRequested(t *testing.T) {
	t.Parallel()
	p := Policy{}

	out, err := p.ResolveScopes([]string{"any"}, nil)
	if err != nil || len(out) != 1 || out[0] != "any" {
		t.Errorf("got %v err %v", out, err)
	}
}
