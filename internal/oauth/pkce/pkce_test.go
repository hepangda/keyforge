package pkce

import (
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := DeriveChallenge(v)
	if err := Validate(MethodS256, challenge, v); err != nil {
		t.Errorf("validate good: %v", err)
	}
}

func TestRejectWrongMethod(t *testing.T) {
	t.Parallel()
	if err := Validate("plain", "x", "y"); !errors.Is(err, ErrUnsupportedMethod) {
		t.Errorf("plain: got %v", err)
	}
}

func TestRejectMismatchedVerifier(t *testing.T) {
	t.Parallel()
	v, _ := GenerateVerifier()
	v2, _ := GenerateVerifier()
	if err := Validate(MethodS256, DeriveChallenge(v), v2); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("wrong verifier: got %v", err)
	}
}

func TestRejectShortVerifier(t *testing.T) {
	t.Parallel()
	if err := Validate(MethodS256, "x", "short"); !errors.Is(err, ErrInvalidVerifier) {
		t.Errorf("short: got %v", err)
	}
}
