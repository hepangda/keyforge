package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	const plaintext = "correct horse battery staple"
	hash, err := Hash(plaintext, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash prefix: %q", hash)
	}
	if err := Verify(hash, plaintext); err != nil {
		t.Errorf("verify good password: %v", err)
	}
}

func TestVerifyWrongPasswordFails(t *testing.T) {
	t.Parallel()
	hash, _ := Hash("a", DefaultParams())
	if err := Verify(hash, "b"); !errors.Is(err, ErrMismatched) {
		t.Errorf("wrong password: err = %v, want ErrMismatched", err)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"",
		"$argon2id$",
		"$argon2id$v=19$m=64$saltsalt$tagtag",
		"$argon2id$v=19$m=64,t=2,p=4$$$",
	} {
		if err := Verify(in, "x"); err == nil {
			t.Errorf("expected error for input %q", in)
		}
	}
}

func TestNeedsRehashHonoursTuningBump(t *testing.T) {
	t.Parallel()
	weak := Params{TimeCost: 1, MemoryKiB: 1024, Parallelism: 1, SaltLen: 16, KeyLen: 16}
	hash, _ := Hash("x", weak)
	if !NeedsRehash(hash, DefaultParams()) {
		t.Errorf("expected NeedsRehash=true for downgraded params")
	}
	stronger, _ := Hash("x", DefaultParams())
	if NeedsRehash(stronger, DefaultParams()) {
		t.Errorf("expected NeedsRehash=false for current params")
	}
}
