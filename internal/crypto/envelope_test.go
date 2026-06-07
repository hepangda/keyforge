package crypto

import (
	"bytes"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	kek := make([]byte, kekLen)
	for i := range kek {
		kek[i] = byte(i)
	}
	env, err := NewEnvelope(kek)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("the answer is 42, treat carefully")
	ct, err := env.Wrap(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := env.Unwrap(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

func TestEnvelopeWrongKEKFails(t *testing.T) {
	t.Parallel()
	good := bytes.Repeat([]byte{1}, kekLen)
	bad := bytes.Repeat([]byte{2}, kekLen)
	envA, _ := NewEnvelope(good)
	envB, _ := NewEnvelope(bad)
	ct, _ := envA.Wrap([]byte("hello"))
	if _, err := envB.Unwrap(ct); err == nil {
		t.Fatal("decrypt with wrong KEK should fail")
	}
}

func TestEnvelopeTamperedCiphertextFails(t *testing.T) {
	t.Parallel()
	kek := bytes.Repeat([]byte{1}, kekLen)
	env, _ := NewEnvelope(kek)
	ct, _ := env.Wrap([]byte("hello"))
	ct[len(ct)-1] ^= 0xff
	if _, err := env.Unwrap(ct); err == nil {
		t.Fatal("tampered ciphertext should fail authentication")
	}
}

func TestSealWithDEKRoundTrip(t *testing.T) {
	t.Parallel()
	kek := bytes.Repeat([]byte{0xab}, kekLen)
	env, _ := NewEnvelope(kek)
	plaintext := []byte("BEGIN PRIVATE KEY... very secret material...")
	wrappedDEK, ct, err := env.SealWithDEK(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := env.OpenWithDEK(wrappedDEK, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestParseMasterKeyFormats(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0x7e}, kekLen)
	cases := []struct {
		name  string
		input string
	}{
		{"raw-ascii", string(raw)},
		{"base64-std", "fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4="},
		{"hex-lower", strings.Repeat("7e", kekLen)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseMasterKey(c.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != kekLen {
				t.Fatalf("len = %d, want %d", len(got), kekLen)
			}
		})
	}
}

func TestParseMasterKeyRejectsShort(t *testing.T) {
	t.Parallel()
	if _, err := ParseMasterKey("short"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestGenerateRSAProducesParsableKey(t *testing.T) {
	t.Parallel()
	kp, err := Generate(AlgRS256)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivatePEM(kp.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Fatalf("private key type = %T, want *rsa.PrivateKey", priv)
	}
	if _, err := ParsePublicPEM(kp.PublicPEM); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateEd25519ProducesParsableKey(t *testing.T) {
	t.Parallel()
	kp, err := Generate(AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivatePEM(kp.PrivatePEM); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicPEM(kp.PublicPEM); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateECDSAProducesParsableKey(t *testing.T) {
	t.Parallel()
	kp, err := Generate(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivatePEM(kp.PrivatePEM); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicPEM(kp.PublicPEM); err != nil {
		t.Fatal(err)
	}
}
