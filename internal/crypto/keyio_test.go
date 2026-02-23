package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519_SignVerify(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello session-attested")
	sig := SignEd25519(priv, msg)

	if !VerifyEd25519(pub, msg, sig) {
		t.Fatalf("verify failed")
	}

	// Tamper
	if VerifyEd25519(pub, []byte("tampered"), sig) {
		t.Fatalf("verify should fail for tampered message")
	}
}

func TestKeyIO_SaveLoad_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "attestation_priv.pem")
	pubPath := filepath.Join(dir, "attestation_pub.pem")

	if err := SaveEd25519PrivateKey(privPath, priv); err != nil {
		t.Fatal(err)
	}
	if err := SaveEd25519PublicKey(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	priv2, err := LoadEd25519PrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := LoadEd25519PublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("roundtrip")
	sig := SignEd25519(priv2, msg)
	if !VerifyEd25519(pub2, msg, sig) {
		t.Fatalf("verify failed after roundtrip")
	}

	// Ensure loaded keys are consistent with original.
	sig2 := SignEd25519(priv, msg)
	if bytes.Equal(sig, sig2) {
		// Ed25519 is deterministic; for the same key+msg, signatures should match.
		// This also indirectly checks the keys are identical.
	} else {
		t.Fatalf("expected deterministic signature match after load")
	}
}

func TestLoadEd25519PrivateKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(p, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519PrivateKey(p); err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadEd25519PublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.pub.pem")
	if err := os.WriteFile(p, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519PublicKey(p); err == nil {
		t.Fatalf("expected error")
	}
}
