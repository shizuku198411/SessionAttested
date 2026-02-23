package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	privateKeyPEMType = "PRIVATE KEY" // PKCS8
	publicKeyPEMType  = "PUBLIC KEY"  // PKIX
)

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// SaveEd25519PrivateKey saves an ed25519 private key in PKCS8 PEM format.
// PEM type: "PRIVATE KEY"
func SaveEd25519PrivateKey(path string, k ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return fmt.Errorf("marshal pkcs8 private key: %w", err)
	}
	block := &pem.Block{Type: privateKeyPEMType, Bytes: der}
	// 0600 is recommended for private keys
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// SaveEd25519PublicKey saves an ed25519 public key in PKIX PEM format.
// PEM type: "PUBLIC KEY"
func SaveEd25519PublicKey(path string, k ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return fmt.Errorf("marshal pkix public key: %w", err)
	}
	block := &pem.Block{Type: publicKeyPEMType, Bytes: der}
	// 0644 is fine for public keys
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pem decode failed: %s", path)
	}
	if block.Type != privateKeyPEMType {
		return nil, fmt.Errorf("unexpected pem type: got=%q want=%q", block.Type, privateKeyPEMType)
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 private key: %T", keyAny)
	}
	return priv, nil
}

func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pem decode failed: %s", path)
	}
	if block.Type != publicKeyPEMType {
		return nil, fmt.Errorf("unexpected pem type: got=%q want=%q", block.Type, publicKeyPEMType)
	}

	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix public key: %w", err)
	}
	pub, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 public key: %T", keyAny)
	}
	return pub, nil
}

func PublicFromPrivate(priv ed25519.PrivateKey) ed25519.PublicKey {
	// ed25519.PrivateKey.Public() returns crypto.PublicKey which is ed25519.PublicKey.
	return priv.Public().(ed25519.PublicKey)
}
