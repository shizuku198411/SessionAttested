package model

type SignatureEnvelope struct {
	Alg             string `json:"alg"` // ed25519
	KeyID           string `json:"key_id,omitempty"`
	SignatureBase64 string `json:"signature_base64"`
}
