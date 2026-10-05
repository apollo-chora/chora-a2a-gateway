// Package byoa implements the Bring-Your-Own-Agent (BYOA) external LLM key
// vault primitive per ADR-132 §10 and CLAUDE.md §1 BYOA Sovereignty rules.
//
// Customers may submit their own external LLM provider keys (OpenAI,
// Anthropic, etc.). Keys are encrypted at rest with the tenant's master
// key and decrypted in-memory only at Model Broker call time. The plaintext
// is NEVER logged.
//
// CRITICAL invariants:
//   - Plaintext keys are AES-GCM encrypted with the tenant master key
//   - Master key supplied as 32-byte raw or base64 (production fetches via
//     Cloud KMS CMEK; skeleton accepts inline for tests)
//   - KeyFingerprint is a SHA-256 hex of the plaintext (audit anchor only —
//     not reversible to plaintext, but allows operators to confirm which
//     key is in use without exposing it)
//   - DecryptKey returns the plaintext only when the same master key is
//     supplied; mismatch returns an error
package byoa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// EncryptedEntry is the persisted vault row.
type EncryptedEntry struct {
	TenantID       string
	Provider       string
	Ciphertext     []byte // nonce || ciphertext-with-tag
	KeyFingerprint string // SHA-256 hex of the plaintext
}

// EncryptParams is the input shape for EncryptKey.
type EncryptParams struct {
	TenantID        string
	Provider        string
	APIKeyPlaintext string
	// TenantMasterKey may be the raw 32-byte key (length 32) or a base64
	// string. Empty triggers an error — production must always supply a
	// CMEK-derived key.
	TenantMasterKey string
}

// EncryptKey encrypts the plaintext API key with AES-GCM using the tenant
// master key, returning a vault entry. The plaintext is not retained.
func EncryptKey(p EncryptParams) (EncryptedEntry, error) {
	if strings.TrimSpace(p.TenantID) == "" {
		return EncryptedEntry{}, errors.New("byoa: TenantID required")
	}
	if strings.TrimSpace(p.Provider) == "" {
		return EncryptedEntry{}, errors.New("byoa: Provider required")
	}
	if strings.TrimSpace(p.APIKeyPlaintext) == "" {
		return EncryptedEntry{}, errors.New("byoa: APIKeyPlaintext required")
	}
	key, err := decodeMasterKey(p.TenantMasterKey)
	if err != nil {
		return EncryptedEntry{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedEntry{}, fmt.Errorf("byoa: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedEntry{}, fmt.Errorf("byoa: gcm init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedEntry{}, fmt.Errorf("byoa: nonce read: %w", err)
	}
	plain := []byte(p.APIKeyPlaintext)
	ct := gcm.Seal(nil, nonce, plain, []byte(p.TenantID+"|"+p.Provider))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)

	sum := sha256.Sum256(plain)
	return EncryptedEntry{
		TenantID:       strings.TrimSpace(p.TenantID),
		Provider:       strings.TrimSpace(p.Provider),
		Ciphertext:     out,
		KeyFingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// DecryptParams is the input shape for DecryptKey.
type DecryptParams struct {
	Entry           EncryptedEntry
	TenantMasterKey string
}

// DecryptKey returns the plaintext API key. The plaintext MUST be wiped from
// memory by the caller after use.
func DecryptKey(p DecryptParams) (string, error) {
	key, err := decodeMasterKey(p.TenantMasterKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("byoa: aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("byoa: gcm init: %w", err)
	}
	if len(p.Entry.Ciphertext) < gcm.NonceSize() {
		return "", errors.New("byoa: ciphertext too short")
	}
	nonce := p.Entry.Ciphertext[:gcm.NonceSize()]
	ct := p.Entry.Ciphertext[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, []byte(p.Entry.TenantID+"|"+p.Entry.Provider))
	if err != nil {
		return "", fmt.Errorf("byoa: open (master key mismatch?): %w", err)
	}
	return string(pt), nil
}

// decodeMasterKey accepts a 32-byte raw, hex-encoded, or base64-encoded key.
// Returns the 32-byte key suitable for AES-256-GCM.
func decodeMasterKey(in string) ([]byte, error) {
	if in == "" {
		return nil, errors.New("byoa: TenantMasterKey required (production: fetch via Cloud KMS CMEK)")
	}
	in = strings.TrimSpace(in)
	if len(in) == 32 {
		return []byte(in), nil
	}
	if b, err := base64.StdEncoding.DecodeString(in); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(in); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(in); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("byoa: TenantMasterKey must decode to a 32-byte AES-256 key (raw, hex, or base64)")
}
