// Package byoa_test exercises the BYOA encrypted external LLM key vault.
//
// CRITICAL invariants:
//   - Plaintext encrypted at rest via AES-GCM
//   - Same master key returns same plaintext on Decrypt
//   - Wrong master key returns error (ciphertext-tag mismatch)
//   - KeyFingerprint is SHA-256 hex of plaintext (audit anchor; not reversible)
//   - Encrypt requires non-empty TenantID, Provider, APIKeyPlaintext
//   - Encrypt requires a 32-byte master key (raw, hex, or base64)
package byoa_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/byoa"
)

const (
	tenantA = "01970000-0000-7000-7000-000000000001"
	plain   = "sk-test-acme-1234567890"
)

// 32 bytes raw key for AES-256.
var masterKey = strings.Repeat("k", 32)

func TestEncrypt_RequiresFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    byoa.EncryptParams
	}{
		{"missing TenantID", byoa.EncryptParams{Provider: "openai", APIKeyPlaintext: "p", TenantMasterKey: masterKey}},
		{"missing Provider", byoa.EncryptParams{TenantID: tenantA, APIKeyPlaintext: "p", TenantMasterKey: masterKey}},
		{"missing Plaintext", byoa.EncryptParams{TenantID: tenantA, Provider: "openai", TenantMasterKey: masterKey}},
		{"missing MasterKey", byoa.EncryptParams{TenantID: tenantA, Provider: "openai", APIKeyPlaintext: "p"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := byoa.EncryptKey(c.p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestEncryptKey_Roundtrip(t *testing.T) {
	t.Parallel()
	entry, err := byoa.EncryptKey(byoa.EncryptParams{
		TenantID:        tenantA,
		Provider:        "openai",
		APIKeyPlaintext: plain,
		TenantMasterKey: masterKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if entry.TenantID != tenantA || entry.Provider != "openai" {
		t.Errorf("wrong tenant/provider")
	}
	if len(entry.Ciphertext) == 0 {
		t.Error("Ciphertext empty")
	}
	// Fingerprint is SHA-256 hex of plaintext.
	sum := sha256.Sum256([]byte(plain))
	if entry.KeyFingerprint != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint mismatch")
	}
	// Decrypt with same master key returns the plaintext.
	pt, err := byoa.DecryptKey(byoa.DecryptParams{
		Entry:           entry,
		TenantMasterKey: masterKey,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != plain {
		t.Errorf("plaintext mismatch: %q", pt)
	}
}

func TestDecryptKey_WrongMasterKeyFails(t *testing.T) {
	t.Parallel()
	entry, _ := byoa.EncryptKey(byoa.EncryptParams{
		TenantID:        tenantA,
		Provider:        "openai",
		APIKeyPlaintext: plain,
		TenantMasterKey: masterKey,
	})
	wrongKey := strings.Repeat("X", 32)
	if _, err := byoa.DecryptKey(byoa.DecryptParams{
		Entry:           entry,
		TenantMasterKey: wrongKey,
	}); err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestEncryptKey_AcceptsHexAndBase64(t *testing.T) {
	t.Parallel()
	hexKey := hex.EncodeToString([]byte(masterKey))
	if _, err := byoa.EncryptKey(byoa.EncryptParams{
		TenantID: tenantA, Provider: "openai", APIKeyPlaintext: plain,
		TenantMasterKey: hexKey,
	}); err != nil {
		t.Errorf("hex master key rejected: %v", err)
	}
	b64Key := base64.StdEncoding.EncodeToString([]byte(masterKey))
	if _, err := byoa.EncryptKey(byoa.EncryptParams{
		TenantID: tenantA, Provider: "openai", APIKeyPlaintext: plain,
		TenantMasterKey: b64Key,
	}); err != nil {
		t.Errorf("base64 master key rejected: %v", err)
	}
}

func TestEncryptKey_TenantProviderTamperResistance(t *testing.T) {
	t.Parallel()
	// AAD is tenant|provider — swapping either should fail decryption.
	entry, _ := byoa.EncryptKey(byoa.EncryptParams{
		TenantID:        tenantA,
		Provider:        "openai",
		APIKeyPlaintext: plain,
		TenantMasterKey: masterKey,
	})
	// Tamper provider.
	tampered := byoa.EncryptedEntry{
		TenantID:       entry.TenantID,
		Provider:       "anthropic",
		Ciphertext:     entry.Ciphertext,
		KeyFingerprint: entry.KeyFingerprint,
	}
	if _, err := byoa.DecryptKey(byoa.DecryptParams{Entry: tampered, TenantMasterKey: masterKey}); err == nil {
		t.Error("expected provider-tampered ciphertext to fail")
	}
}

func TestDecrypt_RejectsShortCiphertext(t *testing.T) {
	t.Parallel()
	// Build a 5-byte garbage ciphertext.
	entry := byoa.EncryptedEntry{
		TenantID:   "t",
		Provider:   "openai",
		Ciphertext: []byte{1, 2, 3, 4, 5},
	}
	if _, err := byoa.DecryptKey(byoa.DecryptParams{
		Entry: entry, TenantMasterKey: masterKey,
	}); err == nil {
		t.Error("expected error on short ciphertext")
	}
}

func TestDecrypt_RejectsInvalidMasterKey(t *testing.T) {
	t.Parallel()
	if _, err := byoa.DecryptKey(byoa.DecryptParams{
		Entry: byoa.EncryptedEntry{TenantID: "t", Provider: "p", Ciphertext: []byte{1}},
	}); err == nil {
		t.Error("expected error on missing master key")
	}
	if _, err := byoa.DecryptKey(byoa.DecryptParams{
		Entry:           byoa.EncryptedEntry{TenantID: "t", Provider: "p", Ciphertext: []byte{1}},
		TenantMasterKey: "not-a-32-byte-key",
	}); err == nil {
		t.Error("expected error on invalid master key length")
	}
}

func TestEncryptKey_DifferentNoncesEachTime(t *testing.T) {
	t.Parallel()
	a, _ := byoa.EncryptKey(byoa.EncryptParams{
		TenantID: tenantA, Provider: "openai", APIKeyPlaintext: plain,
		TenantMasterKey: masterKey,
	})
	b, _ := byoa.EncryptKey(byoa.EncryptParams{
		TenantID: tenantA, Provider: "openai", APIKeyPlaintext: plain,
		TenantMasterKey: masterKey,
	})
	if string(a.Ciphertext) == string(b.Ciphertext) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext (nonce reuse)")
	}
}
