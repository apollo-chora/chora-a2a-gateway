// bootstrap_closure_test.go — exercises BootstrapClosureSubscriber / loadPIIMap
// (the env-driven entry point wired in cmd/server main.go). It delegates to
// config.LoadFromFile, so the success path needs a real YAML manifest and the
// failure path a missing/broken file.
package events_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
)

const validClosureMapYAML = `
domain: chora_a2a
version: "1.0"
fields_to_tokenize:
  - table: a2a_contracts
    columns:
      - column: partner_id
        strategy: tombstone_string
        value: "Former partner"
retention_days_by_jurisdiction:
  EU: 2557
  default: 2557
on_creator_closure:
  strategy: tokenise_authorship_keep_atom
  show_authorship_as: "Former member"
`

func TestBootstrapClosureSubscriber_ValidManifestBuildsSubscriber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PII_Closure_Map.yaml")
	if err := os.WriteFile(path, []byte(validClosureMapYAML), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	repo := events.NewInMemoryClosureRepo()
	pub := events.NewInMemoryClosurePublisher()
	sub, err := events.BootstrapClosureSubscriber(path, repo, pub, nil)
	if err != nil {
		t.Fatalf("BootstrapClosureSubscriber: %v", err)
	}
	if sub == nil {
		t.Fatal("expected a non-nil subscriber")
	}
}

func TestBootstrapClosureSubscriber_MissingManifestErrors(t *testing.T) {
	repo := events.NewInMemoryClosureRepo()
	pub := events.NewInMemoryClosurePublisher()
	if _, err := events.BootstrapClosureSubscriber(
		filepath.Join(t.TempDir(), "does-not-exist.yaml"), repo, pub, nil); err == nil {
		t.Fatal("expected an error when the PII map path is missing")
	}
}

func TestBootstrapClosureSubscriber_InvalidManifestErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PII_Closure_Map.yaml")
	// No `domain` field → validation must reject it.
	if err := os.WriteFile(path, []byte("fields_to_tokenize: []\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	repo := events.NewInMemoryClosureRepo()
	pub := events.NewInMemoryClosurePublisher()
	sub, err := events.BootstrapClosureSubscriber(path, repo, pub, nil)
	if err == nil {
		t.Fatal("expected a validation error for a manifest without a domain")
	}
	if sub != nil {
		t.Fatalf("error path must not return a subscriber; got %v", sub)
	}
	if !strings.Contains(err.Error(), "domain") {
		t.Errorf("error = %q; want a domain-required error", err)
	}
}
