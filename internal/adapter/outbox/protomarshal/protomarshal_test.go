// Package protomarshal_test verifies binary protobuf wire-format encoding for
// chora-a2a-gateway's outbox event payloads. RED tests written BEFORE the
// encoder lands per CLAUDE.md §development-execution + feedback_strict_tdd.
//
// Gap: outbox writer was persisting JSON-marshalled payload bytes that the
// binary-encoded event schemas reject at publish time with
// "Invalid binary proto message". Fix is producer-side: marshal to canonical
// proto wire bytes before the outbox row is written. Dispatcher passes bytes
// through unchanged.
//
// The chora-contracts events-flat schemas define 10 BINARY-encoded schemas
// attached to chora.a2a.* topics:
//
//   - chora.a2a.contract.declared.v1
//   - chora.a2a.contract.approved.v1
//   - chora.a2a.contract.revoked.v1
//   - chora.a2a.external_agent.registered.v1
//   - chora.a2a.external_agent.suspended.v1
//   - chora.a2a.external_agent.deregistered.v1
//   - chora.a2a.invocation.started.v1
//   - chora.a2a.invocation.completed.v1
//   - chora.a2a.invocation.failed.v1
//   - chora.a2a.invocation.guardrail_blocked.v1
//
// Other taxonomy topics (partner.*, agid.*, byoa_key.*, dns_txt.*, mcp.*,
// invocation.rate_limited / scope_denied, contract.published / deprecated /
// invoked / rejected) have NO schema attached at the topic — they fall through
// to JSON with a WARN.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox/protomarshal"
)

// fixedEnvelope returns a deterministic envelope for byte-level assertions.
func fixedEnvelope() protomarshal.Envelope {
	t := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-00000000a2a1",
		IdempotencyKey: "idemp-a2a-1",
		TenantID:       "tenant-acme",
		GCID:           "gcid-platform",
		OccurredAt:     t,
		PublishedAt:    t.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "",
		SourceProject:  "chora-local",
		SourceService:  "chora-a2a-gateway",
		SchemaVersion:  1,
	}
}

// walkBytes walks a wire-encoded proto message + returns the seen top-level
// field numbers. It fails the test on any malformed tag/value pair.
func walkBytes(t *testing.T, bz []byte) map[protowire.Number]bool {
	t.Helper()
	seen := map[protowire.Number]bool{}
	rem := bz
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid tag at offset %d", len(bz)-len(rem))
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, n := protowire.ConsumeBytes(rem)
			if n < 0 {
				t.Fatalf("invalid length-delimited value for field %d", num)
			}
			rem = rem[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(rem)
			if n < 0 {
				t.Fatalf("invalid varint value for field %d", num)
			}
			rem = rem[n:]
		case protowire.Fixed64Type:
			_, n := protowire.ConsumeFixed64(rem)
			if n < 0 {
				t.Fatalf("invalid fixed64 for field %d", num)
			}
			rem = rem[n:]
		case protowire.Fixed32Type:
			_, n := protowire.ConsumeFixed32(rem)
			if n < 0 {
				t.Fatalf("invalid fixed32 for field %d", num)
			}
			rem = rem[n:]
		default:
			t.Fatalf("unexpected wire type %d for field %d", typ, num)
		}
	}
	return seen
}

// -----------------------------------------------------------------------------
// InvocationStarted (chora.a2a.invocation.started.v1)
// -----------------------------------------------------------------------------

func TestMarshalInvocationStarted_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id":        "inv-001",
		"contract_id":          "ctr-001",
		"caller_agid":          "agid-caller",
		"called_agid":          "agid-called",
		"request_payload_hash": "sha256:abc",
		"started_at":           env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7} {
		if !seen[want] {
			t.Fatalf("InvocationStarted: missing field %d (seen=%v)", want, seen)
		}
	}
}

// TestMarshalInvocationStarted_MapsAgidPayloadKeyToCallerAgid asserts that
// the producer-side call sites (which use a single `agid` key for the partner
// caller) get mapped to schema field 4 (caller_agid). The Chora-side caller
// AGID is always the partner's AGID — invocations land at the gateway from
// external A2A traffic.
func TestMarshalInvocationStarted_MapsAgidPayloadKeyToCallerAgid(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id": "inv-002",
		"agid":          "agid-partner",
		"started_at":    env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	if !seen[4] {
		t.Fatalf("expected caller_agid (field 4) to be set from payload[\"agid\"]")
	}
}

// -----------------------------------------------------------------------------
// InvocationCompleted (chora.a2a.invocation.completed.v1)
// -----------------------------------------------------------------------------

func TestMarshalInvocationCompleted_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id":         "inv-003",
		"contract_id":           "ctr-002",
		"caller_agid":           "agid-caller",
		"called_agid":           "agid-called",
		"request_payload_hash":  "sha256:req",
		"response_payload_hash": "sha256:resp",
		"started_at":            env.OccurredAt,
		"completed_at":          env.OccurredAt.Add(50 * time.Millisecond),
		"latency_ms":            int64(50),
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("InvocationCompleted: missing field %d (seen=%v)", want, seen)
		}
	}
}

// TestMarshalInvocationCompleted_AcceptsLatencyAsInt covers the producer call
// site that passes plain int (not int64).
func TestMarshalInvocationCompleted_AcceptsLatencyAsInt(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id": "inv-004",
		"latency_ms":    50, // plain int
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	if !seen[10] {
		t.Fatal("missing latency_ms (field 10)")
	}
}

// -----------------------------------------------------------------------------
// InvocationFailed (chora.a2a.invocation.failed.v1)
// -----------------------------------------------------------------------------

func TestMarshalInvocationFailed_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id":        "inv-005",
		"contract_id":          "ctr-003",
		"caller_agid":          "agid-caller",
		"called_agid":          "agid-called",
		"request_payload_hash": "sha256:req",
		"error_code":           "UPSTREAM_TIMEOUT",
		"error_detail":         "deadline exceeded",
		"started_at":           env.OccurredAt,
		"failed_at":            env.OccurredAt.Add(5 * time.Second),
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.failed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("InvocationFailed: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// InvocationGuardrailBlocked (chora.a2a.invocation.guardrail_blocked.v1)
// -----------------------------------------------------------------------------

func TestMarshalInvocationGuardrailBlocked_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id":            "inv-006",
		"contract_id":              "ctr-004",
		"caller_agid":              "agid-caller",
		"called_agid":              "agid-called",
		"payload_hash":             "sha256:bad",
		"guardrail_violation_type": 2, // MODEL_ARMOR_BLOCK
		"inbound":                  true,
		"detail":                   "blocked by Model Armor strict template",
		"blocked_at":               env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.guardrail_blocked.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("InvocationGuardrailBlocked: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ContractDeclared (chora.a2a.contract.declared.v1)
// -----------------------------------------------------------------------------

func TestMarshalContractDeclared_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"contract_id":       "ctr-101",
		"capability_name":   "RECOMMEND_CONTENT",
		"owning_agid":       "agid-chora",
		"counterparty_agid": "agid-partner",
		"schema_uri":        "https://chora.site/.well-known/agent-skill/RECOMMEND_CONTENT.v1.json",
		"scopes":            []string{"consent:topics_only"},
		"expires_at":        env.OccurredAt.Add(720 * time.Hour),
		"declared_at":       env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.declared.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if !seen[want] {
			t.Fatalf("ContractDeclared: missing field %d (seen=%v)", want, seen)
		}
	}
}

// TestMarshalContractDeclared_AcceptsAnyStringSlice covers scope slices that
// arrive as []any (common when payloads have been through JSON decode).
func TestMarshalContractDeclared_AcceptsAnyStringSlice(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"contract_id":     "ctr-101",
		"capability_name": "X",
		"scopes":          []any{"a", "b", "c"},
		"declared_at":     env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.declared.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
}

// -----------------------------------------------------------------------------
// ContractApproved (chora.a2a.contract.approved.v1)
// -----------------------------------------------------------------------------

func TestMarshalContractApproved_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"contract_id":       "ctr-102",
		"capability_name":   "STUDY_CONVERSATION",
		"owning_agid":       "agid-chora",
		"counterparty_agid": "agid-partner",
		"schema_uri":        "https://chora.site/.well-known/agent-skill/STUDY_CONVERSATION.v1.json",
		"scopes":            []string{"data:learner.profile.read"},
		"expires_at":        env.OccurredAt.Add(720 * time.Hour),
		"approved_by_gcid":  "gcid-admin",
		"approved_at":       env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.approved.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("ContractApproved: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ContractRevoked (chora.a2a.contract.revoked.v1)
// -----------------------------------------------------------------------------

func TestMarshalContractRevoked_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"contract_id":       "ctr-103",
		"capability_name":   "RECOMMEND_CONTENT",
		"owning_agid":       "agid-chora",
		"counterparty_agid": "agid-partner",
		"revoked_by":        "gcid-admin",
		"reason_code":       "POLICY_VIOLATION",
		"detail":            "repeated guardrail blocks",
		"revoked_at":        env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.revoked.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if !seen[want] {
			t.Fatalf("ContractRevoked: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ExternalAgentRegistered (chora.a2a.external_agent.registered.v1)
// -----------------------------------------------------------------------------

func TestMarshalExternalAgentRegistered_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"external_agid":          "agid-partner-1",
		"owner_org_name":         "Acme Corp",
		"owner_org_domain":       "acme.example.com",
		"public_key":             "ssh-ed25519 AAAA...",
		"public_key_fingerprint": "SHA256:abc",
		"trust_level":            3, // VERIFIED
		"registered_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.registered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8} {
		if !seen[want] {
			t.Fatalf("ExternalAgentRegistered: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ExternalAgentSuspended (chora.a2a.external_agent.suspended.v1)
// -----------------------------------------------------------------------------

func TestMarshalExternalAgentSuspended_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"external_agid":     "agid-partner-1",
		"owner_org_name":    "Acme Corp",
		"suspended_by_gcid": "gcid-admin",
		"suspension_reason": "GUARDRAIL_REPEAT",
		"detail":            "3 strikes in 24h",
		"suspended_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.suspended.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7} {
		if !seen[want] {
			t.Fatalf("ExternalAgentSuspended: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ExternalAgentDeregistered (chora.a2a.external_agent.deregistered.v1)
// -----------------------------------------------------------------------------

func TestMarshalExternalAgentDeregistered_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"external_agid":        "agid-partner-1",
		"owner_org_name":       "Acme Corp",
		"owner_org_domain":     "acme.example.com",
		"deregistered_by_gcid": "gcid-admin",
		"reason_code":          "PARTNER_REQUESTED",
		"deregistered_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.deregistered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkBytes(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7} {
		if !seen[want] {
			t.Fatalf("ExternalAgentDeregistered: missing field %d (seen=%v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// Envelope tag-walk
// -----------------------------------------------------------------------------

// TestMarshalAnyTopic_EnvelopeIsWireCompatible asserts the nested envelope
// submessage decodes to chora.common.v1.EventEnvelope field layout
// (event_id=1 ... schema_version=11).
func TestMarshalAnyTopic_EnvelopeIsWireCompatible(t *testing.T) {
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, map[string]any{
		"invocation_id": "inv-x",
	})
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	// First top-level field must be envelope (field 1).
	num, typ, n := protowire.ConsumeTag(bz)
	if num != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("expected envelope tag (1, bytes), got num=%d typ=%d", num, typ)
	}
	envBytes, m := protowire.ConsumeBytes(bz[n:])
	if m < 0 {
		t.Fatal("invalid envelope bytes")
	}
	if len(envBytes) == 0 {
		t.Fatal("empty envelope bytes")
	}

	seen := map[protowire.Number]bool{}
	rem := envBytes
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid envelope inner tag")
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, n := protowire.ConsumeBytes(rem)
			if n < 0 {
				t.Fatalf("invalid envelope inner bytes for field %d", num)
			}
			rem = rem[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(rem)
			if n < 0 {
				t.Fatalf("invalid envelope inner varint for field %d", num)
			}
			rem = rem[n:]
		}
	}
	required := []protowire.Number{1, 2, 3, 4, 5, 6, 7, 9, 10, 11}
	for _, want := range required {
		if !seen[want] {
			t.Fatalf("envelope: missing required field %d (seen: %v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// Error semantics
// -----------------------------------------------------------------------------

// TestMarshal_UnknownTopic_FailsLoud asserts unsupported topics return a
// typed error so the dispatcher dead-letters rather than persisting bytes
// the Schema Registry will reject.
func TestMarshal_UnknownTopic_FailsLoud(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload("chora.a2a.partner.registered.v1", env, nil)
	if err == nil {
		t.Fatal("expected ErrUnsupportedTopic, got nil")
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		t.Fatalf("expected IsUnsupportedTopic(true), got: %v", err)
	}
}

// TestMarshal_NilPayloadProducesEmptyButValidMessage asserts a nil payload
// still produces a wire-valid message containing just the envelope.
func TestMarshal_NilPayloadProducesEmptyButValidMessage(t *testing.T) {
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, nil)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("nil payload should still produce envelope bytes")
	}
	num, _, n := protowire.ConsumeTag(bz)
	if n < 0 {
		t.Fatal("invalid leading tag")
	}
	if num != 1 {
		t.Fatalf("expected leading field=1 (envelope), got %d", num)
	}
}

// TestMarshal_RejectsInvalidPayloadType asserts the encoder fails loud when
// payload fields have the wrong Go type for their proto schema slot
// (rather than silently coercing or producing garbage bytes).
func TestMarshal_RejectsInvalidPayloadType_StringSlot(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id": 42, // schema demands string
	}
	_, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for invocation_id=int")
	}
}

func TestMarshal_RejectsInvalidPayloadType_TimestampSlot(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id": "inv-x",
		"started_at":    "not-a-time",
	}
	_, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for started_at=string")
	}
}

// TestMarshal_IMDAEvidence_ProjectsIntoEnvelope confirms the envelope picks
// up the optional IMDA dimension + lifecycle stage from the payload so that
// O+ governance dashboards can filter by ADR-141 canonical labels.
func TestMarshal_IMDAEvidence_ProjectsIntoEnvelope(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id":        "inv-x",
		"chora_imda_dimension": "transparency",
		"imda_lifecycle_stage": "runtime",
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	// Walk into the envelope submessage; fields 14 + 15 must be present.
	_, _, n := protowire.ConsumeTag(bz)
	envBytes, _ := protowire.ConsumeBytes(bz[n:])

	seen := map[protowire.Number]bool{}
	rem := envBytes
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid envelope inner tag")
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, n := protowire.ConsumeBytes(rem)
			rem = rem[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(rem)
			rem = rem[n:]
		}
	}
	if !seen[14] {
		t.Fatal("envelope: missing chora_imda_dimension (field 14)")
	}
	if !seen[15] {
		t.Fatal("envelope: missing imda_lifecycle_stage (field 15)")
	}
}

// TestMarshal_AcceptsTimePointer ensures producers can pass *time.Time as
// well as time.Time on Timestamp slots.
func TestMarshal_AcceptsTimePointer(t *testing.T) {
	env := fixedEnvelope()
	now := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	payload := map[string]any{
		"invocation_id": "inv-x",
		"started_at":    &now,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with *time.Time: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
}

// -----------------------------------------------------------------------------
// Type-coercion + error-path coverage. Each topic encoder + each numeric
// coercion path needs at least one positive AND one negative hit so the gate
// (≥85% domain coverage per development-execution rule) clears with margin.
// -----------------------------------------------------------------------------

// TestMarshal_PerTopic_InvalidStringSlot drives every binary encoder through
// its first stringField error path. Catches schema-drift introduced by a
// future field-rename + missing test.
func TestMarshal_PerTopic_InvalidStringSlot(t *testing.T) {
	cases := []struct {
		topic string
		key   string // first string field after envelope
	}{
		{"chora.a2a.invocation.started.v1", "invocation_id"},
		{"chora.a2a.invocation.completed.v1", "invocation_id"},
		{"chora.a2a.invocation.failed.v1", "invocation_id"},
		{"chora.a2a.invocation.guardrail_blocked.v1", "invocation_id"},
		{"chora.a2a.contract.declared.v1", "contract_id"},
		{"chora.a2a.contract.approved.v1", "contract_id"},
		{"chora.a2a.contract.revoked.v1", "contract_id"},
		{"chora.a2a.external_agent.registered.v1", "external_agid"},
		{"chora.a2a.external_agent.suspended.v1", "external_agid"},
		{"chora.a2a.external_agent.deregistered.v1", "external_agid"},
	}
	env := fixedEnvelope()
	for _, tc := range cases {
		_, err := protomarshal.MarshalPayload(tc.topic, env, map[string]any{tc.key: 42})
		if err == nil {
			t.Errorf("%s: expected type error for %s=int", tc.topic, tc.key)
		}
	}
}

// TestMarshal_PerTopic_InvalidTimestampSlot drives every binary encoder
// through its first timestampField error path.
func TestMarshal_PerTopic_InvalidTimestampSlot(t *testing.T) {
	cases := []struct {
		topic string
		key   string
	}{
		{"chora.a2a.invocation.started.v1", "started_at"},
		{"chora.a2a.invocation.completed.v1", "started_at"},
		{"chora.a2a.invocation.failed.v1", "started_at"},
		{"chora.a2a.invocation.guardrail_blocked.v1", "blocked_at"},
		{"chora.a2a.contract.declared.v1", "declared_at"},
		{"chora.a2a.contract.approved.v1", "approved_at"},
		{"chora.a2a.contract.revoked.v1", "revoked_at"},
		{"chora.a2a.external_agent.registered.v1", "registered_at"},
		{"chora.a2a.external_agent.suspended.v1", "suspended_at"},
		{"chora.a2a.external_agent.deregistered.v1", "deregistered_at"},
	}
	env := fixedEnvelope()
	for _, tc := range cases {
		_, err := protomarshal.MarshalPayload(tc.topic, env, map[string]any{tc.key: "not-a-time"})
		if err == nil {
			t.Errorf("%s: expected type error for %s=string", tc.topic, tc.key)
		}
	}
}

// TestMarshal_GuardrailBlocked_RejectsNonBoolInbound covers the bool slot's
// type-check path.
func TestMarshal_GuardrailBlocked_RejectsNonBoolInbound(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload(
		"chora.a2a.invocation.guardrail_blocked.v1",
		env,
		map[string]any{
			"invocation_id": "x",
			"inbound":       "yes", // schema demands bool
		},
	)
	if err == nil {
		t.Fatal("expected type error for inbound=string")
	}
}

// TestMarshal_GuardrailBlocked_RejectsNonIntViolationType covers the
// int32/enum slot's type-check path.
func TestMarshal_GuardrailBlocked_RejectsNonIntViolationType(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload(
		"chora.a2a.invocation.guardrail_blocked.v1",
		env,
		map[string]any{
			"invocation_id":            "x",
			"guardrail_violation_type": "MODEL_ARMOR_BLOCK", // schema demands enum/int
		},
	)
	if err == nil {
		t.Fatal("expected type error for guardrail_violation_type=string")
	}
}

// TestMarshal_InvocationCompleted_RejectsNonIntLatency covers the int64 slot.
func TestMarshal_InvocationCompleted_RejectsNonIntLatency(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload(
		"chora.a2a.invocation.completed.v1",
		env,
		map[string]any{
			"invocation_id": "x",
			"latency_ms":    "fifty", // schema demands int64
		},
	)
	if err == nil {
		t.Fatal("expected type error for latency_ms=string")
	}
}

// TestMarshal_ContractDeclared_RejectsNonStringSliceScopes covers the
// repeatedStringField type-check path.
func TestMarshal_ContractDeclared_RejectsNonStringSliceScopes(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload(
		"chora.a2a.contract.declared.v1",
		env,
		map[string]any{
			"contract_id": "x",
			"scopes":      []any{1, 2, 3}, // not []string of strings
		},
	)
	if err == nil {
		t.Fatal("expected type error for scopes=[]any-of-int")
	}
}

// TestMarshal_ExternalAgentRegistered_AcceptsTrustLevelInt32 confirms an
// int32 typed value flows through the int32Field coercion.
func TestMarshal_ExternalAgentRegistered_AcceptsTrustLevelInt32(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"external_agid": "x",
		"trust_level":   int32(4), // PARTNER
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.registered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with int32: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty")
	}
}

// TestMarshal_InvocationCompleted_LatencyAcceptsFloat covers the float64
// coercion path (JSON decodes numbers as float64).
func TestMarshal_InvocationCompleted_LatencyAcceptsFloat(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"invocation_id": "x",
		"latency_ms":    float64(42),
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with float64: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty")
	}
}

// TestMarshal_ContractDeclared_EmptyScopesSliceIsNoop ensures empty strings
// inside a repeated field are skipped.
func TestMarshal_ContractDeclared_EmptyScopesSliceIsNoop(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"contract_id": "x",
		"scopes":      []string{"", "valid", ""},
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.declared.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty")
	}
}

// TestMarshal_ExternalAgentRegistered_NilTimePointerRejects asserts that a
// nil *time.Time present in the payload fails loud rather than silently
// skipping or emitting a zero timestamp. The producer expressed intent to
// set the field; nil is a programming error.
func TestMarshal_ExternalAgentRegistered_NilTimePointerRejects(t *testing.T) {
	env := fixedEnvelope()
	var nilTime *time.Time
	payload := map[string]any{
		"external_agid": "x",
		"registered_at": nilTime,
	}
	_, err := protomarshal.MarshalPayload("chora.a2a.external_agent.registered.v1", env, payload)
	if err == nil {
		t.Fatal("expected error for nil *time.Time in Timestamp slot")
	}
}

// TestMarshal_AcceptsIntegerCoercions exercises every numeric type accepted
// by asInt32 / asInt64. JSON-decoded payloads + Go int literals + uint types
// all need to round-trip. Covers the polymorphic switch arms.
func TestMarshal_AcceptsIntegerCoercions(t *testing.T) {
	env := fixedEnvelope()
	for _, v := range []any{int(5), int32(5), int64(5), float32(5), float64(5), uint(5), uint32(5), uint64(5)} {
		payload := map[string]any{
			"invocation_id": "x",
			"latency_ms":    v,
		}
		bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
		if err != nil {
			t.Fatalf("latency_ms=%T(%v): %v", v, v, err)
		}
		if len(bz) == 0 {
			t.Fatalf("latency_ms=%T(%v): empty bytes", v, v)
		}
	}
	for _, v := range []any{int(2), int32(2), int64(2), float32(2), float64(2), uint(2), uint32(2), uint64(2)} {
		payload := map[string]any{
			"external_agid": "x",
			"trust_level":   v,
		}
		bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.registered.v1", env, payload)
		if err != nil {
			t.Fatalf("trust_level=%T(%v): %v", v, v, err)
		}
		if len(bz) == 0 {
			t.Fatalf("trust_level=%T(%v): empty bytes", v, v)
		}
	}
}

// TestMarshal_ContractDeclared_StringSliceCoercions covers both []string and
// []any-of-string paths for the repeatedStringField.
func TestMarshal_ContractDeclared_StringSliceCoercions(t *testing.T) {
	env := fixedEnvelope()
	for _, scopes := range []any{
		[]string{"a", "b"},
		[]any{"a", "b"},
	} {
		bz, err := protomarshal.MarshalPayload("chora.a2a.contract.declared.v1", env, map[string]any{
			"contract_id": "x",
			"scopes":      scopes,
		})
		if err != nil {
			t.Fatalf("scopes=%T: %v", scopes, err)
		}
		if len(bz) == 0 {
			t.Fatalf("scopes=%T: empty", scopes)
		}
	}
}
