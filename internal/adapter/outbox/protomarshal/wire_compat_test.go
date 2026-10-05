// wire_compat_test verifies the binary bytes emitted by MarshalPayload parse
// cleanly into the generated proto types from chora-contracts. This is the
// load-bearing assertion — if these tests pass, the event bus Schema Registry
// will accept the bytes.
//
// All 10 BINARY-schema-attached chora.a2a.* topics have generated Go bindings
// in chora-contracts/gen/go/chora/a2a/v1, so we round-trip every encoder
// through proto.Unmarshal.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	a2av1 "github.com/apollo-chora/chora-contracts/gen/go/chora/a2a/v1"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox/protomarshal"
)

func wireEnv() protomarshal.Envelope {
	t0 := time.Date(2026, 5, 16, 9, 30, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-00000000abc1",
		IdempotencyKey: "idemp-wire-a2a-1",
		TenantID:       "tenant-acme",
		GCID:           "gcid-platform",
		OccurredAt:     t0,
		PublishedAt:    t0.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "vendor=value",
		SourceProject:  "chora-local",
		SourceService:  "chora-a2a-gateway",
		SchemaVersion:  1,
	}
}

func TestWireCompat_InvocationStarted_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	payload := map[string]any{
		"invocation_id":        "inv-001",
		"contract_id":          "ctr-001",
		"caller_agid":          "agid-caller",
		"called_agid":          "agid-called",
		"request_payload_hash": "sha256:req",
		"started_at":           env.OccurredAt,
		"chora_imda_dimension": "transparency",
		"imda_lifecycle_stage": "runtime",
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.started.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.InvocationStarted
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if msg.GetEnvelope() == nil {
		t.Fatal("envelope not decoded")
	}
	if got := msg.GetEnvelope().GetEventId(); got != env.EventID {
		t.Fatalf("envelope.event_id: got %q want %q", got, env.EventID)
	}
	if got := msg.GetEnvelope().GetTenantId(); got != env.TenantID {
		t.Fatalf("envelope.tenant_id: got %q want %q", got, env.TenantID)
	}
	if got := msg.GetEnvelope().GetTraceparent(); got != env.Traceparent {
		t.Fatalf("envelope.traceparent: got %q", got)
	}
	if got := msg.GetEnvelope().GetSchemaVersion(); got != env.SchemaVersion {
		t.Fatalf("envelope.schema_version: got %d", got)
	}
	if got := msg.GetEnvelope().GetChoraImdaDimension(); got != "transparency" {
		t.Fatalf("envelope.chora_imda_dimension: got %q", got)
	}
	if got := msg.GetEnvelope().GetImdaLifecycleStage(); got != "runtime" {
		t.Fatalf("envelope.imda_lifecycle_stage: got %q", got)
	}
	if got := msg.GetInvocationId(); got != "inv-001" {
		t.Fatalf("invocation_id: got %q", got)
	}
	if got := msg.GetContractId(); got != "ctr-001" {
		t.Fatalf("contract_id: got %q", got)
	}
	if got := msg.GetCallerAgid(); got != "agid-caller" {
		t.Fatalf("caller_agid: got %q", got)
	}
	if got := msg.GetCalledAgid(); got != "agid-called" {
		t.Fatalf("called_agid: got %q", got)
	}
	if got := msg.GetRequestPayloadHash(); got != "sha256:req" {
		t.Fatalf("request_payload_hash: got %q", got)
	}
	if got := msg.GetStartedAt(); got == nil || got.AsTime().Unix() != env.OccurredAt.Unix() {
		t.Fatalf("started_at not round-tripped: %+v", got)
	}
}

func TestWireCompat_InvocationCompleted_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	completedAt := env.OccurredAt.Add(50 * time.Millisecond)
	payload := map[string]any{
		"invocation_id":         "inv-003",
		"contract_id":           "ctr-002",
		"caller_agid":           "agid-caller",
		"called_agid":           "agid-called",
		"request_payload_hash":  "sha256:req",
		"response_payload_hash": "sha256:resp",
		"started_at":            env.OccurredAt,
		"completed_at":          completedAt,
		"latency_ms":            int64(50),
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.InvocationCompleted
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetInvocationId(); got != "inv-003" {
		t.Fatalf("invocation_id: got %q", got)
	}
	if got := msg.GetResponsePayloadHash(); got != "sha256:resp" {
		t.Fatalf("response_payload_hash: got %q", got)
	}
	if got := msg.GetLatencyMs(); got != 50 {
		t.Fatalf("latency_ms: got %d", got)
	}
	if got := msg.GetCompletedAt(); got == nil || got.AsTime().Unix() != completedAt.Unix() {
		t.Fatalf("completed_at not round-tripped: %+v", got)
	}
}

func TestWireCompat_InvocationFailed_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	failedAt := env.OccurredAt.Add(5 * time.Second)
	payload := map[string]any{
		"invocation_id":        "inv-005",
		"contract_id":          "ctr-003",
		"caller_agid":          "agid-caller",
		"called_agid":          "agid-called",
		"request_payload_hash": "sha256:req",
		"error_code":           "UPSTREAM_TIMEOUT",
		"error_detail":         "deadline exceeded",
		"started_at":           env.OccurredAt,
		"failed_at":            failedAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.failed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.InvocationFailed
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetErrorCode(); got != "UPSTREAM_TIMEOUT" {
		t.Fatalf("error_code: got %q", got)
	}
	if got := msg.GetErrorDetail(); got != "deadline exceeded" {
		t.Fatalf("error_detail: got %q", got)
	}
	if got := msg.GetFailedAt(); got == nil || got.AsTime().Unix() != failedAt.Unix() {
		t.Fatalf("failed_at: %+v", got)
	}
}

func TestWireCompat_InvocationGuardrailBlocked_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	payload := map[string]any{
		"invocation_id":            "inv-006",
		"contract_id":              "ctr-004",
		"caller_agid":              "agid-caller",
		"called_agid":              "agid-called",
		"payload_hash":             "sha256:bad",
		"guardrail_violation_type": 2,
		"inbound":                  true,
		"detail":                   "blocked by Model Armor",
		"blocked_at":               env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.invocation.guardrail_blocked.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.InvocationGuardrailBlocked
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetPayloadHash(); got != "sha256:bad" {
		t.Fatalf("payload_hash: got %q", got)
	}
	if got := msg.GetGuardrailViolationType(); got != a2av1.GuardrailViolationType_GUARDRAIL_VIOLATION_TYPE_MODEL_ARMOR_BLOCK {
		t.Fatalf("guardrail_violation_type: got %v", got)
	}
	if got := msg.GetInbound(); !got {
		t.Fatalf("inbound: got %v", got)
	}
}

func TestWireCompat_ContractDeclared_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	expiresAt := env.OccurredAt.Add(720 * time.Hour)
	payload := map[string]any{
		"contract_id":       "ctr-101",
		"capability_name":   "RECOMMEND_CONTENT",
		"owning_agid":       "agid-chora",
		"counterparty_agid": "agid-partner",
		"schema_uri":        "https://chora.site/.well-known/agent-skill/RECOMMEND_CONTENT.v1.json",
		"scopes":            []string{"consent:topics_only", "data:learner.profile.read"},
		"expires_at":        expiresAt,
		"declared_at":       env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.declared.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.ContractDeclared
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetContractId(); got != "ctr-101" {
		t.Fatalf("contract_id: got %q", got)
	}
	if got := msg.GetCapabilityName(); got != "RECOMMEND_CONTENT" {
		t.Fatalf("capability_name: got %q", got)
	}
	if got := msg.GetSchemaUri(); got != "https://chora.site/.well-known/agent-skill/RECOMMEND_CONTENT.v1.json" {
		t.Fatalf("schema_uri: got %q", got)
	}
	if got := msg.GetScopes(); len(got) != 2 || got[0] != "consent:topics_only" || got[1] != "data:learner.profile.read" {
		t.Fatalf("scopes: got %v", got)
	}
	if got := msg.GetExpiresAt(); got == nil || got.AsTime().Unix() != expiresAt.Unix() {
		t.Fatalf("expires_at: %+v", got)
	}
}

func TestWireCompat_ContractApproved_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	approvedAt := env.OccurredAt
	expiresAt := env.OccurredAt.Add(720 * time.Hour)
	payload := map[string]any{
		"contract_id":       "ctr-102",
		"capability_name":   "STUDY_CONVERSATION",
		"owning_agid":       "agid-chora",
		"counterparty_agid": "agid-partner",
		"schema_uri":        "https://chora.site/.well-known/agent-skill/STUDY_CONVERSATION.v1.json",
		"scopes":            []string{"data:learner.profile.read"},
		"expires_at":        expiresAt,
		"approved_by_gcid":  "gcid-admin",
		"approved_at":       approvedAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.contract.approved.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.ContractApproved
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetApprovedByGcid(); got != "gcid-admin" {
		t.Fatalf("approved_by_gcid: got %q", got)
	}
	if got := msg.GetApprovedAt(); got == nil || got.AsTime().Unix() != approvedAt.Unix() {
		t.Fatalf("approved_at: %+v", got)
	}
}

func TestWireCompat_ContractRevoked_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
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
	var msg a2av1.ContractRevoked
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetRevokedBy(); got != "gcid-admin" {
		t.Fatalf("revoked_by: got %q", got)
	}
	if got := msg.GetReasonCode(); got != "POLICY_VIOLATION" {
		t.Fatalf("reason_code: got %q", got)
	}
}

func TestWireCompat_ExternalAgentRegistered_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
	payload := map[string]any{
		"external_agid":          "agid-partner-1",
		"owner_org_name":         "Acme Corp",
		"owner_org_domain":       "acme.example.com",
		"public_key":             "ssh-ed25519 AAAA...",
		"public_key_fingerprint": "SHA256:abc",
		"trust_level":            3,
		"registered_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.a2a.external_agent.registered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg a2av1.ExternalAgentRegistered
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetExternalAgid(); got != "agid-partner-1" {
		t.Fatalf("external_agid: got %q", got)
	}
	if got := msg.GetOwnerOrgDomain(); got != "acme.example.com" {
		t.Fatalf("owner_org_domain: got %q", got)
	}
	if got := msg.GetTrustLevel(); got != a2av1.TrustLevel_TRUST_LEVEL_VERIFIED {
		t.Fatalf("trust_level: got %v", got)
	}
}

func TestWireCompat_ExternalAgentSuspended_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
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
	var msg a2av1.ExternalAgentSuspended
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetSuspensionReason(); got != "GUARDRAIL_REPEAT" {
		t.Fatalf("suspension_reason: got %q", got)
	}
	if got := msg.GetDetail(); got != "3 strikes in 24h" {
		t.Fatalf("detail: got %q", got)
	}
}

func TestWireCompat_ExternalAgentDeregistered_DecodesIntoGeneratedType(t *testing.T) {
	env := wireEnv()
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
	var msg a2av1.ExternalAgentDeregistered
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetDeregisteredByGcid(); got != "gcid-admin" {
		t.Fatalf("deregistered_by_gcid: got %q", got)
	}
	if got := msg.GetReasonCode(); got != "PARTNER_REQUESTED" {
		t.Fatalf("reason_code: got %q", got)
	}
}
