// Package protomarshal encodes chora-a2a-gateway outbox event payloads to
// canonical binary protobuf wire format so the event bus Schema Registry
// validation (BINARY encoding) passes at publish time.
//
// Why hand-rolled
// ---------------
// Generated Go bindings exist in chora-contracts/gen/go/chora/a2a/v1 for all
// 10 schema-attached events. We use google.golang.org/protobuf/encoding/
// protowire to emit canonical wire bytes for the exact subset of fields each
// Schema Registry schema expects, with zero hard dependency on the generated
// bindings at runtime (they're only used in the round-trip wire_compat_test).
//
// Hand-rolling keeps the encoder pure-protowire — small, easy to audit, and
// detached from the chora-contracts module's regen cycle. The wire-bytes are
// what event bus validates against; the generated Go types are just one of many
// consumers that can decode them.
//
// Field numbers + wire types are pinned to chora-contracts/proto/events-flat/
// a2a/* — those flat protos ARE the Schema Registry schemas. Schemas verified
// via `the chora-contracts events-flat schemas` 2026-05-16; all 10 attached schemas are
// BINARY-encoded.
//
// Invariants per the Schema Registry binary-encoded protos:
//
//   - Field 1 = envelope (length-delimited nested message)
//   - Envelope nested fields 1..15 follow chora.common.v1.EventEnvelope layout
//     (event_id=1 ... schema_version=11, chora_imda_dimension=14, imda_lifecycle_stage=15)
//   - Timestamps are nested messages: int64 seconds (field 1) + int32 nanos
//     (field 2)
//   - Unknown topics fail loud (ErrUnsupportedTopic) so the dispatcher
//     dead-letters rather than retrying forever against a schema mismatch
//
// Per CLAUDE.md §6 — wire format MUST be binary protobuf for event bus-attached
// topics. JSON encoding is rejected at publish time with "Invalid binary
// proto message". chora.a2a.* topics WITHOUT an attached schema (partner.*,
// agid.*, byoa_key.*, dns_txt.*, mcp.*, invocation.rate_limited / scope_denied,
// contract.published / deprecated / invoked / rejected) fall through to a JSON
// path with a one-shot WARN at the outbox publisher — see
// outbox/publisher.encodePayload.
package protomarshal

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Envelope is the producer-side flat shape of chora.common.v1.EventEnvelope
// that the encoder needs. Mirrors the cgcenvelope.Envelope on the event bus
// bridge + the protomarshal.Envelope in chora-consumption. Defined locally
// to keep this package import-cycle-free.
type Envelope struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	OccurredAt     time.Time
	PublishedAt    time.Time
	Traceparent    string
	Tracestate     string
	SourceProject  string
	SourceService  string
	SchemaVersion  int32
}

// ErrUnsupportedTopic is returned by MarshalPayload when the topic has no
// registered binary encoder. The dispatcher's caller (outbox.publisher)
// catches this and falls back to JSON with a one-shot WARN log so the row
// still persists; Schema Registry rejects on publish, and the row
// dead-letters under attempt exhaustion.
var ErrUnsupportedTopic = errors.New("protomarshal: topic has no binary encoder; outbox row will dead-letter at publish")

// IsUnsupportedTopic reports whether err is (or wraps) ErrUnsupportedTopic.
func IsUnsupportedTopic(err error) bool { return errors.Is(err, ErrUnsupportedTopic) }

// MarshalPayload converts a topic + envelope + loose payload map into the
// canonical binary protobuf wire bytes for that topic's Schema Registry
// schema. Returns ErrUnsupportedTopic if no encoder is registered for the
// supplied topic.
//
// Topics with registered encoders (10 BINARY-attached schemas as of 2026-05-16):
//
//   - chora.a2a.invocation.started.v1
//   - chora.a2a.invocation.completed.v1
//   - chora.a2a.invocation.failed.v1
//   - chora.a2a.invocation.guardrail_blocked.v1
//   - chora.a2a.contract.declared.v1
//   - chora.a2a.contract.approved.v1
//   - chora.a2a.contract.revoked.v1
//   - chora.a2a.external_agent.registered.v1
//   - chora.a2a.external_agent.suspended.v1
//   - chora.a2a.external_agent.deregistered.v1
//
// Adding more topics: append a case to the switch + implement
// encode{X}(env, payload) returning the wire bytes.
func MarshalPayload(topic string, env Envelope, payload map[string]any) ([]byte, error) {
	switch topic {
	case "chora.a2a.invocation.started.v1":
		return encodeInvocationStarted(env, payload)
	case "chora.a2a.invocation.completed.v1":
		return encodeInvocationCompleted(env, payload)
	case "chora.a2a.invocation.failed.v1":
		return encodeInvocationFailed(env, payload)
	case "chora.a2a.invocation.guardrail_blocked.v1":
		return encodeInvocationGuardrailBlocked(env, payload)
	case "chora.a2a.contract.declared.v1":
		return encodeContractDeclared(env, payload)
	case "chora.a2a.contract.approved.v1":
		return encodeContractApproved(env, payload)
	case "chora.a2a.contract.revoked.v1":
		return encodeContractRevoked(env, payload)
	case "chora.a2a.external_agent.registered.v1":
		return encodeExternalAgentRegistered(env, payload)
	case "chora.a2a.external_agent.suspended.v1":
		return encodeExternalAgentSuspended(env, payload)
	case "chora.a2a.external_agent.deregistered.v1":
		return encodeExternalAgentDeregistered(env, payload)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTopic, topic)
	}
}

// -----------------------------------------------------------------------------
// InvocationStarted (chora.a2a.invocation.started.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/invocation/started.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string invocation_id
//	3  string contract_id
//	4  string caller_agid
//	5  string called_agid
//	6  string request_payload_hash
//	7  bytes  Timestamp started_at
func encodeInvocationStarted(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "invocation_id", payload),
		stringFieldStep(enc, 3, "contract_id", payload),
		stringFieldStep(enc, 4, "caller_agid", payload, "agid"),
		stringFieldStep(enc, 5, "called_agid", payload),
		stringFieldStep(enc, 6, "request_payload_hash", payload),
		timestampFieldStep(enc, 7, "started_at", payload),
	)
}

// -----------------------------------------------------------------------------
// InvocationCompleted (chora.a2a.invocation.completed.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/invocation/completed.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string invocation_id
//	3  string contract_id
//	4  string caller_agid
//	5  string called_agid
//	6  string request_payload_hash
//	7  string response_payload_hash
//	8  bytes  Timestamp started_at
//	9  bytes  Timestamp completed_at
//	10 varint int64 latency_ms
func encodeInvocationCompleted(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "invocation_id", payload),
		stringFieldStep(enc, 3, "contract_id", payload),
		stringFieldStep(enc, 4, "caller_agid", payload, "agid"),
		stringFieldStep(enc, 5, "called_agid", payload),
		stringFieldStep(enc, 6, "request_payload_hash", payload),
		stringFieldStep(enc, 7, "response_payload_hash", payload),
		timestampFieldStep(enc, 8, "started_at", payload),
		timestampFieldStep(enc, 9, "completed_at", payload),
		int64FieldStep(enc, 10, "latency_ms", payload),
	)
}

// -----------------------------------------------------------------------------
// InvocationFailed (chora.a2a.invocation.failed.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/invocation/failed.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string invocation_id
//	3  string contract_id
//	4  string caller_agid
//	5  string called_agid
//	6  string request_payload_hash
//	7  string error_code
//	8  string error_detail
//	9  bytes  Timestamp started_at
//	10 bytes  Timestamp failed_at
func encodeInvocationFailed(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "invocation_id", payload),
		stringFieldStep(enc, 3, "contract_id", payload),
		stringFieldStep(enc, 4, "caller_agid", payload, "agid"),
		stringFieldStep(enc, 5, "called_agid", payload),
		stringFieldStep(enc, 6, "request_payload_hash", payload),
		stringFieldStep(enc, 7, "error_code", payload),
		stringFieldStep(enc, 8, "error_detail", payload),
		timestampFieldStep(enc, 9, "started_at", payload),
		timestampFieldStep(enc, 10, "failed_at", payload),
	)
}

// -----------------------------------------------------------------------------
// InvocationGuardrailBlocked (chora.a2a.invocation.guardrail_blocked.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/invocation/guardrail_blocked.proto
// -----------------------------------------------------------------------------
//
//	1  bytes   Envelope envelope
//	2  string  invocation_id
//	3  string  contract_id
//	4  string  caller_agid
//	5  string  called_agid
//	6  string  payload_hash
//	7  varint  GuardrailViolationType guardrail_violation_type
//	8  varint  bool inbound
//	9  string  detail
//	10 bytes   Timestamp blocked_at
func encodeInvocationGuardrailBlocked(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "invocation_id", payload),
		stringFieldStep(enc, 3, "contract_id", payload),
		stringFieldStep(enc, 4, "caller_agid", payload, "agid"),
		stringFieldStep(enc, 5, "called_agid", payload),
		stringFieldStep(enc, 6, "payload_hash", payload),
		int32FieldStep(enc, 7, "guardrail_violation_type", payload),
		boolFieldStep(enc, 8, "inbound", payload),
		stringFieldStep(enc, 9, "detail", payload),
		timestampFieldStep(enc, 10, "blocked_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ContractDeclared (chora.a2a.contract.declared.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/contract/declared.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string contract_id
//	3  string capability_name
//	4  string owning_agid
//	5  string counterparty_agid
//	6  string schema_uri
//	7  string repeated scopes
//	8  bytes  Timestamp expires_at
//	9  bytes  Timestamp declared_at
func encodeContractDeclared(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "contract_id", payload),
		stringFieldStep(enc, 3, "capability_name", payload),
		stringFieldStep(enc, 4, "owning_agid", payload),
		stringFieldStep(enc, 5, "counterparty_agid", payload),
		stringFieldStep(enc, 6, "schema_uri", payload),
		repeatedStringFieldStep(enc, 7, "scopes", payload),
		timestampFieldStep(enc, 8, "expires_at", payload),
		timestampFieldStep(enc, 9, "declared_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ContractApproved (chora.a2a.contract.approved.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/contract/approved.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string contract_id
//	3  string capability_name
//	4  string owning_agid
//	5  string counterparty_agid
//	6  string schema_uri
//	7  string repeated scopes
//	8  bytes  Timestamp expires_at
//	9  string approved_by_gcid
//	10 bytes  Timestamp approved_at
func encodeContractApproved(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "contract_id", payload),
		stringFieldStep(enc, 3, "capability_name", payload),
		stringFieldStep(enc, 4, "owning_agid", payload),
		stringFieldStep(enc, 5, "counterparty_agid", payload),
		stringFieldStep(enc, 6, "schema_uri", payload),
		repeatedStringFieldStep(enc, 7, "scopes", payload),
		timestampFieldStep(enc, 8, "expires_at", payload),
		stringFieldStep(enc, 9, "approved_by_gcid", payload),
		timestampFieldStep(enc, 10, "approved_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ContractRevoked (chora.a2a.contract.revoked.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/contract/revoked.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string contract_id
//	3  string capability_name
//	4  string owning_agid
//	5  string counterparty_agid
//	6  string revoked_by
//	7  string reason_code
//	8  string detail
//	9  bytes  Timestamp revoked_at
func encodeContractRevoked(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "contract_id", payload),
		stringFieldStep(enc, 3, "capability_name", payload),
		stringFieldStep(enc, 4, "owning_agid", payload),
		stringFieldStep(enc, 5, "counterparty_agid", payload),
		stringFieldStep(enc, 6, "revoked_by", payload),
		stringFieldStep(enc, 7, "reason_code", payload),
		stringFieldStep(enc, 8, "detail", payload),
		timestampFieldStep(enc, 9, "revoked_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ExternalAgentRegistered (chora.a2a.external_agent.registered.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/external_agent/registered.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string external_agid
//	3  string owner_org_name
//	4  string owner_org_domain
//	5  string public_key
//	6  string public_key_fingerprint
//	7  varint TrustLevel trust_level
//	8  bytes  Timestamp registered_at
func encodeExternalAgentRegistered(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "external_agid", payload),
		stringFieldStep(enc, 3, "owner_org_name", payload),
		stringFieldStep(enc, 4, "owner_org_domain", payload),
		stringFieldStep(enc, 5, "public_key", payload),
		stringFieldStep(enc, 6, "public_key_fingerprint", payload),
		int32FieldStep(enc, 7, "trust_level", payload),
		timestampFieldStep(enc, 8, "registered_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ExternalAgentSuspended (chora.a2a.external_agent.suspended.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/external_agent/suspended.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string external_agid
//	3  string owner_org_name
//	4  string suspended_by_gcid
//	5  string suspension_reason
//	6  string detail
//	7  bytes  Timestamp suspended_at
func encodeExternalAgentSuspended(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "external_agid", payload),
		stringFieldStep(enc, 3, "owner_org_name", payload),
		stringFieldStep(enc, 4, "suspended_by_gcid", payload),
		stringFieldStep(enc, 5, "suspension_reason", payload),
		stringFieldStep(enc, 6, "detail", payload),
		timestampFieldStep(enc, 7, "suspended_at", payload),
	)
}

// -----------------------------------------------------------------------------
// ExternalAgentDeregistered (chora.a2a.external_agent.deregistered.v1)
// Field layout — chora-contracts/proto/events-flat/a2a/external_agent/deregistered.proto
// -----------------------------------------------------------------------------
//
//	1  bytes  Envelope envelope
//	2  string external_agid
//	3  string owner_org_name
//	4  string owner_org_domain
//	5  string deregistered_by_gcid
//	6  string reason_code
//	7  bytes  Timestamp deregistered_at
func encodeExternalAgentDeregistered(env Envelope, payload map[string]any) ([]byte, error) {
	enc := newMessage()
	if err := enc.envelope(env, payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return enc.bytes(), nil
	}
	return enc.run(
		stringFieldStep(enc, 2, "external_agid", payload),
		stringFieldStep(enc, 3, "owner_org_name", payload),
		stringFieldStep(enc, 4, "owner_org_domain", payload),
		stringFieldStep(enc, 5, "deregistered_by_gcid", payload),
		stringFieldStep(enc, 6, "reason_code", payload),
		timestampFieldStep(enc, 7, "deregistered_at", payload),
	)
}

// -----------------------------------------------------------------------------
// Builder + per-slot encoders. Keeps each topic encoder declarative.
// -----------------------------------------------------------------------------

type messageBuilder struct {
	buf []byte
}

func newMessage() *messageBuilder { return &messageBuilder{buf: make([]byte, 0, 256)} }

func (m *messageBuilder) bytes() []byte { return m.buf }

// run executes the encoder steps in order, short-circuits on first error,
// and returns the assembled bytes (or nil + error). Keeping the per-encoder
// bodies declarative — one `step` per schema field — is what gives the
// canonical encoder its coverage profile and makes drift between schema +
// encoder loud.
func (m *messageBuilder) run(steps ...func() error) ([]byte, error) {
	for _, s := range steps {
		if err := s(); err != nil {
			return nil, err
		}
	}
	return m.buf, nil
}

// stringFieldStep — closure factory for the encoder.run pipeline.
func stringFieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any, alts ...string) func() error {
	return func() error { return m.stringField(field, key, payload, alts...) }
}

// repeatedStringFieldStep — closure factory.
func repeatedStringFieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any) func() error {
	return func() error { return m.repeatedStringField(field, key, payload) }
}

// int32FieldStep — closure factory.
func int32FieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any) func() error {
	return func() error { return m.int32Field(field, key, payload) }
}

// int64FieldStep — closure factory.
func int64FieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any) func() error {
	return func() error { return m.int64Field(field, key, payload) }
}

// boolFieldStep — closure factory.
func boolFieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any) func() error {
	return func() error { return m.boolField(field, key, payload) }
}

// timestampFieldStep — closure factory.
func timestampFieldStep(m *messageBuilder, field protowire.Number, key string, payload map[string]any) func() error {
	return func() error { return m.timestampField(field, key, payload) }
}

// envelope emits the field-1 nested EventEnvelope submessage. Returns nil
// error today (envelope is fully internal); accepts payload so optional IMDA
// evidence fields can be projected from the payload into envelope fields
// 14 (chora_imda_dimension) + 15 (imda_lifecycle_stage).
func (m *messageBuilder) envelope(env Envelope, payload map[string]any) error {
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	m.buf = appendLengthDelimited(m.buf, 1, envBz)
	return nil
}

// stringField emits a string field. The variadic alternateKeys lets a slot
// fall back to an alternate payload key (e.g. caller_agid ← payload["agid"]
// when the call site shipped a single AGID).
func (m *messageBuilder) stringField(field protowire.Number, primaryKey string, payload map[string]any, alternateKeys ...string) error {
	keys := append([]string{primaryKey}, alternateKeys...)
	for _, k := range keys {
		raw, present := payload[k]
		if !present {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("field %s: expected string, got %T", k, raw)
		}
		if s == "" {
			return nil
		}
		m.buf = appendString(m.buf, field, s)
		return nil
	}
	return nil
}

// repeatedStringField emits a repeated string field — one wire record per
// element in the slice. Accepts []string and []any-of-string (for JSON-loose
// payloads).
func (m *messageBuilder) repeatedStringField(field protowire.Number, key string, payload map[string]any) error {
	raw, present := payload[key]
	if !present {
		return nil
	}
	items, ok := stringSlice(raw)
	if !ok {
		return fmt.Errorf("field %s: expected []string or []any-of-string, got %T", key, raw)
	}
	for _, s := range items {
		if s == "" {
			continue
		}
		m.buf = appendString(m.buf, field, s)
	}
	return nil
}

// int32Field emits a varint-encoded int32 — used for proto3 int32 + enum
// slots. Skips zero (proto3 default; omitting it makes the on-wire bytes
// stable across producers).
func (m *messageBuilder) int32Field(field protowire.Number, key string, payload map[string]any) error {
	raw, present := payload[key]
	if !present {
		return nil
	}
	v, ok := asInt32(raw)
	if !ok {
		return fmt.Errorf("field %s: expected int32-convertible, got %T", key, raw)
	}
	if v == 0 {
		return nil
	}
	m.buf = appendVarint(m.buf, field, uint64(uint32(v)))
	return nil
}

// int64Field emits a varint-encoded int64 — used for latency_ms in
// InvocationCompleted.
func (m *messageBuilder) int64Field(field protowire.Number, key string, payload map[string]any) error {
	raw, present := payload[key]
	if !present {
		return nil
	}
	v, ok := asInt64(raw)
	if !ok {
		return fmt.Errorf("field %s: expected int64-convertible, got %T", key, raw)
	}
	if v == 0 {
		return nil
	}
	m.buf = appendVarint(m.buf, field, uint64(v))
	return nil
}

// boolField emits a varint-encoded bool. Skips false (proto3 default).
func (m *messageBuilder) boolField(field protowire.Number, key string, payload map[string]any) error {
	raw, present := payload[key]
	if !present {
		return nil
	}
	b, ok := raw.(bool)
	if !ok {
		return fmt.Errorf("field %s: expected bool, got %T", key, raw)
	}
	if !b {
		return nil
	}
	m.buf = appendVarint(m.buf, field, 1)
	return nil
}

// timestampField emits a length-delimited nested google.protobuf.Timestamp.
func (m *messageBuilder) timestampField(field protowire.Number, key string, payload map[string]any) error {
	raw, present := payload[key]
	if !present {
		return nil
	}
	t, ok := asTime(raw)
	if !ok {
		return fmt.Errorf("field %s: expected time.Time, got %T", key, raw)
	}
	m.buf = appendLengthDelimited(m.buf, field, encodeTimestamp(t))
	return nil
}

// -----------------------------------------------------------------------------
// Envelope (nested in every event message; field layout matches
// chora.common.v1.EventEnvelope as flattened by chora-contracts/internal/
// protoflatten and embedded as a NESTED type in every events-flat schema).
// -----------------------------------------------------------------------------
//
//	1  string event_id
//	2  string idempotency_key
//	3  string tenant_id
//	4  string gcid
//	5  bytes  Timestamp occurred_at
//	6  bytes  Timestamp published_at
//	7  string traceparent
//	8  string tracestate
//	9  string source_project
//	10 string source_service
//	11 varint int32 schema_version
//	12 string correlation_id
//	13 string causation_id
//	14 string chora_imda_dimension
//	15 string imda_lifecycle_stage
func encodeEnvelope(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)

	if env.EventID != "" {
		out = appendString(out, 1, env.EventID)
	}
	if env.IdempotencyKey != "" {
		out = appendString(out, 2, env.IdempotencyKey)
	}
	if env.TenantID != "" {
		out = appendString(out, 3, env.TenantID)
	}
	if env.GCID != "" {
		out = appendString(out, 4, env.GCID)
	}
	if !env.OccurredAt.IsZero() {
		out = appendLengthDelimited(out, 5, encodeTimestamp(env.OccurredAt))
	}
	if !env.PublishedAt.IsZero() {
		out = appendLengthDelimited(out, 6, encodeTimestamp(env.PublishedAt))
	}
	if env.Traceparent != "" {
		out = appendString(out, 7, env.Traceparent)
	}
	if env.Tracestate != "" {
		out = appendString(out, 8, env.Tracestate)
	}
	if env.SourceProject != "" {
		out = appendString(out, 9, env.SourceProject)
	}
	if env.SourceService != "" {
		out = appendString(out, 10, env.SourceService)
	}
	if env.SchemaVersion > 0 {
		out = appendVarint(out, 11, uint64(uint32(env.SchemaVersion)))
	}

	// Optional IMDA evidence fields sourced from the payload (ADR-141
	// canonical labels). Producer call sites already canonicalise these to
	// lowercase in outbox.publisher; we accept whatever string they ship.
	if payload != nil {
		if v, ok := payload["chora_imda_dimension"].(string); ok && v != "" {
			out = appendString(out, 14, v)
		}
		if v, ok := payload["imda_lifecycle_stage"].(string); ok && v != "" {
			out = appendString(out, 15, v)
		}
	}

	return out, nil
}

// encodeTimestamp emits the nested google.protobuf.Timestamp wire shape:
//
//	1 varint int64  seconds
//	2 varint int32  nanos
func encodeTimestamp(t time.Time) []byte {
	out := make([]byte, 0, 16)
	t = t.UTC()
	secs := t.Unix()
	nanos := int32(t.Nanosecond())
	if secs != 0 {
		out = appendVarint(out, 1, uint64(secs))
	}
	if nanos != 0 {
		out = appendVarint(out, 2, uint64(uint32(nanos)))
	}
	return out
}

// -----------------------------------------------------------------------------
// Wire-format helpers (thin protowire wrappers; reuse keeps callers tidy).
// -----------------------------------------------------------------------------

func appendString(b []byte, field protowire.Number, v string) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendString(b, v)
	return b
}

func appendVarint(b []byte, field protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, field, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

func appendLengthDelimited(b []byte, field protowire.Number, payload []byte) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendBytes(b, payload)
	return b
}

// -----------------------------------------------------------------------------
// Loose-typed payload coercion (in/out: map[string]any).
// -----------------------------------------------------------------------------

// asInt32 converts the value to int32. Returns false (not 0) if v is nil OR
// is a non-numeric type — caller decides whether to fail or skip.
func asInt32(v any) (int32, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int32(n), true
	case int32:
		return n, true
	case int64:
		return int32(n), true
	case float32:
		return int32(n), true
	case float64:
		return int32(n), true
	case uint:
		return int32(n), true
	case uint32:
		return int32(n), true
	case uint64:
		return int32(n), true
	default:
		return 0, false
	}
}

// asInt64 converts to int64 (used for latency_ms).
func asInt64(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	default:
		return 0, false
	}
}

// asTime coerces a value to time.Time. Accepts time.Time directly + nil.
func asTime(v any) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	default:
		return time.Time{}, false
	}
}

// stringSlice coerces []string or []any-of-string to a string slice.
func stringSlice(v any) ([]string, bool) {
	if v == nil {
		return nil, false
	}
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	default:
		return nil, false
	}
}
