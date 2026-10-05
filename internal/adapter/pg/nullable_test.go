// nullable_test.go — direct unit tests for the package-private value→nullable
// coercers used by the pg adapter's Put statements. These are pure helpers, so
// an in-package test is the cheapest way to lock the empty/nil mapping contract.
package pg

import (
	"testing"
	"time"
)

func TestNullableString(t *testing.T) {
	if got := nullableString(""); got != nil {
		t.Errorf("nullableString(\"\") = %v; want nil", got)
	}
	if got := nullableString("abc"); got != "abc" {
		t.Errorf("nullableString(\"abc\") = %v; want abc", got)
	}
}

func TestNullableTimePtr(t *testing.T) {
	if got := nullableTimePtr(nil); got != nil {
		t.Errorf("nullableTimePtr(nil) = %v; want nil", got)
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if got := nullableTimePtr(&now); got != now {
		t.Errorf("nullableTimePtr(&now) = %v; want %v", got, now)
	}
}
