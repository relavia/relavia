package kernel

import (
	"context"
	"errors"
	"fmt"
)

// Kind classifies adapter errors so the UI can react (and translate)
// without parsing message strings.
type Kind string

const (
	// KindInvalidConfig: the configuration is structurally invalid
	// (missing fields, out-of-range values). User-fixable.
	KindInvalidConfig Kind = "invalid_config"
	// KindUnsupported: the configuration is well-formed but this
	// adapter does not support the protocol/transport/security
	// combination (see Capabilities).
	KindUnsupported Kind = "unsupported"
	// KindPlatformUnavailable: a requested platform capability
	// (TUN device, kill switch, VPN permission, ...) is missing.
	KindPlatformUnavailable Kind = "platform_unavailable"
	// KindHandshakeFailed: a real protocol handshake against a node
	// failed (unreachable, refused, bad credentials, ...).
	KindHandshakeFailed Kind = "handshake_failed"
	// KindNetwork: a local network operation failed (bind, dial of
	// the control plane, DNS bootstrap, ...).
	KindNetwork Kind = "network"
	// KindWrongState: the operation is not allowed in the adapter's
	// current lifecycle state (e.g. Start while already running).
	KindWrongState Kind = "wrong_state"
	// KindTimeout: the operation exceeded its deadline.
	KindTimeout Kind = "timeout"
	// KindCanceled: the operation was canceled via context.
	KindCanceled Kind = "canceled"
	// KindInternal: an unexpected failure inside the kernel.
	// Treat as a bug; details belong in the wrapped error.
	KindInternal Kind = "internal"
)

// Error is the structured error type returned by Adapter methods.
// Callers classify with IsKind / KindOf; Message is for logs and
// diagnostics, NOT for end-user display decisions.
type Error struct {
	Kind    Kind
	Op      string // adapter method or subsystem, e.g. "Start"
	Message string
	Err     error // wrapped cause, may be nil
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("kernel: %s [%s]", e.Op, e.Kind)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// NewError builds an *Error.
func NewError(kind Kind, op, message string, cause error) *Error {
	return &Error{Kind: kind, Op: op, Message: message, Err: cause}
}

// IsKind reports whether err (or anything it wraps) is an *Error of
// the given kind. Bare context errors also match KindCanceled and
// KindTimeout.
func IsKind(err error, kind Kind) bool {
	if err == nil {
		return false
	}
	return KindOf(err) == kind
}

// KindOf returns the classification of err: the Kind of a wrapped
// *Error if present, KindCanceled / KindTimeout for bare context
// errors, and KindInternal for anything else. Returns "" for nil.
func KindOf(err error) Kind {
	if err == nil {
		return ""
	}
	var ke *Error
	if errors.As(err, &ke) {
		return ke.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	if errors.Is(err, context.Canceled) {
		return KindCanceled
	}
	return KindInternal
}
