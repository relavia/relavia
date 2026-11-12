package kernel_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"openproxy/core/kernel"
)

func TestIsKindThroughWrapping(t *testing.T) {
	base := kernel.NewError(kernel.KindUnsupported, "ValidateConfig", "nope", nil)
	wrapped := fmt.Errorf("ui layer: %w", base)
	if !kernel.IsKind(wrapped, kernel.KindUnsupported) {
		t.Fatal("IsKind should see through wrapping")
	}
	if kernel.IsKind(wrapped, kernel.KindInternal) {
		t.Fatal("IsKind matched the wrong kind")
	}
	if kernel.KindOf(nil) != "" {
		t.Fatal("KindOf(nil) should be empty")
	}
}

func TestKindOfContextErrors(t *testing.T) {
	if got := kernel.KindOf(context.Canceled); got != kernel.KindCanceled {
		t.Fatalf("KindOf(Canceled) = %s, want canceled", got)
	}
	if got := kernel.KindOf(context.DeadlineExceeded); got != kernel.KindTimeout {
		t.Fatalf("KindOf(DeadlineExceeded) = %s, want timeout", got)
	}
	if got := kernel.KindOf(errors.New("mystery")); got != kernel.KindInternal {
		t.Fatalf("KindOf(unknown) = %s, want internal", got)
	}
}
