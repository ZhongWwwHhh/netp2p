package tracing

import (
	"context"
	"testing"
)

func TestSetupDisabledIsNoop(t *testing.T) {
	shutdown, err := Setup(context.Background(), "", "test-version")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if Enabled() {
		t.Fatal("tracing should stay disabled without an endpoint")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown: %v", err)
	}
}

func TestSetupRejectsInvalidEndpoint(t *testing.T) {
	if _, err := Setup(context.Background(), "://not-a-url", "test-version"); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}
