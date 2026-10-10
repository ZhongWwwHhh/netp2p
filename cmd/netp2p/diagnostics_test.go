package main

import (
	"errors"
	"strings"
	"testing"
)

func TestAggregateNetcheckErrorsReportsEveryFailure(t *testing.T) {
	if err := aggregateNetcheckErrors([]error{nil, nil}); err != nil {
		t.Fatalf("successful checks returned %v", err)
	}

	err := aggregateNetcheckErrors([]error{
		errors.New("daemon unavailable"),
		nil,
		errors.New("tun permission denied"),
	})
	if err == nil {
		t.Fatal("expected an aggregate error")
	}
	message := err.Error()
	if !strings.Contains(message, "netcheck failed (2 checks)") ||
		!strings.Contains(message, "daemon unavailable") ||
		!strings.Contains(message, "tun permission denied") {
		t.Fatalf("aggregate error did not include all failures: %v", err)
	}
}
