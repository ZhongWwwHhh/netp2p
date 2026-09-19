package p2p

import (
	"context"
	"testing"
)

func TestSeededIdentityMatchesExpectedPeerID(t *testing.T) {
	node, err := New(context.Background(), Config{IdentitySeed: 101})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if got := node.Host.ID().String(); got != "12D3KooWNC1cKisChtyY5ZbeJBV8Xqqaj1k8gxGJPt2u2JtCAPp4" {
		t.Fatalf("unexpected peer id %s", got)
	}
}
