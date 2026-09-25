package p2p

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

func TestTwoNodesOpenSecureStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodeA, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()
	nodeB, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	received := make(chan network.Stream, 1)
	nodeA.Handle(FrameProtocol, func(stream network.Stream) {
		received <- stream
	})

	addresses := nodeA.Addresses()
	if len(addresses) == 0 {
		t.Fatal("node A has no addresses")
	}
	var target peer.AddrInfo
	for _, address := range addresses {
		if info, parseErr := peer.AddrInfoFromString(address); parseErr == nil {
			target = *info
			break
		}
	}
	if target.ID == "" {
		t.Fatal("could not parse node A address")
	}
	if err := nodeB.Host.Connect(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Send(ctx, nodeA.Host.ID(), FrameProtocol, &pb.ProbeRequest{Kind: "hello", Nonce: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("handler did not receive stream")
	}
}
