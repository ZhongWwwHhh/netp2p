package chaos

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/netp2p/netp2p/internal/p2p"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	peerA = peer.ID("peerA")
	peerB = peer.ID("peerB")
)

// recordingNext counts deliveries so a test can prove a message was dropped,
// delayed or duplicated without a real libp2p host.
type recordingNext struct {
	calls int
}

func (next *recordingNext) send() p2p.SendFunc {
	return func(context.Context, peer.ID, protocol.ID, proto.Message) error {
		next.calls++
		return nil
	}
}

func TestPartitionDropsUntilHealed(t *testing.T) {
	controller := New()
	next := &recordingNext{}
	hook := p2p.SendHook(controller.Wrap)
	ctx := context.Background()

	if err := hook(ctx, peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 1 {
		t.Fatalf("delivered %d messages before partition, want 1", next.calls)
	}

	controller.Partition("peerA")
	if err := hook(ctx, peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 1 {
		t.Fatalf("partition delivered a message: %d calls, want 1", next.calls)
	}
	// A different peer must be unaffected by the partition.
	if err := hook(ctx, peerB, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 2 {
		t.Fatalf("partition leaked to an unrelated peer: %d calls, want 2", next.calls)
	}

	controller.Heal("peerA")
	if err := hook(ctx, peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 3 {
		t.Fatalf("heal did not restore delivery: %d calls, want 3", next.calls)
	}
	if stats := controller.Stats(); stats.Dropped != 1 {
		t.Fatalf("dropped counter %d, want 1", stats.Dropped)
	}
}

func TestProtocolScopedFaultAndDuplicate(t *testing.T) {
	controller := New()
	controller.SetFaults(Fault{Protocol: "state-update", Duplicate: 2})
	next := &recordingNext{}
	ctx := context.Background()

	if err := controller.Wrap(ctx, peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 3 {
		t.Fatalf("duplicate delivered %d calls, want 3", next.calls)
	}
	if err := controller.Wrap(ctx, peerA, protocol.ID("/netp2p/link/probe/2.0.0"), &emptypb.Empty{}, next.send()); err != nil {
		t.Fatal(err)
	}
	if next.calls != 4 {
		t.Fatalf("protocol filter leaked: %d calls, want 4", next.calls)
	}
	if stats := controller.Stats(); stats.Duplicated != 2 {
		t.Fatalf("duplicated counter %d, want 2", stats.Duplicated)
	}
}

func TestDeterministicLoss(t *testing.T) {
	run := func() uint64 {
		controller := New()
		controller.SetFaults(Fault{Loss: 0.5})
		next := &recordingNext{}
		for index := 0; index < 100; index++ {
			_ = controller.Wrap(context.Background(), peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send())
		}
		return controller.Stats().Dropped
	}
	first := run()
	if first != run() {
		t.Fatal("loss injection is not deterministic for a fixed seed")
	}
	if first == 0 || first == 100 {
		t.Fatalf("loss rate produced %d/100 drops, want a mix", first)
	}
}

func TestDelayHonoursContext(t *testing.T) {
	controller := New()
	controller.SetFaults(Fault{Delay: time.Hour})
	next := &recordingNext{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := controller.Wrap(ctx, peerA, protocol.ID("/netp2p/control/state-update/2.0.0"), &emptypb.Empty{}, next.send()); err == nil {
		t.Fatal("delayed send should return the context error")
	}
	if time.Since(start) > time.Minute {
		t.Fatal("delay ignored the context deadline")
	}
	if next.calls != 0 {
		t.Fatalf("delayed send was delivered %d times, want 0", next.calls)
	}
}
