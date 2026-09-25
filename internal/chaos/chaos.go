// Package chaos injects deterministic faults into the control plane so tests
// can exercise partitions, leader churn, message loss and replay without a
// real flaky network. Faults are matched on the destination peer id and the
// protocol id, so a test can isolate a single manager or a single message type.
package chaos

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/netp2p/netp2p/internal/p2p"
	"google.golang.org/protobuf/proto"
)

// Fault describes a reproducible fault applied to matching outbound sends.
// Match fields are substrings; an empty match field matches anything. A fault
// with Drop discards the message; Loss is a deterministic probability in
// [0,1]; Duplicate re-sends the message N extra times; Delay stalls it.
type Fault struct {
	Peer      string
	Protocol  string
	Drop      bool
	Loss      float64
	Duplicate int
	Delay     time.Duration
}

// Stats counts what the controller did, for assertions and diagnostics.
type Stats struct {
	Delivered  uint64
	Dropped    uint64
	Duplicated uint64
	Delayed    uint64
}

// Controller is a deterministic fault injector. It is safe for concurrent use
// because committee sends fan out from many goroutines.
type Controller struct {
	mu       sync.Mutex
	faults   []Fault
	isolated map[string]bool
	random   *rand.Rand
	stats    Stats
}

// New creates a controller with a fixed seed so probabilistic loss is
// reproducible across runs.
func New() *Controller {
	return &Controller{random: rand.New(rand.NewSource(0x5eed)), isolated: make(map[string]bool)}
}

// Partition drops every message to the peer whose id contains peerID. It is
// how a test simulates a manager going dark while the rest of the committee
// keeps running.
func (controller *Controller) Partition(peerID string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.faults = append(controller.faults, Fault{Peer: peerID, Drop: true})
}

// Heal removes every fault that targets the peer, undoing Partition.
func (controller *Controller) Heal(peerID string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	kept := controller.faults[:0]
	for _, fault := range controller.faults {
		if fault.Peer == peerID && fault.Drop {
			continue
		}
		kept = append(kept, fault)
	}
	controller.faults = kept
}

// Isolate cuts a peer in both directions: it stops receiving (Partition) and
// stops sending. Reconnect undoes it.
func (controller *Controller) Isolate(peerID string) {
	controller.mu.Lock()
	controller.isolated[peerID] = true
	controller.mu.Unlock()
	controller.Partition(peerID)
}

// Reconnect removes the isolation and the inbound partition for a peer.
func (controller *Controller) Reconnect(peerID string) {
	controller.mu.Lock()
	delete(controller.isolated, peerID)
	controller.mu.Unlock()
	controller.Heal(peerID)
}

func (controller *Controller) isIsolated(peerID string) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.isolated[peerID]
}

// HookFor returns a send hook bound to the local peer. Isolating the local peer
// cuts its outbound traffic, which — combined with Partition on the other
// nodes — models a full two-way network split.
func (controller *Controller) HookFor(local peer.ID) p2p.SendHook {
	return func(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message, next p2p.SendFunc) error {
		if controller.isIsolated(local.String()) || controller.isIsolated(string(local)) {
			controller.mu.Lock()
			controller.stats.Dropped++
			controller.mu.Unlock()
			return nil
		}
		return controller.Wrap(ctx, peerID, id, message, next)
	}
}

// SetFaults replaces the active fault set.
func (controller *Controller) SetFaults(faults ...Fault) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.faults = append([]Fault(nil), faults...)
}

// Clear removes every fault.
func (controller *Controller) Clear() {
	controller.SetFaults()
}

// Stats returns a snapshot of the counters.
func (controller *Controller) Stats() Stats {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.stats
}

// decision is the per-message fault to apply, if any.
type decision struct {
	drop      bool
	duplicate int
	delay     time.Duration
}

func (controller *Controller) decide(peerID, protocolID string) decision {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	for _, fault := range controller.faults {
		if !strings.Contains(peerID, fault.Peer) || !strings.Contains(protocolID, fault.Protocol) {
			continue
		}
		result := decision{drop: fault.Drop, duplicate: fault.Duplicate, delay: fault.Delay}
		if fault.Loss > 0 && controller.random.Float64() < fault.Loss {
			result.drop = true
		}
		return result
	}
	return decision{}
}

// Wrap adapts the controller to the node send hook.
func (controller *Controller) Wrap(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message, next p2p.SendFunc) error {
	// Match against both the base58 form (what certified state stores) and the
	// raw string so tests can use readable placeholder ids.
	action := controller.decide(peerID.String(), string(id))
	if action == (decision{}) {
		action = controller.decide(string(peerID), string(id))
	}
	controller.mu.Lock()
	if action.drop {
		controller.stats.Dropped++
	}
	if action.delay > 0 {
		controller.stats.Delayed++
	}
	controller.mu.Unlock()
	if action.drop {
		return nil
	}
	if action.delay > 0 {
		timer := time.NewTimer(action.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	err := next(ctx, peerID, id, message)
	if err != nil {
		return err
	}
	for index := 0; index < action.duplicate; index++ {
		controller.mu.Lock()
		controller.stats.Duplicated++
		controller.mu.Unlock()
		_ = next(ctx, peerID, id, message)
	}
	controller.mu.Lock()
	controller.stats.Delivered++
	controller.mu.Unlock()
	return nil
}
