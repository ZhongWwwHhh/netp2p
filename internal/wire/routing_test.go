package wire_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
)

func TestRouteAssignmentPathMetricsRoundTrip(t *testing.T) {
	assignment := model.RouteAssignment{
		ID: "assignment-1", NetworkID: "network-1", SourcePeerID: "peer-a",
		DestinationPeerID: "peer-b", Epoch: 7, UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.UTC),
		Primary: model.PathSpec{
			ID: "path-1", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-1"},
			RTTMilliseconds: 12.5, JitterMilliseconds: 3.25, LossPercent: 0.5,
			BandwidthMbps: 250, Confidence: 0.9, Cost: 42,
		},
		Fallbacks: []model.PathSpec{{
			ID: "path-2", Kind: model.PathKindMultiHop, ManagerHops: []string{"manager-1", "manager-2"},
			RTTMilliseconds: 20, JitterMilliseconds: 6.5, LossPercent: 1,
			BandwidthMbps: 180, Confidence: 0.8,
		}},
		RequiresAdmission: true, MaxHops: 2,
	}
	transition := model.StateTransition{
		Type: bft.TransitionUpdateAssignment, Assignment: &assignment,
	}

	decoded := wire.StateTransitionFromProto(wire.StateTransitionToProto(transition))
	if decoded.Assignment == nil {
		t.Fatal("route assignment transition dropped assignment")
	}
	if !reflect.DeepEqual(*decoded.Assignment, assignment) {
		t.Fatalf("route assignment changed over wire: got %+v want %+v", *decoded.Assignment, assignment)
	}
	if decoded.Assignment.Primary.JitterMilliseconds != assignment.Primary.JitterMilliseconds {
		t.Fatalf("primary jitter = %v, want %v", decoded.Assignment.Primary.JitterMilliseconds, assignment.Primary.JitterMilliseconds)
	}
	if decoded.Assignment.Fallbacks[0].JitterMilliseconds != assignment.Fallbacks[0].JitterMilliseconds {
		t.Fatalf("fallback jitter = %v, want %v", decoded.Assignment.Fallbacks[0].JitterMilliseconds, assignment.Fallbacks[0].JitterMilliseconds)
	}
}
