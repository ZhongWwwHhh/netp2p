package manager

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/protocol"
)

func admissionTestState() model.NetworkState {
	return model.NetworkState{
		NetworkID: "net",
		Peers: []model.PeerRecord{
			{PeerID: "client-a", OverlayIP: "100.64.0.1"},
			{PeerID: "client-b", OverlayIP: "100.64.0.2"},
		},
		Assignments: []model.RouteAssignment{{
			ID: "assignment", NetworkID: "net", SourcePeerID: "client-a", DestinationPeerID: "client-b",
			Primary: model.PathSpec{ID: "direct", Kind: model.PathKindDirect},
			Fallbacks: []model.PathSpec{{
				ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-a"},
			}},
		}},
	}
}

func TestValidAdmissionAcceptsOwnedPath(t *testing.T) {
	state := admissionTestState()
	report := protocol.AdmissionReport{AssignmentID: "assignment", PathID: "direct", OK: true, RTTMs: 5, LossPct: 0, ObservedAt: time.Now().UTC()}
	if !validAdmission(state, "client-a", report) {
		t.Fatal("owned assignment path rejected")
	}
}

func TestValidAdmissionRejectsSpoofedPeerAndMalformedValues(t *testing.T) {
	state := admissionTestState()
	report := protocol.AdmissionReport{AssignmentID: "assignment", PathID: "direct", OK: true, ObservedAt: time.Now().UTC()}
	if validAdmission(state, "client-b", report) {
		t.Fatal("destination peer was allowed to report the source assignment")
	}
	report = protocol.AdmissionReport{AssignmentID: "unknown", PathID: "direct", OK: true, ObservedAt: time.Now().UTC()}
	if validAdmission(state, "client-a", report) {
		t.Fatal("unknown assignment accepted")
	}
	report = protocol.AdmissionReport{AssignmentID: "assignment", PathID: "unknown", OK: true, ObservedAt: time.Now().UTC()}
	if validAdmission(state, "client-a", report) {
		t.Fatal("unknown path accepted")
	}
	report = protocol.AdmissionReport{AssignmentID: "assignment", PathID: "direct", LossPct: 101, ObservedAt: time.Now().UTC()}
	if validAdmission(state, "client-a", report) {
		t.Fatal("invalid loss percentage accepted")
	}
}
