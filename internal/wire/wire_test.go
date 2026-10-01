package wire_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

func sampleState() model.NetworkState {
	return model.NetworkState{
		NetworkID:   "net-1",
		OverlayCIDR: "100.64.0.0/24",
		Peers: []model.PeerRecord{{
			PeerID: "peer-a", OverlayIP: "100.64.0.1", Addresses: []string{"/ip4/127.0.0.1/udp/1/quic-v1"},
			Groups: []string{"clients"}, Hostname: "alpha", OS: "linux", ClientVersion: "0.1.0",
			DNSLabel: "alpha", LastLogin: "2026-01-01T00:00:00Z",
		}},
		Users: []model.User{{ID: "user-1", Email: "a@example.com", Role: model.RoleOwner, AutoGroups: []string{"g1"}, LastLogin: "2026-01-01T00:00:00Z"}},
		Groups: []model.Group{{
			ID: "clients", Name: "Clients", UserIDs: []string{"user-1"}, PeerIDs: []string{"peer-a"},
			Managed: true, SSOClaim: "clients", Issued: model.GroupIssuedAPI,
		}},
		Policies: []model.Policy{{
			ID: "allow", SourceGroups: []string{"clients"}, DestinationGroups: []string{"clients"},
			Services: []model.Service{{Protocol: "tcp", StartPort: 1, EndPort: 65535}},
			Effect:   model.EffectAllow, Direction: model.DirectionBidirectional,
			Posture: []string{"edr"}, LinkConstraints: []string{"direct"}, Priority: 3, FlowClass: "latency",
		}},
		Routes: []model.Route{{
			ID: "r1", Destination: "10.0.0.0/24", RoutingGroup: "clients",
			DistributionGroup: []string{"clients"}, Metric: 1, MaxHops: 2, BudgetIDs: []string{"b1"}, FlowClass: "throughput",
		}},
		Budgets: []model.TrafficBudget{{
			ID: "b1", SubjectType: "group", SubjectID: "clients", DailyBytes: 1 << 30, MonthlyBytes: 1 << 34,
			PeakBPS: 1e6, PeakBurstBytes: 1 << 20, ForwardingCostLimit: 4, OnExhausted: "throttle",
			UsedDailyBytes: 10, UsedMonthlyBytes: 20, UpdatedAt: time.Unix(1000, 0).UTC(),
		}},
		SetupKeys: []model.SetupKey{{
			ID: "k1", Name: "default", TokenHash: []byte{1, 2, 3}, TokenPrefix: "abc",
			Type: "reusable", Groups: []string{"clients"}, UsageLimit: 10, UsedCount: 2,
		}},
		Nameservers: []model.Nameserver{{
			ID: "ns1", Name: "primary", Groups: []string{"clients"},
			MatchDomains: []string{"corp.internal"}, Servers: []string{"1.1.1.1:53"}, Primary: true, Enabled: true,
		}},
		Zones: []model.DNSZone{{
			ID: "z1", Domain: "example.test",
			Records: []model.DNSRecord{{Name: "host", Type: "A", Value: "100.64.0.1", TTL: 60}},
			Groups:  []string{"clients"}, Enabled: true,
		}},
		DNSSettings: model.DNSSettings{Disabled: false, Groups: []string{"clients"}},
		Settings: model.NetworkSettings{
			DNSDomain: "netp2p.internal", LoginExpirationDays: 30, JWTGroupsEnabled: true,
			JWTGroupsClaimName: "groups", JWTAllowGroups: []string{"eng"},
			LinkMinBandwidthMbps: 10, ViaManagerLatencyAdvantageMs: 50, ViaManagerLossAdvantagePct: 5,
			LinkProbeIntervalSeconds: 15, LinkProbeTimeoutMs: 2000, ViaManagerEnabled: true,
			DirectPathEnabled: true, MaxManagerHops: 2, ProbeBandwidthBudgetKB: 128,
			QuotaEnforcementEnabled: true, QuotaReportIntervalSeconds: 30, DefaultFlowClass: "latency",
		},
		Assignments: []model.RouteAssignment{{
			ID: "a1", SourcePeerID: "peer-a", DestinationPeerID: "peer-b", Epoch: 2, MaxHops: 2,
			Primary: model.PathSpec{
				ID: "p1", Kind: model.PathKindViaManager, ManagerHops: []string{"m1"},
				RTTMilliseconds: 12, LossPercent: 0.1, BandwidthMbps: 100,
				Confidence: 0.8, Cost: 3,
			},
			Fallbacks: []model.PathSpec{{ID: "p2", Kind: model.PathKindDirect}},
		}},
		NextIPOffset:    3,
		CommitteeConfig: model.CommitteeConfig{Threshold: 3, Size: 4, GroupPublicKey: []byte{9, 9}, CommitteeEpoch: 1},
	}
}

func deterministic(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestNetworkStateRoundTripIsDeterministic(t *testing.T) {
	state := sampleState()
	encoded := deterministic(t, wire.NetworkStateToProto(state))

	var restored pb.NetworkState
	if err := proto.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	roundTripped := wire.NetworkStateFromProto(&restored)
	reEncoded := deterministic(t, wire.NetworkStateToProto(roundTripped))
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatalf("protobuf round trip changed the deterministic encoding")
	}
}

func TestControlMessagesRoundTrip(t *testing.T) {
	login := protocol.LoginRequest{
		NetworkID: "net-1", SetupKey: "k", JWTToken: "jwt", PeerID: "peer-a",
		Addresses: []string{"/ip4/1.2.3.4/udp/1/quic-v1"}, Hostname: "alpha", OS: "linux",
		ClientVersion: "0.1.0", ProtocolVersion: "2.0.0", Capabilities: []string{"protobuf"},
	}
	{
		message := wire.LoginRequestToProto(login)
		var restored pb.LoginRequest
		roundTrip(t, message, &restored)
		if got := wire.LoginRequestFromProto(&restored); got.PeerID != login.PeerID || got.ProtocolVersion != login.ProtocolVersion {
			t.Fatalf("login round trip mismatch: %#v", got)
		}
	}
	{
		sync := protocol.SyncRequest{
			NetworkID: "net-1", PeerID: "peer-a", Height: 5, AssignmentsHeight: 2,
			Admissions: []protocol.AdmissionReport{{
				AssignmentID: "a1", PathID: "p1", OK: true, RTTMs: 12, LossPct: 0.5,
				ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			}},
			ProtocolVersion: "2.0.0",
		}
		message := wire.SyncRequestToProto(sync)
		var restored pb.SyncRequest
		roundTrip(t, message, &restored)
		if got := wire.SyncRequestFromProto(&restored); len(got.Admissions) != 1 || got.Admissions[0].PathID != "p1" {
			t.Fatalf("sync round trip mismatch: %#v", got)
		}
	}
	{
		transition := model.StateTransition{
			Type: "register_peer", SetupKey: "k", RequestID: "req-1",
			Peer:        model.PeerRecord{PeerID: "peer-a", OverlayIP: "100.64.0.1"},
			BudgetUsage: &model.BudgetUsage{BudgetID: "b1", DailyBytes: 5, PeriodDay: "2026-01-01"},
			Actor:       &model.Actor{ID: "user-1", Name: "Ada", Role: model.RoleAdmin},
		}
		message := wire.StateTransitionToProto(transition)
		var restored pb.StateTransition
		roundTrip(t, message, &restored)
		got := wire.StateTransitionFromProto(&restored)
		if got.BudgetUsage == nil || got.BudgetUsage.BudgetID != "b1" {
			t.Fatalf("transition round trip mismatch: %#v", got)
		}
		if got.Actor == nil || got.Actor.ID != "user-1" || got.Actor.Role != model.RoleAdmin || got.Actor.Name != "Ada" {
			t.Fatalf("actor round trip mismatch: %#v", got.Actor)
		}
	}
}

// TestActorAbsentRoundTripsToNil guards the optional field: a transition
// without an actor must not gain an empty one, or every hash would change.
func TestActorAbsentRoundTripsToNil(t *testing.T) {
	message := wire.StateTransitionToProto(model.StateTransition{Type: "genesis"})
	if message.GetActor() != nil {
		t.Fatalf("absent actor should not be set, got %#v", message.GetActor())
	}
	var restored pb.StateTransition
	roundTrip(t, message, &restored)
	if got := wire.StateTransitionFromProto(&restored); got.Actor != nil {
		t.Fatalf("absent actor round-tripped to %#v", got.Actor)
	}
}

func roundTrip(t *testing.T, message proto.Message, restored proto.Message) {
	t.Helper()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(encoded, restored); err != nil {
		t.Fatal(err)
	}
}

// Posture labels must survive the protobuf boundary and keep their order.
func TestPeerRecordPostureRoundTrip(t *testing.T) {
	peer := model.PeerRecord{
		PeerID: "peer-a", OverlayIP: "100.64.0.1",
		Posture: []string{"disk-encrypted", "edr"},
	}
	restored := wire.PeerRecordFromProto(wire.PeerRecordToProto(peer))
	if len(restored.Posture) != 2 || restored.Posture[0] != "disk-encrypted" || restored.Posture[1] != "edr" {
		t.Fatalf("posture = %v, want round-tripped labels", restored.Posture)
	}
}
