package forward

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/quota"
)

func scaleTestState() model.NetworkState {
	return model.NetworkState{
		NetworkID: "scale-test",
		Peers: []model.PeerRecord{
			{PeerID: sourceID, OverlayIP: "100.64.0.1", Groups: []string{"sources"}},
			{PeerID: destinationID, OverlayIP: "100.64.0.2", Groups: []string{"destinations"}},
		},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{sourceID}},
			{ID: "destinations", PeerIDs: []string{destinationID}},
		},
		Policies: []model.Policy{{
			ID: "allow-icmp", SourceGroups: []string{"sources"}, DestinationGroups: []string{"destinations"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
		}},
		PathFamilies: []model.PathFamily{{
			ID: "family-via-manager-b", Kind: model.PathKindViaManager,
			ManagerHops:  []string{firstHopID, secondHopID},
			SourceGroups: []string{"sources"}, DestinationScopes: []string{"group:destinations"},
			FlowClasses: []string{string(path.FlowLatency)},
		}},
		RoutingDomains: []model.RoutingDomainAuthorization{{
			ID: "domain-a",
			Key: model.RoutingDomainKey{
				SourceManagerID: "manager-b", SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations",
				FlowClass:        string(path.FlowLatency),
			},
			PathFamilyIDs: []string{"family-via-manager-b"}, PolicyIDs: []string{"allow-icmp"},
		}},
	}
}

func scaleTestPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 0x5150, 1, []byte("scale"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func scaleTCPPayload(source, destination string, port uint16) []byte {
	raw := make([]byte, 40)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = 6
	copy(raw[12:16], net.ParseIP(source).To4())
	copy(raw[16:20], net.ParseIP(destination).To4())
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], port)
	return raw
}

func TestScaleEnvelopeRoundTrip(t *testing.T) {
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowRealtime),
			FlowHash: 0x1122334455667788, Sequence: 42, TTL: DefaultTTL,
		},
		Payload: []byte("overlay payload"),
	}
	encoded, err := EncodeScaleEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeScaleEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header != envelope.Header || !bytes.Equal(decoded.Payload, envelope.Payload) {
		t.Fatalf("round trip changed envelope: got %+v want %+v", decoded, envelope)
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := DecodeScaleEnvelope(encoded); err != nil {
		t.Fatal("decode should still parse a modified payload")
	}
	encoded[0] = 0xff
	if _, err := DecodeScaleEnvelope(encoded); err != ErrMalformedScaleEnvelope {
		t.Fatalf("magic error = %v, want %v", err, ErrMalformedScaleEnvelope)
	}
}

func TestAdaptiveFECRecoversOneLostPacket(t *testing.T) {
	payloads := [][]byte{[]byte("aaaa"), []byte("bbbb"), []byte("cccc"), []byte("dddd")}
	policy := AdaptiveFECPolicy(path.FlowRealtime, 2, 5, false)
	if !policy.Enabled || policy.RedundancyForLoss(2) != 1 {
		t.Fatalf("realtime FEC policy = %+v", policy)
	}
	frames, err := BuildFECGroup(7, payloads, policy, 2)
	if err != nil {
		t.Fatal(err)
	}
	received := make([]FECFrame, 0, len(frames))
	for _, frame := range frames {
		if frame.Index != 1 {
			received = append(received, frame)
		}
	}
	recovered, count, err := RecoverFECGroup(received)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !bytes.Equal(recovered[1], payloads[1]) {
		t.Fatalf("recovered=%v count=%d", recovered, count)
	}
}

func TestAcceptScaleAuthorizesAndForwards(t *testing.T) {
	collector := metrics.New()
	table := NewTableWithMetrics(scaleTestState(), firstHopID, nil, collector)
	var sent []ScaleEnvelope
	table.SetScaleRouting(func(source, destination, domain, family, class string) (ScaleAuthorization, error) {
		if source != sourceID || destination != destinationID || domain != "domain-a" || family != "family-via-manager-b" || class != string(path.FlowLatency) {
			t.Fatalf("unexpected authorization input %q %q %q %q %q", source, destination, domain, family, class)
		}
		return ScaleAuthorization{
			FaceID: "manager-b", NextHop: secondHopID, ExpectedPredecessor: sourceID,
		}, nil
	}, func(_ peer.ID, envelope ScaleEnvelope) error {
		sent = append(sent, envelope)
		return nil
	})
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	payload := scaleTestPayload(t)
	flowHash, ok := packet.FlowHash(payload)
	if !ok {
		t.Fatal("test payload is not a valid IP packet")
	}
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency),
			FlowHash: flowHash, Sequence: 1, TTL: DefaultTTL,
		},
		Payload: payload,
	}
	if forwarded, err := table.AcceptScale(source, envelope); forwarded || err != nil {
		t.Fatalf("forwarded=%v err=%v", forwarded, err)
	}
	if len(sent) != 1 || sent[0].Header.TTL != DefaultTTL-1 {
		t.Fatalf("unexpected forwarded envelope %+v", sent)
	}
	if forwarded, dropped := table.Stats(); forwarded != 1 || dropped != 0 {
		t.Fatalf("stats forwarded=%d dropped=%d", forwarded, dropped)
	}
	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	expected := `netp2p_forward_scale_path_selections_total{kind="via_manager",manager_hops="2",path_family="family-via-manager-b"} 1`
	if !strings.Contains(recorder.Body.String(), expected) {
		t.Fatalf("scale path selection metric missing from exposition:\n%s", recorder.Body.String())
	}
}

func TestAcceptScaleReturnsEstablishedFlowWithoutReversePolicy(t *testing.T) {
	state := scaleTestState()
	firstTable := NewTable(state, firstHopID, nil)
	secondTable := NewTable(state, secondHopID, nil)
	firstTable.SetFaceID("manager-b")
	secondTable.SetFaceID("manager-b")
	faceBudgets, err := quota.NewFaceBudgetSet([]quota.FaceConfig{{
		FaceID: "manager-b", CapacityBytesPerSecond: 1_000_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	firstTable.SetFaceBudgets(faceBudgets)
	secondTable.SetFaceBudgets(faceBudgets)
	type sentScale struct {
		remote   peer.ID
		envelope ScaleEnvelope
	}
	firstSent := make([]sentScale, 0, 2)
	secondSent := make([]sentScale, 0, 2)
	firstTable.SetScaleRouting(func(_, _, _, _, _ string) (ScaleAuthorization, error) {
		return ScaleAuthorization{FaceID: "manager-b", NextHop: secondHopID, ExpectedPredecessor: sourceID}, nil
	}, func(remote peer.ID, envelope ScaleEnvelope) error {
		firstSent = append(firstSent, sentScale{remote: remote, envelope: envelope})
		return nil
	})
	secondTable.SetScaleRouting(func(_, _, _, _, _ string) (ScaleAuthorization, error) {
		return ScaleAuthorization{FaceID: "manager-b", NextHop: destinationID, ExpectedPredecessor: firstHopID}, nil
	}, func(remote peer.ID, envelope ScaleEnvelope) error {
		secondSent = append(secondSent, sentScale{remote: remote, envelope: envelope})
		return nil
	})
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := peer.Decode(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	firstHop, err := peer.Decode(firstHopID)
	if err != nil {
		t.Fatal(err)
	}
	secondHop, err := peer.Decode(secondHopID)
	if err != nil {
		t.Fatal(err)
	}

	forward := scaleEnvelopeForPayload(t, scaleTestPayload(t))
	if _, err := firstTable.AcceptScale(source, forward); err != nil {
		t.Fatalf("forward first hop: %v", err)
	}
	if len(firstSent) != 1 {
		t.Fatalf("forward first hop sent %d envelopes", len(firstSent))
	}
	if _, err := secondTable.AcceptScale(firstHop, firstSent[0].envelope); err != nil {
		t.Fatalf("forward second hop: %v", err)
	}
	if len(secondSent) != 1 || secondSent[0].remote.String() != destinationID {
		t.Fatalf("forward second hop sent %+v", secondSent)
	}

	returnPayload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.2"), net.ParseIP("100.64.0.1"), 0x5150, 1, []byte("return"),
	)
	if err != nil {
		t.Fatal(err)
	}
	returnFlowHash, ok := packet.FlowHash(returnPayload)
	if !ok {
		t.Fatal("return payload is not a valid IP packet")
	}
	returnEnvelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: destinationID, DestinationPeerID: sourceID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "family-via-manager-b:manager-b", FlowClass: string(path.FlowLatency),
			FlowHash: returnFlowHash, Sequence: 2, TTL: DefaultTTL,
		},
		Payload: returnPayload,
	}
	if _, err := secondTable.AcceptScale(destination, returnEnvelope); err != nil {
		t.Fatalf("return from destination: %v", err)
	}
	if len(secondSent) != 2 || secondSent[1].remote.String() != firstHopID {
		t.Fatalf("return sent by second hop: %+v", secondSent)
	}
	if _, err := firstTable.AcceptScale(secondHop, secondSent[1].envelope); err != nil {
		t.Fatalf("return to original source: %v", err)
	}
	if len(firstSent) != 2 || firstSent[1].remote.String() != sourceID {
		t.Fatalf("return delivered by first hop: %+v", firstSent)
	}

	untrackedPayload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.2"), net.ParseIP("100.64.0.1"), 0x6161, 1, []byte("new"),
	)
	if err != nil {
		t.Fatal(err)
	}
	untrackedHash, ok := packet.FlowHash(untrackedPayload)
	if !ok {
		t.Fatal("untracked payload is not a valid IP packet")
	}
	untracked := returnEnvelope
	untracked.Header.FlowHash = untrackedHash
	untracked.Header.Sequence = 3
	untracked.Payload = untrackedPayload
	if _, err := secondTable.AcceptScale(destination, untracked); err == nil {
		t.Fatal("untracked reverse-direction packet must not bypass policy")
	}
}

func TestAcceptScaleEnforcesFaceBudget(t *testing.T) {
	table := NewTable(scaleTestState(), firstHopID, nil)
	budgets, err := quota.NewFaceBudgetSet([]quota.FaceConfig{{FaceID: "manager-b", CapacityBytesPerSecond: 10}})
	if err != nil {
		t.Fatal(err)
	}
	table.SetFaceBudgets(budgets)
	table.SetScaleRouting(func(_, _, _, _, _ string) (ScaleAuthorization, error) {
		return ScaleAuthorization{FaceID: "manager-b", NextHop: secondHopID, ExpectedPredecessor: sourceID}, nil
	}, func(_ peer.ID, _ ScaleEnvelope) error { return nil })
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	payload := scaleTestPayload(t)
	flowHash, ok := packet.FlowHash(payload)
	if !ok {
		t.Fatal("test payload is not a valid IP packet")
	}
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency),
			FlowHash: flowHash, TTL: DefaultTTL,
		},
		Payload: payload,
	}
	if _, err := table.AcceptScale(source, envelope); err != ErrFaceBudgetExceeded {
		t.Fatalf("error = %v, want %v", err, ErrFaceBudgetExceeded)
	}
}

func TestValidateScaleRejectsSpoofedOverlaySource(t *testing.T) {
	table := NewTable(scaleTestState(), firstHopID, nil)
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.3"), net.ParseIP("100.64.0.2"), 0x5150, 1, []byte("spoof"),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := scaleEnvelopeForPayload(t, payload)
	if err := table.ValidateScaleEnvelope(envelope); err != ErrInvalidSource {
		t.Fatalf("spoofed source error = %v, want %v", err, ErrInvalidSource)
	}
}

func TestValidateScaleRejectsUnauthorizedService(t *testing.T) {
	table := NewTable(scaleTestState(), firstHopID, nil)
	payload := scaleTCPPayload("100.64.0.1", "100.64.0.2", 443)
	envelope := scaleEnvelopeForPayload(t, payload)
	if err := table.ValidateScaleEnvelope(envelope); !errors.Is(err, ErrScaleUnauthorized) {
		t.Fatalf("TCP error = %v, want %v", err, ErrScaleUnauthorized)
	}
}

func TestValidateScaleRejectsDestinationOutsideRoute(t *testing.T) {
	state := scaleTestState()
	state.Routes = []model.Route{{
		ID: "route-a", Destination: "192.0.2.0/24", RoutingGroup: "destinations",
	}}
	state.Peers[1].IsExitNode = true
	state.RoutingDomains[0].Key.DestinationScope = model.DestinationScopeRoute + "route-a"
	state.PathFamilies[0].DestinationScopes = []string{"*"}
	table := NewTable(state, firstHopID, nil)

	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("198.51.100.1"), 0x5150, 1, []byte("route"),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := scaleEnvelopeForPayload(t, payload)
	if err := table.ValidateScaleEnvelope(envelope); err != ErrDestinationHeader {
		t.Fatalf("outside-route error = %v, want %v", err, ErrDestinationHeader)
	}
}

func TestAcceptScaleChargesEndpointQuotasOnceForMultiHop(t *testing.T) {
	state := scaleTestState()
	state.Settings.QuotaEnforcementEnabled = true
	payload := scaleTestPayload(t)
	limit := uint64(2*len(payload) - 1)
	state.Budgets = []model.TrafficBudget{
		{ID: "source", SubjectType: "peer", SubjectID: sourceID, DailyBytes: limit, MonthlyBytes: limit, OnExhausted: "block"},
		{ID: "destination", SubjectType: "peer", SubjectID: destinationID, DailyBytes: limit, MonthlyBytes: limit, OnExhausted: "block"},
	}
	table := NewTable(state, firstHopID, nil)
	calls := 0
	var forwarded []ScaleEnvelope
	table.SetScaleRouting(func(_, _, _, _, _ string) (ScaleAuthorization, error) {
		calls++
		if calls == 2 {
			return ScaleAuthorization{Destination: true, ExpectedPredecessor: firstHopID}, nil
		}
		return ScaleAuthorization{FaceID: "manager-b", NextHop: secondHopID, ExpectedPredecessor: sourceID}, nil
	}, func(_ peer.ID, envelope ScaleEnvelope) error {
		forwarded = append(forwarded, envelope)
		return nil
	})
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	firstHop, err := peer.Decode(firstHopID)
	if err != nil {
		t.Fatal(err)
	}

	envelope := scaleEnvelopeForPayload(t, payload)
	if _, err := table.AcceptScale(source, envelope); err != nil {
		t.Fatalf("first hop: %v", err)
	}
	if len(forwarded) != 1 {
		t.Fatalf("first hop forwarded %d envelopes, want 1", len(forwarded))
	}
	if _, err := table.AcceptScale(firstHop, forwarded[0]); err != nil {
		t.Fatalf("second hop must not double-charge endpoint quotas: %v", err)
	}
	if _, err := table.AcceptScale(source, scaleEnvelopeForPayload(t, payload)); err != ErrQuotaExceeded {
		t.Fatalf("third packet error = %v, want %v", err, ErrQuotaExceeded)
	}
}

func TestAcceptScaleFaceBudgetRunsBeforeEndpointQuota(t *testing.T) {
	state := scaleTestState()
	state.Settings.QuotaEnforcementEnabled = true
	payload := scaleTestPayload(t)
	state.Budgets = []model.TrafficBudget{{
		ID: "source", SubjectType: "peer", SubjectID: sourceID,
		DailyBytes: uint64(len(payload)), MonthlyBytes: uint64(len(payload)), OnExhausted: "block",
	}}
	table := NewTable(state, firstHopID, nil)
	table.SetScaleRouting(func(_, _, _, _, _ string) (ScaleAuthorization, error) {
		return ScaleAuthorization{FaceID: "manager-b", NextHop: secondHopID, ExpectedPredecessor: sourceID}, nil
	}, func(_ peer.ID, _ ScaleEnvelope) error { return nil })
	limited, err := quota.NewFaceBudgetSet([]quota.FaceConfig{{FaceID: "manager-b", CapacityBytesPerSecond: 10}})
	if err != nil {
		t.Fatal(err)
	}
	table.SetFaceBudgets(limited)
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	envelope := scaleEnvelopeForPayload(t, payload)
	if _, err := table.AcceptScale(source, envelope); err != ErrFaceBudgetExceeded {
		t.Fatalf("face budget error = %v, want %v", err, ErrFaceBudgetExceeded)
	}
	generous, err := quota.NewFaceBudgetSet([]quota.FaceConfig{{FaceID: "manager-b", CapacityBytesPerSecond: 100000}})
	if err != nil {
		t.Fatal(err)
	}
	table.SetFaceBudgets(generous)
	if _, err := table.AcceptScale(source, envelope); err != nil {
		t.Fatalf("quota was consumed before face budget admission: %v", err)
	}
}

func scaleEnvelopeForPayload(t *testing.T, payload []byte) ScaleEnvelope {
	t.Helper()
	flowHash, ok := packet.FlowHash(payload)
	if !ok {
		t.Fatal("payload is not a valid IP packet")
	}
	return ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency),
			FlowHash: flowHash, Sequence: 1, TTL: DefaultTTL,
		},
		Payload: payload,
	}
}

func BenchmarkScaleEnvelopeCodec(b *testing.B) {
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency), TTL: DefaultTTL,
		},
		Payload: make([]byte, 1200),
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		encoded, err := EncodeScaleEnvelope(envelope)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeScaleEnvelope(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
