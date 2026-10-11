package forward

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/quota"
)

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
	table := NewTable(model.NetworkState{}, firstHopID, nil)
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
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency),
			FlowHash: 99, Sequence: 1, TTL: DefaultTTL,
		},
		Payload: []byte("payload"),
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
}

func TestAcceptScaleEnforcesFaceBudget(t *testing.T) {
	table := NewTable(model.NetworkState{}, firstHopID, nil)
	budgets, err := quota.NewFaceBudgetSet([]quota.FaceConfig{{FaceID: "manager-b", CapacityBytesPerSecond: 100}})
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
	envelope := ScaleEnvelope{
		Header: ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", PathFamilyID: "family-via-manager-b",
			PathInstanceID: "manager-b", FlowClass: string(path.FlowLatency), TTL: DefaultTTL,
		},
		Payload: make([]byte, 100),
	}
	if _, err := table.AcceptScale(source, envelope); err != ErrFaceBudgetExceeded {
		t.Fatalf("error = %v, want %v", err, ErrFaceBudgetExceeded)
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
