package wire_test

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

func FuzzNetworkStateProto(f *testing.F) {
	valid := wire.NetworkStateToProto(model.NetworkState{
		NetworkID:   "fuzz",
		OverlayCIDR: "100.64.0.0/24",
		Peers: []model.PeerRecord{{
			PeerID: "peer", OverlayIP: "100.64.0.1", Hostname: "host",
			Addresses: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}, Posture: []string{"edr"},
		}},
		Zones: []model.DNSZone{{
			ID: "zone", Domain: "fuzz.invalid", Enabled: true,
			Records: []model.DNSRecord{{Name: "host", Type: "A", Value: "100.64.0.1", TTL: 60}},
		}},
	})
	encoded, err := proto.Marshal(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff})
	f.Add([]byte{0x0a, 0x80, 0x80, 0x80, 0x80, 0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var message pb.NetworkState
		if err := proto.Unmarshal(data, &message); err != nil {
			return
		}
		state := wire.NetworkStateFromProto(&message)
		if _, err := proto.Marshal(wire.NetworkStateToProto(state)); err != nil {
			t.Fatalf("remarshal decoded state: %v", err)
		}
	})
}

func FuzzStateTransitionProto(f *testing.F) {
	valid := wire.StateTransitionToProto(model.StateTransition{
		Type: "upsert_zone",
		Zone: &model.DNSZone{
			ID: "zone", Domain: "fuzz.invalid", Enabled: true,
			Records: []model.DNSRecord{{Name: "host", Type: "A", Value: "100.64.0.1", TTL: -1}},
		},
	})
	encoded, err := proto.Marshal(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{0x12, 0x03, 0xff, 0xfe, 0xfd})
	f.Add([]byte{0xfa, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		var message pb.StateTransition
		if err := proto.Unmarshal(data, &message); err != nil {
			return
		}
		transition := wire.StateTransitionFromProto(&message)
		if _, err := proto.Marshal(wire.StateTransitionToProto(transition)); err != nil {
			t.Fatalf("remarshal decoded transition: %v", err)
		}
	})
}
