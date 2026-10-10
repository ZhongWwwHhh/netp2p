package main

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func member(id string, overrides model.CommitteeMember) model.CommitteeMember {
	member := model.CommitteeMember{
		ID: id, PeerID: "peer-" + id, Address: "/dns4/" + id + "/udp/4001",
		ListenAddr: "/ip4/0.0.0.0/udp/4101/webrtc-direct", PublicKey: []byte(id),
		ForwardingEnabled: true,
	}
	member.PublicKey = append(member.PublicKey, byte(len(id)))
	if overrides.ID != "" {
		member.ID = overrides.ID
	}
	if overrides.PeerID != "" {
		member.PeerID = overrides.PeerID
	}
	if overrides.Address != "" {
		member.Address = overrides.Address
	}
	if overrides.ListenAddr != "" {
		member.ListenAddr = overrides.ListenAddr
	}
	if overrides.KeySeed != 0 {
		member.KeySeed = overrides.KeySeed
	}
	if len(overrides.PublicKey) != 0 {
		member.PublicKey = overrides.PublicKey
	}
	return member
}

func TestSameRoutingCommitteeMatchesIndependentOrder(t *testing.T) {
	manifest := []model.CommitteeMember{member("sg", model.CommitteeMember{}), member("fr", model.CommitteeMember{})}
	certified := []model.CommitteeMember{member("fr", model.CommitteeMember{}), member("sg", model.CommitteeMember{})}
	certified[0].BLSPublicKey = []byte("dkg-fr")
	certified[1].BLSPublicKey = []byte("dkg-sg")
	if !sameRoutingCommittee(manifest, certified) {
		t.Fatal("routing committee differed only by order or certified DKG keys")
	}
}

func TestSameRoutingCommitteeRejectsDrift(t *testing.T) {
	base := []model.CommitteeMember{member("fr", model.CommitteeMember{}), member("sg", model.CommitteeMember{})}
	cases := map[string]func([]model.CommitteeMember){
		"peer id": func(members []model.CommitteeMember) {
			members[0] = member("fr", model.CommitteeMember{PeerID: "rotated"})
		},
		"address": func(members []model.CommitteeMember) {
			members[0] = member("fr", model.CommitteeMember{Address: "/dns4/rotated/udp/4001"})
		},
		"listen addr": func(members []model.CommitteeMember) {
			members[0] = member("fr", model.CommitteeMember{ListenAddr: "/ip4/0.0.0.0/udp/9999/webrtc-direct"})
		},
		"identity": func(members []model.CommitteeMember) {
			members[0] = member("fr", model.CommitteeMember{PublicKey: []byte("rotated")})
		},
		"forwarding": func(members []model.CommitteeMember) {
			members[0].ForwardingEnabled = false
		},
		"seed": func(members []model.CommitteeMember) { members[0] = member("fr", model.CommitteeMember{KeySeed: 1}) },
	}
	for name, mutate := range cases {
		certified := append([]model.CommitteeMember(nil), base...)
		mutate(certified)
		if sameRoutingCommittee(base, certified) {
			t.Fatalf("%s drift was accepted", name)
		}
	}
	if sameRoutingCommittee(base, base[:1]) {
		t.Fatal("committee size mismatch was accepted")
	}
}
