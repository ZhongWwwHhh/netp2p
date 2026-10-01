package bls

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// runDKG simulates a full in-process Pedersen ceremony for `size` members and
// returns each member's finished result.
func runDKG(t *testing.T, threshold, size int) []*DKGResult {
	t.Helper()
	points := make([]fr.Element, size)
	for index := range points {
		points[index] = PointForIdentity(string(rune('A' + index)))
	}
	states := make([]*DKGState, size)
	for index := range states {
		reader := bytes.NewReader(deterministicBytes("member", byte(index)))
		state, err := NewDKGState(threshold, size, index, points, reader)
		if err != nil {
			t.Fatalf("new state %d: %v", index, err)
		}
		states[index] = state
	}
	for dealer, state := range states {
		for member, target := range states {
			if err := target.AddCommitments(dealer, state.Commitments()); err != nil {
				t.Fatalf("commitments %d->%d: %v", dealer, member, err)
			}
		}
	}
	for dealer, state := range states {
		for member, target := range states {
			share, err := state.ShareFor(member)
			if err != nil {
				t.Fatalf("share %d->%d: %v", dealer, member, err)
			}
			if err := target.AddShare(dealer, share); err != nil {
				t.Fatalf("accept share %d->%d: %v", dealer, member, err)
			}
		}
	}
	results := make([]*DKGResult, size)
	for index, state := range states {
		result, err := state.Finalize()
		if err != nil {
			t.Fatalf("finalize %d: %v", index, err)
		}
		results[index] = result
	}
	return results
}

func deterministicBytes(prefix string, tag byte) []byte {
	out := make([]byte, 0, 512)
	seed := append([]byte{tag}, []byte(prefix)...)
	for len(out) < 512 {
		digest := sha256.Sum256(append(seed, byte(len(out))))
		out = append(out, digest[:]...)
	}
	return out
}

func TestDKGAggregatesWithQuorum(t *testing.T) {
	const threshold, size = 3, 4
	results := runDKG(t, threshold, size)
	for index := 1; index < size; index++ {
		if !bytes.Equal(results[0].GroupPublicKey, results[index].GroupPublicKey) {
			t.Fatalf("members disagree on the group public key")
		}
	}
	if !ValidG2Point(results[0].GroupPublicKey) {
		t.Fatal("group public key is not a valid G2 point")
	}

	points := make([]fr.Element, size)
	for index := range points {
		points[index] = PointForIdentity(string(rune('A' + index)))
	}
	keys, err := results[0].KeySet(threshold, size, 0, points)
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	message := []byte("height=1 round=0 transition=abc")
	partials := make(map[int][]byte, threshold)
	for _, index := range []int{0, 1, 2} {
		memberKeys, err := results[index].KeySet(threshold, size, index, points)
		if err != nil {
			t.Fatalf("member %d key set: %v", index, err)
		}
		signature, err := memberKeys.SignShare(index, message)
		if err != nil {
			t.Fatalf("sign %d: %v", index, err)
		}
		if !Verify(keys.PublicKeyShare(index), message, signature) {
			t.Fatalf("share %d did not verify against its public key", index)
		}
		partials[index] = signature
	}
	aggregate, err := keys.Aggregate(partials)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !Verify(results[0].GroupPublicKey, message, aggregate) {
		t.Fatal("threshold aggregate did not verify against the DKG group key")
	}

	// Fewer than threshold partials must not verify against the group key.
	short, err := keys.Aggregate(map[int][]byte{0: partials[0], 1: partials[1]})
	if err != nil {
		t.Fatalf("short aggregate: %v", err)
	}
	if Verify(results[0].GroupPublicKey, message, short) {
		t.Fatal("2-of-4 signature verified against the DKG group key")
	}
}

func TestDKGRejectsTamperedShare(t *testing.T) {
	const threshold, size = 3, 4
	points := make([]fr.Element, size)
	for index := range points {
		points[index] = PointForIdentity(string(rune('A' + index)))
	}
	dealer, err := NewDKGState(threshold, size, 0, points, bytes.NewReader(deterministicBytes("d", 0)))
	if err != nil {
		t.Fatalf("dealer: %v", err)
	}
	member, err := NewDKGState(threshold, size, 1, points, bytes.NewReader(deterministicBytes("m", 1)))
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	if err := member.AddCommitments(0, dealer.Commitments()); err != nil {
		t.Fatalf("commitments: %v", err)
	}
	share, err := dealer.ShareFor(1)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	share.Add(&share, new(fr.Element).SetUint64(1))
	if err := member.AddShare(0, share); err == nil {
		t.Fatal("tampered share was accepted")
	}
}

func TestDKGRejectsInvalidCommitment(t *testing.T) {
	const threshold, size = 3, 4
	points := make([]fr.Element, size)
	for index := range points {
		points[index] = PointForIdentity(string(rune('A' + index)))
	}
	member, err := NewDKGState(threshold, size, 0, points, bytes.NewReader(deterministicBytes("m", 0)))
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if err := member.AddCommitments(1, [][]byte{make([]byte, PublicKeySize), make([]byte, PublicKeySize), make([]byte, PublicKeySize)}); err == nil {
		t.Fatal("all-zero commitment was accepted")
	}
}
