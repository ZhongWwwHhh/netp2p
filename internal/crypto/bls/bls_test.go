package bls

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func deriveTestKeySet(seed []byte, threshold, size int) (*KeySet, error) {
	points := make([]fr.Element, size)
	for index := range points {
		points[index] = PointForIdentity(string(rune('A' + index)))
	}
	return DeriveKeySet(seed, threshold, points)
}

func TestThresholdAggregate(t *testing.T) {
	keys, err := deriveTestKeySet([]byte("committee-seed"), 3, 4)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	message := []byte("height=7 round=0")

	partials := make(map[int][]byte, 3)
	for _, index := range []int{0, 1, 2} {
		signature, err := keys.SignShare(index, message)
		if err != nil {
			t.Fatalf("sign share %d: %v", index, err)
		}
		if !Verify(keys.PublicKeyShare(index), message, signature) {
			t.Fatalf("partial signature %d did not verify", index)
		}
		partials[index] = signature
	}
	aggregate, err := keys.Aggregate(partials)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !Verify(keys.GroupPublicKey, message, aggregate) {
		t.Fatalf("aggregate did not verify against group public key")
	}
}

func TestAggregateOrderIndependent(t *testing.T) {
	keys, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	message := []byte("payload")
	signatures := make(map[int][]byte)
	for _, index := range []int{1, 2, 3} {
		signature, _ := keys.SignShare(index, message)
		signatures[index] = signature
	}
	first, err := keys.Aggregate(signatures)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Recompute with a different signer subset order; the result must be stable.
	second, err := keys.Aggregate(map[int][]byte{3: signatures[3], 1: signatures[1], 2: signatures[2]})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("aggregation is order dependent")
	}
}

func TestAggregateDifferentSubsetMatches(t *testing.T) {
	keys, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	message := []byte("payload")
	signatures := make(map[int][]byte)
	for index := 0; index < 4; index++ {
		signature, _ := keys.SignShare(index, message)
		signatures[index] = signature
	}
	a, _ := keys.Aggregate(map[int][]byte{0: signatures[0], 1: signatures[1], 2: signatures[2]})
	b, _ := keys.Aggregate(map[int][]byte{0: signatures[0], 1: signatures[1], 3: signatures[3]})
	// Any t-of-n subset reconstructs f(0)*H(m), so all subsets produce the
	// identical group signature.
	if !bytes.Equal(a, b) {
		t.Fatalf("valid subsets produced different aggregates")
	}
	if !Verify(keys.GroupPublicKey, message, b) {
		t.Fatalf("second subset aggregate did not verify")
	}
}

func TestTwoSharesCannotReconstruct(t *testing.T) {
	keys, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	message := []byte("payload")
	first, _ := keys.SignShare(0, message)
	second, _ := keys.SignShare(1, message)
	aggregate, err := keys.Aggregate(map[int][]byte{0: first, 1: second})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if Verify(keys.GroupPublicKey, message, aggregate) {
		t.Fatalf("two shares must not reconstruct the master signature")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	keys, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	message := []byte("payload")
	partials := map[int][]byte{}
	for _, index := range []int{0, 1, 2} {
		signature, _ := keys.SignShare(index, message)
		partials[index] = signature
	}
	aggregate, _ := keys.Aggregate(partials)

	if Verify(keys.GroupPublicKey, []byte("other message"), aggregate) {
		t.Fatalf("signature verified for a different message")
	}
	other, _ := deriveTestKeySet([]byte("other-seed"), 3, 4)
	if Verify(other.GroupPublicKey, message, aggregate) {
		t.Fatalf("signature verified against the wrong group public key")
	}
	tampered := append([]byte(nil), aggregate...)
	tampered[0] ^= 0x01
	if Verify(keys.GroupPublicKey, message, tampered) {
		t.Fatalf("tampered signature verified")
	}
}

func TestDeriveDeterministic(t *testing.T) {
	first, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	second, _ := deriveTestKeySet([]byte("seed"), 3, 4)
	if !bytes.Equal(first.GroupPublicKey, second.GroupPublicKey) {
		t.Fatalf("group public key derivation is not deterministic")
	}
	for index := 0; index < 4; index++ {
		if !bytes.Equal(first.PublicKeyShare(index), second.PublicKeyShare(index)) {
			t.Fatalf("share %d derivation is not deterministic", index)
		}
	}
}

func TestInvalidThreshold(t *testing.T) {
	if _, err := deriveTestKeySet([]byte("seed"), 4, 3); err == nil {
		t.Fatalf("expected error for threshold larger than size")
	}
}
