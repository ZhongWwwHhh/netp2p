// Package bls implements the BLS12-381 threshold signatures used for committee
// quorum certificates.
//
// Signatures live in G1 (48-byte compressed) and public keys in G2 (96-byte
// compressed) so the aggregate carried in a QuorumCertificate stays small. The
// scheme is the standard BLS signature: sigma = sk * H(m), verified with a
// pairing e(sigma, G2) == e(H(m), pk).
//
// Consensus uses a (t-of-n) Shamir sharing of a master secret. In v0 the master
// secret is derived deterministically from the committee seed so that any
// manager can rebuild the shares without a DKG ceremony; this is documented as
// a development-grade simplification. A later stage replaces it with a real
// distributed key generation.
package bls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// SignatureSize and PublicKeySize are the compressed sizes for the G1/G2
// groups used here.
const (
	SignatureSize = bls12381.SizeOfG1AffineCompressed
	PublicKeySize = bls12381.SizeOfG2AffineCompressed

	// domainSeparationTag is the hash-to-curve domain for the overlay.
	domainSeparationTag = "NETP2P_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"
)

var (
	// ErrInvalidThreshold is returned when the (t, n) parameters are unusable.
	ErrInvalidThreshold = errors.New("bls: invalid threshold parameters")
	// ErrNotEnoughShares is returned when fewer than t signatures are offered.
	ErrNotEnoughShares = errors.New("bls: not enough shares to aggregate")
)

// KeySet holds the deterministic Shamir sharing for a committee. Share i
// (0-based) corresponds to x = i+1, matching the sorted committee order used by
// the BFT engine.
type KeySet struct {
	Threshold      int
	Size           int
	GroupPublicKey []byte
	shares         []fr.Element
	sharePubs      [][]byte
}

// DeriveKeySet deterministically builds a (threshold, size) sharing from seed.
// The same seed always yields the same group public key and shares, so every
// committee member can independently reconstruct the configuration.
func DeriveKeySet(seed []byte, threshold, size int) (*KeySet, error) {
	if size < 1 || threshold < 1 || threshold > size {
		return nil, ErrInvalidThreshold
	}
	coefficients := make([]fr.Element, threshold)
	for index := range coefficients {
		coefficients[index] = deriveScalar(seed, byte(index))
	}
	keys := &KeySet{
		Threshold: threshold,
		Size:      size,
		shares:    make([]fr.Element, size),
		sharePubs: make([][]byte, size),
	}
	for index := 0; index < size; index++ {
		var x fr.Element
		x.SetUint64(uint64(index + 1))
		var value fr.Element
		value.Set(&coefficients[threshold-1])
		for degree := threshold - 2; degree >= 0; degree-- {
			value.Mul(&value, &x)
			value.Add(&value, &coefficients[degree])
		}
		keys.shares[index] = value
		publicKey, err := scalarBaseG2(&value)
		if err != nil {
			return nil, err
		}
		keys.sharePubs[index] = publicKey
	}
	groupPublicKey, err := scalarBaseG2(&coefficients[0])
	if err != nil {
		return nil, err
	}
	keys.GroupPublicKey = groupPublicKey
	return keys, nil
}

// SignShare produces this member's partial signature over message.
func (keys *KeySet) SignShare(index int, message []byte) ([]byte, error) {
	if index < 0 || index >= keys.Size {
		return nil, fmt.Errorf("bls: share index %d out of range", index)
	}
	point, err := bls12381.HashToG1(message, []byte(domainSeparationTag))
	if err != nil {
		return nil, err
	}
	var signature bls12381.G1Affine
	signature.ScalarMultiplication(&point, frToBigInt(&keys.shares[index]))
	encoded := signature.Bytes()
	return encoded[:], nil
}

// PublicKeyShare returns the compressed public key for share index.
func (keys *KeySet) PublicKeyShare(index int) []byte {
	if index < 0 || index >= keys.Size {
		return nil
	}
	return append([]byte(nil), keys.sharePubs[index]...)
}

// Aggregate combines at least Threshold partial signatures into a single
// signature that verifies against the group public key. The order of the input
// map does not affect the result.
func Aggregate(partials map[int][]byte) ([]byte, error) {
	if len(partials) == 0 {
		return nil, ErrNotEnoughShares
	}
	indices := make([]int, 0, len(partials))
	for index := range partials {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	var accumulator bls12381.G1Affine
	first := true
	for _, index := range indices {
		var signature bls12381.G1Affine
		if _, err := signature.SetBytes(partials[index]); err != nil {
			return nil, fmt.Errorf("bls: invalid partial signature: %w", err)
		}
		lambda := lagrangeAtZero(indices, index)
		var term bls12381.G1Affine
		term.ScalarMultiplication(&signature, lambda)
		if first {
			accumulator = term
			first = false
			continue
		}
		accumulator.Add(&accumulator, &term)
	}
	encoded := accumulator.Bytes()
	return encoded[:], nil
}

// Verify checks a (possibly aggregated) signature against a public key.
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}
	var key bls12381.G2Affine
	if _, err := key.SetBytes(publicKey); err != nil {
		return false
	}
	var sig bls12381.G1Affine
	if _, err := sig.SetBytes(signature); err != nil {
		return false
	}
	point, err := bls12381.HashToG1(message, []byte(domainSeparationTag))
	if err != nil {
		return false
	}
	return pairingEqual(sig, point, key)
}

func pairingEqual(signature, point bls12381.G1Affine, publicKey bls12381.G2Affine) bool {
	_, _, _, generator := bls12381.Generators()
	var negPoint bls12381.G1Affine
	negPoint.Neg(&point)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{signature, negPoint},
		[]bls12381.G2Affine{generator, publicKey},
	)
	return err == nil && ok
}

// lagrangeAtZero returns the Lagrange coefficient evaluated at 0 for share
// index among the provided indices, all of which use x = index+1.
func lagrangeAtZero(indices []int, index int) *big.Int {
	var numerator, denominator fr.Element
	numerator.SetOne()
	denominator.SetOne()
	var xIndex fr.Element
	xIndex.SetUint64(uint64(index + 1))
	for _, other := range indices {
		if other == index {
			continue
		}
		var xOther, difference fr.Element
		xOther.SetUint64(uint64(other + 1))
		numerator.Mul(&numerator, &xOther)
		difference.Sub(&xOther, &xIndex)
		denominator.Mul(&denominator, &difference)
	}
	var coefficient fr.Element
	coefficient.Div(&numerator, &denominator)
	return frToBigInt(&coefficient)
}

func deriveScalar(seed []byte, tag byte) fr.Element {
	digest := sha256.Sum256(append(append([]byte(nil), seed...), tag))
	var scalar fr.Element
	scalar.SetBytes(digest[:])
	if scalar.IsZero() {
		scalar.SetUint64(1)
	}
	return scalar
}

func scalarBaseG2(scalar *fr.Element) ([]byte, error) {
	_, _, _, generator := bls12381.Generators()
	var point bls12381.G2Affine
	point.ScalarMultiplication(&generator, frToBigInt(scalar))
	encoded := point.Bytes()
	return encoded[:], nil
}

func frToBigInt(scalar *fr.Element) *big.Int {
	return scalar.BigInt(new(big.Int))
}
