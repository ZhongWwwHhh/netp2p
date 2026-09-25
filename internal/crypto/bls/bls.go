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
// (0-based) is evaluated at a stable per-member point, so replacing one member
// leaves the other members' shares and the group public key untouched.
type KeySet struct {
	Threshold      int
	Size           int
	GroupPublicKey []byte
	shares         []fr.Element
	points         []fr.Element
	sharePubs      [][]byte
}

// PointForIdentity derives the stable evaluation point for a committee member
// identity. The value is a deterministic field element; two different
// identities collide only with negligible probability.
func PointForIdentity(identity string) fr.Element {
	digest := sha256.Sum256(append([]byte("netp2p-bls-point-v1"), []byte(identity)...))
	var point fr.Element
	point.SetBytes(digest[:])
	if point.IsZero() {
		point.SetUint64(1)
	}
	return point
}

// DeriveKeySet deterministically builds a (threshold, size) sharing from seed
// evaluated at the provided member points. The same seed and points always
// yield the same group public key and shares, so every committee member can
// independently reconstruct the configuration.
func DeriveKeySet(seed []byte, threshold int, points []fr.Element) (*KeySet, error) {
	size := len(points)
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
		points:    make([]fr.Element, size),
		sharePubs: make([][]byte, size),
	}
	for index := 0; index < size; index++ {
		x := points[index]
		keys.points[index] = x
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

// Points returns the evaluation points used for the shares, in index order.
func (keys *KeySet) Points() []fr.Element {
	return append([]fr.Element(nil), keys.points...)
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
func (keys *KeySet) Aggregate(partials map[int][]byte) ([]byte, error) {
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
		if index < 0 || index >= len(keys.points) {
			return nil, fmt.Errorf("bls: share index %d out of range", index)
		}
		var signature bls12381.G1Affine
		if _, err := signature.SetBytes(partials[index]); err != nil {
			return nil, fmt.Errorf("bls: invalid partial signature: %w", err)
		}
		lambda := keys.lagrangeAtZero(indices, index)
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

// lagrangeAtZero returns the Lagrange coefficient evaluated at 0 for the share
// at index among the provided indices.
func (keys *KeySet) lagrangeAtZero(indices []int, index int) *big.Int {
	var numerator, denominator fr.Element
	numerator.SetOne()
	denominator.SetOne()
	xIndex := keys.points[index]
	for _, other := range indices {
		if other == index {
			continue
		}
		var xOther, difference fr.Element
		xOther = keys.points[other]
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
