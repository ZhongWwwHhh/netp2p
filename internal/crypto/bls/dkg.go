package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ErrDKG is returned for malformed or inconsistent DKG material.
var ErrDKG = errors.New("bls: invalid dkg material")

// DKGResult is the material a member holds once a Pedersen DKG ceremony
// completes: the joint group public key, this member's secret share and the
// public key share of every member (computed from the public commitments).
type DKGResult struct {
	GroupPublicKey []byte
	Share          fr.Element
	SharePublics   [][]byte
}

// KeySet converts the DKG result into the KeySet the consensus engine signs
// and aggregates with. Only the local share is known, but aggregation needs
// just the evaluation points, so the resulting KeySet is fully usable.
func (result *DKGResult) KeySet(threshold, size, index int, points []fr.Element) (*KeySet, error) {
	if len(points) != size {
		return nil, fmt.Errorf("%w: %d points for size %d", ErrDKG, len(points), size)
	}
	return NewKeySetFromShares(threshold, size, points, index, result.Share, result.SharePublics, result.GroupPublicKey)
}

// DKGState is one member's local state during a two-round Pedersen DKG. Round
// one publishes the commitments; round two publishes the shares. Commitments
// from every dealer must arrive before shares can be verified.
type DKGState struct {
	Threshold int
	Size      int
	Index     int
	Points    []fr.Element

	coefficients  []fr.Element
	commitments   [][]byte
	dealerCommits map[int][][]byte
	shares        map[int]fr.Element
}

// NewDKGState starts a ceremony for the member at index. It generates a random
// degree-(threshold-1) polynomial whose constant term is this member's
// contribution to the joint secret.
func NewDKGState(threshold, size, index int, points []fr.Element, reader io.Reader) (*DKGState, error) {
	if size < 1 || threshold < 1 || threshold > size {
		return nil, ErrInvalidThreshold
	}
	if index < 0 || index >= size {
		return nil, fmt.Errorf("%w: member index %d out of range", ErrDKG, index)
	}
	if len(points) != size {
		return nil, fmt.Errorf("%w: %d points for size %d", ErrDKG, len(points), size)
	}
	if reader == nil {
		reader = rand.Reader
	}
	coefficients := make([]fr.Element, threshold)
	for position := range coefficients {
		coefficient, err := randomScalar(reader)
		if err != nil {
			return nil, err
		}
		coefficients[position] = coefficient
	}
	commitments := make([][]byte, threshold)
	for position := range coefficients {
		commitment, err := scalarBaseG2(&coefficients[position])
		if err != nil {
			return nil, err
		}
		commitments[position] = commitment
	}
	return &DKGState{
		Threshold: threshold, Size: size, Index: index,
		Points:        append([]fr.Element(nil), points...),
		coefficients:  coefficients,
		commitments:   commitments,
		dealerCommits: make(map[int][][]byte),
		shares:        make(map[int]fr.Element),
	}, nil
}

// Commitments returns this member's coefficient commitments (G2 compressed),
// to be broadcast in round one.
func (state *DKGState) Commitments() [][]byte {
	return cloneCommitments(state.commitments)
}

// ShareFor evaluates this member's polynomial at the recipient's point. The
// result is sent privately to that member in round two.
func (state *DKGState) ShareFor(index int) (fr.Element, error) {
	if index < 0 || index >= state.Size {
		return fr.Element{}, fmt.Errorf("%w: share index %d out of range", ErrDKG, index)
	}
	return evaluatePolynomial(state.coefficients, state.Points[index]), nil
}

// AddCommitments records the commitments published by another dealer.
func (state *DKGState) AddCommitments(dealer int, commitments [][]byte) error {
	if dealer < 0 || dealer >= state.Size {
		return fmt.Errorf("%w: dealer %d out of range", ErrDKG, dealer)
	}
	if len(commitments) != state.Threshold {
		return fmt.Errorf("%w: dealer %d published %d commitments, want %d", ErrDKG, dealer, len(commitments), state.Threshold)
	}
	for _, commitment := range commitments {
		if !ValidG2Point(commitment) {
			return fmt.Errorf("%w: dealer %d has an invalid commitment", ErrDKG, dealer)
		}
	}
	state.dealerCommits[dealer] = cloneCommitments(commitments)
	return nil
}

// AddShare records a share dealt to this member, verifying it against the
// dealer's published commitments.
func (state *DKGState) AddShare(dealer int, share fr.Element) error {
	commitments, ok := state.dealerCommits[dealer]
	if !ok {
		return fmt.Errorf("%w: missing commitments for dealer %d", ErrDKG, dealer)
	}
	if !VerifyShare(commitments, state.Points[state.Index], share) {
		return fmt.Errorf("%w: dealer %d sent an inconsistent share", ErrDKG, dealer)
	}
	state.shares[dealer] = share
	return nil
}

// Finalize requires every dealer's share, sums them into the local secret and
// derives the joint group public key and every member's public key share.
func (state *DKGState) Finalize() (*DKGResult, error) {
	if len(state.dealerCommits) != state.Size {
		return nil, fmt.Errorf("%w: have %d commitments, want %d", ErrDKG, len(state.dealerCommits), state.Size)
	}
	if len(state.shares) != state.Size {
		return nil, fmt.Errorf("%w: have %d shares, want %d", ErrDKG, len(state.shares), state.Size)
	}
	var secret fr.Element
	secret.SetZero()
	for dealer := 0; dealer < state.Size; dealer++ {
		contribution := state.shares[dealer]
		secret.Add(&secret, &contribution)
	}
	var groupKey bls12381.G2Affine
	for dealer := 0; dealer < state.Size; dealer++ {
		var commitment bls12381.G2Affine
		if _, err := commitment.SetBytes(state.dealerCommits[dealer][0]); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDKG, err)
		}
		if dealer == 0 {
			groupKey = commitment
			continue
		}
		groupKey.Add(&groupKey, &commitment)
	}
	sharePublics := make([][]byte, state.Size)
	for member := 0; member < state.Size; member++ {
		point, err := commitSumAt(state.dealerCommits, state.Size, state.Points[member])
		if err != nil {
			return nil, err
		}
		encoded := point.Bytes()
		sharePublics[member] = append([]byte(nil), encoded[:]...)
	}
	encodedGroup := groupKey.Bytes()
	return &DKGResult{
		GroupPublicKey: append([]byte(nil), encodedGroup[:]...),
		Share:          secret,
		SharePublics:   sharePublics,
	}, nil
}

// VerifyShare checks g^share == product of commitment_k^{x^k}.
func VerifyShare(commitments [][]byte, point fr.Element, share fr.Element) bool {
	expected, err := commitSumAt(map[int][][]byte{0: commitments}, 1, point)
	if err != nil {
		return false
	}
	actual, err := scalarBaseG2(&share)
	if err != nil {
		return false
	}
	var actualPoint bls12381.G2Affine
	if _, err := actualPoint.SetBytes(actual); err != nil {
		return false
	}
	return expected.Equal(&actualPoint)
}

// ValidG2Point reports whether b decodes to a point on the G2 curve.
func ValidG2Point(b []byte) bool {
	if len(b) != PublicKeySize {
		return false
	}
	var point bls12381.G2Affine
	if _, err := point.SetBytes(b); err != nil {
		return false
	}
	return !point.IsInfinity()
}

// ShareBytes encodes a share scalar for transport.
func ShareBytes(share fr.Element) []byte {
	encoded := share.Bytes()
	return append([]byte(nil), encoded[:]...)
}

// ShareFromBytes decodes a share scalar from transport.
func ShareFromBytes(b []byte) (fr.Element, error) {
	var share fr.Element
	if err := share.SetBytesCanonical(b); err != nil {
		return fr.Element{}, fmt.Errorf("%w: %v", ErrDKG, err)
	}
	return share, nil
}

func evaluatePolynomial(coefficients []fr.Element, at fr.Element) fr.Element {
	var value fr.Element
	value.Set(&coefficients[len(coefficients)-1])
	for degree := len(coefficients) - 2; degree >= 0; degree-- {
		value.Mul(&value, &at)
		value.Add(&value, &coefficients[degree])
	}
	return value
}

// commitSumAt computes sum_dealer eval(commitments_dealer, point), i.e. the G2
// point g^{f(point)} for the joint polynomial.
func commitSumAt(dealerCommits map[int][][]byte, dealers int, point fr.Element) (bls12381.G2Affine, error) {
	var result bls12381.G2Affine
	first := true
	for dealer := 0; dealer < dealers; dealer++ {
		commitments, ok := dealerCommits[dealer]
		if !ok {
			return result, fmt.Errorf("%w: missing commitments for dealer %d", ErrDKG, dealer)
		}
		var power fr.Element
		power.SetOne()
		for _, encoded := range commitments {
			var commitment bls12381.G2Affine
			if _, err := commitment.SetBytes(encoded); err != nil {
				return result, fmt.Errorf("%w: %v", ErrDKG, err)
			}
			var term bls12381.G2Affine
			term.ScalarMultiplication(&commitment, frToBigInt(&power))
			if first {
				result = term
				first = false
			} else {
				result.Add(&result, &term)
			}
			power.Mul(&power, &point)
		}
	}
	return result, nil
}

func randomScalar(reader io.Reader) (fr.Element, error) {
	var buffer [64]byte
	if _, err := io.ReadFull(reader, buffer[:]); err != nil {
		return fr.Element{}, err
	}
	digest := sha256.Sum256(buffer[:])
	var scalar fr.Element
	scalar.SetBytes(digest[:])
	if scalar.IsZero() {
		scalar.SetUint64(1)
	}
	return scalar, nil
}

func cloneCommitments(commitments [][]byte) [][]byte {
	cloned := make([][]byte, len(commitments))
	for index, commitment := range commitments {
		cloned[index] = append([]byte(nil), commitment...)
	}
	return cloned
}
