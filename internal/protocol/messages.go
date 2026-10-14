// Package protocol defines the control-plane wire messages shared by the
// manager and client so the two sides cannot drift apart.
package protocol

import (
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

type LoginRequest struct {
	NetworkID     string   `json:"networkId"`
	SetupKey      string   `json:"setupKey"`
	JWTToken      string   `json:"jwtToken,omitempty"`
	PeerID        string   `json:"peerId"`
	Addresses     []string `json:"addresses,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"clientVersion,omitempty"`
	// ProtocolVersion and Capabilities implement the startup handshake. A
	// mismatch is rejected with an explicit error instead of a decode failure.
	ProtocolVersion string   `json:"protocolVersion,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	// Posture is the declarative capability labels the peer advertises. It is
	// recorded on first registration and later managed through update_peer.
	Posture []string `json:"posture,omitempty"`
}

type LoginResponse struct {
	Snapshot model.SignedSnapshot `json:"snapshot"`
	Peer     model.PeerRecord     `json:"peer"`
	Error    string               `json:"error,omitempty"`
	// Code classifies a failure so clients can branch without matching prose.
	Code            string   `json:"code,omitempty"`
	ProtocolVersion string   `json:"protocolVersion,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

// Login error codes shared by the manager and client.
const (
	CodeLoginExpired         = "login_expired"
	CodeInvalidJWT           = "invalid_jwt"
	CodeInvalidSetupKey      = "invalid_setup_key"
	CodeRegistrationRequired = "registration_required"
	CodeCommitteeUnavailable = "committee_unavailable"
)

type SyncRequest struct {
	NetworkID         string            `json:"networkId"`
	PeerID            string            `json:"peerId"`
	Height            uint64            `json:"height"`
	AssignmentsHeight uint64            `json:"assignmentsHeight,omitempty"`
	Admissions        []AdmissionReport `json:"admissions,omitempty"`
	ProtocolVersion   string            `json:"protocolVersion,omitempty"`
}

type AdmissionReport struct {
	AssignmentID string    `json:"assignmentId"`
	PathID       string    `json:"pathId"`
	OK           bool      `json:"ok"`
	RTTMs        float64   `json:"rttMs"`
	LossPct      float64   `json:"lossPct"`
	ObservedAt   time.Time `json:"observedAt"`
}

// QuotaReport carries client-observed byte increments to the manager. The
// manager aggregates them and settles the total into certified state, which is
// why the client never submits absolute usage.
type QuotaReport struct {
	PeerID          string            `json:"peerId"`
	Increments      []BudgetIncrement `json:"increments"`
	ReportedAt      time.Time         `json:"reportedAt"`
	ProtocolVersion string            `json:"protocolVersion,omitempty"`
}

type BudgetIncrement struct {
	BudgetID string `json:"budgetId"`
	Bytes    uint64 `json:"bytes"`
}

// Login rejection codes added by the quota/committee stages.
const (
	CodeProtocolMismatch = "protocol_mismatch"
)
