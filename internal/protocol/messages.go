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
}

type LoginResponse struct {
	Snapshot model.SignedSnapshot `json:"snapshot"`
	Peer     model.PeerRecord     `json:"peer"`
	Error    string               `json:"error,omitempty"`
	// Code classifies a failure so clients can branch without matching prose.
	Code string `json:"code,omitempty"`
}

// Login error codes shared by the manager and client.
const (
	CodeLoginExpired         = "login_expired"
	CodeInvalidJWT           = "invalid_jwt"
	CodeInvalidSetupKey      = "invalid_setup_key"
	CodeRegistrationRequired = "registration_required"
)

type SyncRequest struct {
	NetworkID         string            `json:"networkId"`
	PeerID            string            `json:"peerId"`
	Height            uint64            `json:"height"`
	AssignmentsHeight uint64            `json:"assignmentsHeight,omitempty"`
	Admissions        []AdmissionReport `json:"admissions,omitempty"`
}

type AdmissionReport struct {
	AssignmentID string    `json:"assignmentId"`
	PathID       string    `json:"pathId"`
	OK           bool      `json:"ok"`
	RTTMs        float64   `json:"rttMs"`
	LossPct      float64   `json:"lossPct"`
	ObservedAt   time.Time `json:"observedAt"`
}
