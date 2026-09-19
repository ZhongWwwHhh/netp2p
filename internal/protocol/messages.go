// Package protocol defines the control-plane wire messages shared by the
// manager and client so the two sides cannot drift apart.
package protocol

import "github.com/netp2p/netp2p/internal/model"

type LoginRequest struct {
	NetworkID     string   `json:"networkId"`
	SetupKey      string   `json:"setupKey"`
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
}

type SyncRequest struct {
	NetworkID string `json:"networkId"`
	PeerID    string `json:"peerId"`
	Height    uint64 `json:"height"`
}
