package model

// Proposal is a leader's candidate block. It carries the full post-transition
// state so voters can recompute the state hash independently.
type Proposal struct {
	Height     uint64          `json:"height"`
	Round      uint64          `json:"round"`
	NetworkID  string          `json:"networkId"`
	State      NetworkState    `json:"state"`
	LeaderID   string          `json:"leaderId"`
	Transition StateTransition `json:"transition"`
}

// Vote is a committee member's signature over a proposal's state and
// transition hashes.
type Vote struct {
	Height         uint64 `json:"height"`
	Round          uint64 `json:"round"`
	NetworkID      string `json:"networkId"`
	StateHash      []byte `json:"stateHash"`
	TransitionHash []byte `json:"transitionHash"`
	// ClientViewHash covers the client-visible projection of the state and
	// transition, allowing clients to validate redacted snapshots without
	// receiving manager-only secrets.
	ClientViewHash []byte `json:"clientViewHash,omitempty"`
	VoterID        string `json:"voterId"`
	Signature      []byte `json:"signature"`
	// CommitteeEpoch binds the vote to the committee configuration that
	// produced it, so votes cast before a key rotation cannot be replayed.
	CommitteeEpoch uint64 `json:"committeeEpoch,omitempty"`
}

// CommitteeEnvelope multiplexes the consensus messages exchanged between
// managers on the state-update stream.
type CommitteeEnvelope struct {
	Type       string           `json:"type"`
	Proposal   *Proposal        `json:"proposal,omitempty"`
	Vote       *Vote            `json:"vote,omitempty"`
	Snapshot   *SignedSnapshot  `json:"snapshot,omitempty"`
	Transition *StateTransition `json:"transition,omitempty"`
	Height     uint64           `json:"height,omitempty"`
	Round      uint64           `json:"round,omitempty"`
}
