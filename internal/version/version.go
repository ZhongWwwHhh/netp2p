// Package version exposes the build identity reported during peer registration
// and shown in the console.
package version

// Version is the client/manager protocol revision. Override at build time with
// -ldflags "-X github.com/netp2p/netp2p/internal/version.Version=...".
var Version = "0.2.2"

// ProtocolVersion is the wire revision stamped into every libp2p protocol id.
// Managers and clients refuse to exchange control-plane messages across
// mismatched revisions. It changes only with a breaking wire change.
const ProtocolVersion = "3.0.0"

// Capabilities lists the optional protocol features this build understands.
// It is exchanged during login so a peer can reject an incompatible partner
// with a specific reason instead of failing with a generic decode error.
func Capabilities() []string {
	return []string{
		"protobuf",
		"sync-heartbeat",
		"bls-threshold-qc",
		"committee-reconfig",
		"quota-enforcement",
		"multi-hop",
		"presence",
	}
}
