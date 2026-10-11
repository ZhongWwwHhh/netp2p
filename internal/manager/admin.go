// Package manager admin plane: authenticated config transitions over libp2p.
package manager

import (
	"context"
	"crypto/subtle"
	"encoding/json"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

type AdminResponse struct {
	Snapshot *model.SignedSnapshot
	Error    string
}

// RegisterAdminHandler installs the admin stream handler. The manager verifies
// the admin token before forwarding a transition to BFT. A separate Argon2id
// manager-join verifier admits only submit_manager_join and read-only snapshot
// queries from a candidate manager.
func RegisterAdminHandler(node *p2p.Node, mesh *CommitteeMesh, adminToken string, managerJoinTokenHash []byte) {
	node.Handle(p2p.AdminProtocol, func(stream network.Stream) {
		defer stream.Close()
		envelope, err := p2p.DecodeEnvelope(stream)
		if err != nil {
			respondAdmin(stream, AdminResponse{Error: "invalid envelope"})
			return
		}
		var message pb.AdminRequest
		if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
			respondAdmin(stream, AdminResponse{Error: "invalid request"})
			return
		}
		token, transition, query := wire.AdminRequestFromProto(&message)
		adminAuthenticated := adminToken != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1
		joinAuthenticated := len(managerJoinTokenHash) > 0 &&
			subtle.ConstantTimeCompare(model.ManagerJoinTokenHash(token), managerJoinTokenHash) == 1
		if !adminAuthenticated && !joinAuthenticated {
			respondAdmin(stream, AdminResponse{Error: "forbidden"})
			return
		}
		if joinAuthenticated && !adminAuthenticated {
			if query != "" && query != "snapshot" && query != "manager-snapshot" {
				respondAdmin(stream, AdminResponse{Error: "forbidden join query"})
				return
			}
			if query == "" && transition.Type != bft.TransitionSubmitManagerJoin {
				respondAdmin(stream, AdminResponse{Error: "forbidden join transition"})
				return
			}
		}
		if query != "" {
			payload, err := adminQuery(mesh, query, stream.Conn().RemotePeer())
			if err != nil {
				respondAdminQuery(stream, nil, err.Error())
				return
			}
			respondAdminQuery(stream, payload, "")
			return
		}
		identity := auth.BreakGlass()
		actor := auth.ActorOf(identity)
		if joinAuthenticated && !adminAuthenticated {
			actor = model.Actor{ID: "system:manager-join", Name: "manager join", Role: "system"}
		} else if err := auth.AuthorizeTransition(identity, transition.Type); err != nil {
			respondAdmin(stream, AdminResponse{Error: err.Error()})
			return
		}
		// The stream cannot carry a structured identity, so any actor sent on
		// the wire is discarded here.
		transition.Actor = &actor
		snapshot, err := mesh.Submit(transition)
		if err != nil {
			respondAdmin(stream, AdminResponse{Error: err.Error()})
			return
		}
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			respondAdmin(stream, AdminResponse{Error: err.Error()})
			return
		}
		respondAdmin(stream, AdminResponse{Snapshot: &snapshot})
	})
}

// adminQuery answers read-only admin inspections from certified local state.
// Queries never touch BFT and never mutate anything, so a manager can serve
// them even while the committee is degraded.
func adminQuery(mesh *CommitteeMesh, query string, remote peer.ID) ([]byte, error) {
	switch query {
	case "snapshot":
		snapshot, ok := mesh.engine.LatestSnapshot()
		if !ok {
			return nil, &AdminError{Message: "no certified snapshot"}
		}
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			return nil, err
		}
		return json.Marshal(model.ClientSnapshot(snapshot))
	case "manager-snapshot":
		snapshot, ok := mesh.engine.LatestSnapshot()
		if !ok {
			return nil, &AdminError{Message: "no certified snapshot"}
		}
		approved := false
		for _, request := range snapshot.State.ManagerJoins {
			if request.PeerID == remote.String() &&
				(request.Status == model.ManagerJoinApproved || request.Status == model.ManagerJoinActivated) {
				approved = true
				break
			}
		}
		if !approved {
			return nil, &AdminError{Message: "candidate manager is not approved"}
		}
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			return nil, err
		}
		return json.Marshal(snapshot)
	default:
		return nil, &AdminError{Message: "unknown query " + query}
	}
}

// QueryAdmin performs a read-only inspection over the admin protocol. The
// manager authenticates the token exactly as it does for transitions.
func QueryAdmin(ctx context.Context, node *p2p.Node, managerID peer.ID, adminToken, query string) ([]byte, error) {
	stream, err := node.Host.NewStream(ctx, managerID, p2p.AdminProtocol)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, wire.AdminQueryToProto(adminToken, query)); err != nil {
		return nil, err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return nil, err
	}
	var message pb.AdminResponse
	if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
		return nil, err
	}
	data, errMessage := wire.AdminQueryResponseFromProto(&message)
	if errMessage != "" {
		return nil, &AdminError{Message: errMessage}
	}
	return data, nil
}

// SubmitAdmin sends an authenticated transition to a manager and waits for the
// BFT-certified snapshot. This is the client-side helper used by the admin CLI.
func SubmitAdmin(ctx context.Context, node *p2p.Node, managerID peer.ID, adminToken string, transition model.StateTransition) (model.SignedSnapshot, error) {
	stream, err := node.Host.NewStream(ctx, managerID, p2p.AdminProtocol)
	if err != nil {
		return model.SignedSnapshot{}, err
	}
	defer stream.Close()
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, wire.AdminRequestToProto(adminToken, transition)); err != nil {
		return model.SignedSnapshot{}, err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return model.SignedSnapshot{}, err
	}
	var message pb.AdminResponse
	if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
		return model.SignedSnapshot{}, err
	}
	snapshot, errMessage := wire.AdminResponseFromProto(&message)
	if errMessage != "" {
		return model.SignedSnapshot{}, &AdminError{Message: errMessage}
	}
	if snapshot == nil {
		return model.SignedSnapshot{}, &AdminError{Message: "no snapshot in response"}
	}
	return *snapshot, nil
}

type AdminError struct {
	Message string
}

func (err *AdminError) Error() string { return err.Message }

func respondAdmin(stream network.Stream, response AdminResponse) {
	if response.Snapshot != nil {
		redacted := model.ClientSnapshot(*response.Snapshot)
		response.Snapshot = &redacted
	}
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, wire.AdminResponseToProto(response.Snapshot, response.Error)); err != nil {
		stream.Reset()
	}
}

func respondAdminQuery(stream network.Stream, data []byte, errMessage string) {
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, wire.AdminQueryResponseToProto(data, errMessage)); err != nil {
		stream.Reset()
	}
}
