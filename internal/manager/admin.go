// Package manager admin plane: authenticated config transitions over libp2p.
package manager

import (
	"context"

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
// the admin token from the static seed before forwarding the transition to BFT.
func RegisterAdminHandler(node *p2p.Node, mesh *CommitteeMesh, adminToken string) {
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
		token, transition := wire.AdminRequestFromProto(&message)
		if adminToken == "" || token != adminToken {
			respondAdmin(stream, AdminResponse{Error: "forbidden"})
			return
		}
		if err := auth.AuthorizeTransition(auth.BreakGlass(), transition.Type); err != nil {
			respondAdmin(stream, AdminResponse{Error: err.Error()})
			return
		}
		// The admin stream cannot carry a structured identity, so every admin
		// transition is attributed to the break-glass token. Any actor sent on
		// the wire is discarded here.
		actor := auth.ActorOf(auth.BreakGlass())
		transition.Actor = &actor
		snapshot, err := mesh.Submit(transition)
		if err != nil {
			respondAdmin(stream, AdminResponse{Error: err.Error()})
			return
		}
		respondAdmin(stream, AdminResponse{Snapshot: &snapshot})
	})
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
	if err := bft.ValidateSnapshot(*snapshot); err != nil {
		return model.SignedSnapshot{}, err
	}
	return *snapshot, nil
}

type AdminError struct {
	Message string
}

func (err *AdminError) Error() string { return err.Message }

func respondAdmin(stream network.Stream, response AdminResponse) {
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, wire.AdminResponseToProto(response.Snapshot, response.Error)); err != nil {
		stream.Reset()
	}
}
