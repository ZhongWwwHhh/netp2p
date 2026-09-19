// Package manager admin plane: authenticated config transitions over libp2p.
package manager

import (
	"context"
	"encoding/json"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

type AdminRequest struct {
	Token      string                `json:"token"`
	Transition model.StateTransition `json:"transition"`
}

type AdminResponse struct {
	Snapshot *model.SignedSnapshot `json:"snapshot,omitempty"`
	Error    string                `json:"error,omitempty"`
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
		var request AdminRequest
		if err := json.Unmarshal(envelope.Payload, &request); err != nil {
			respondAdmin(stream, AdminResponse{Error: "invalid request"})
			return
		}
		if adminToken == "" || request.Token != adminToken {
			respondAdmin(stream, AdminResponse{Error: "forbidden"})
			return
		}
		snapshot, err := mesh.Submit(request.Transition)
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
	encoded, err := json.Marshal(AdminRequest{Token: adminToken, Transition: transition})
	if err != nil {
		return model.SignedSnapshot{}, err
	}
	if err := json.NewEncoder(stream).Encode(p2p.Envelope{Protocol: p2p.AdminProtocol, Payload: encoded}); err != nil {
		return model.SignedSnapshot{}, err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return model.SignedSnapshot{}, err
	}
	var response AdminResponse
	if err := json.Unmarshal(envelope.Payload, &response); err != nil {
		return model.SignedSnapshot{}, err
	}
	if response.Error != "" {
		return model.SignedSnapshot{}, &AdminError{Message: response.Error}
	}
	if response.Snapshot == nil {
		return model.SignedSnapshot{}, &AdminError{Message: "no snapshot in response"}
	}
	if err := bft.ValidateSnapshot(*response.Snapshot); err != nil {
		return model.SignedSnapshot{}, err
	}
	return *response.Snapshot, nil
}

type AdminError struct {
	Message string
}

func (err *AdminError) Error() string { return err.Message }

func respondAdmin(stream network.Stream, response AdminResponse) {
	if err := json.NewEncoder(stream).Encode(response); err != nil {
		stream.Reset()
	}
}
