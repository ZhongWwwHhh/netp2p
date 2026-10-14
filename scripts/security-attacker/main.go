// Command security-attacker exercises NetP2P's public control-plane boundaries
// with a real libp2p host. It is intentionally external to the manager process.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/transport"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

type options struct {
	manager         string
	network         string
	adminToken      string
	joinToken       string
	victimPeer      string
	budgetID        string
	assignmentID    string
	pathID          string
	sourcePeer      string
	destination     string
	attacks         string
	protocolVersion string
}

func main() {
	var opts options
	flag.StringVar(&opts.manager, "manager", "", "manager multiaddr including /p2p/")
	flag.StringVar(&opts.network, "network", "", "certified network id")
	flag.StringVar(&opts.adminToken, "admin-token", "", "valid admin token used only for read-only height checks")
	flag.StringVar(&opts.joinToken, "join-token", "", "valid manager join token")
	flag.StringVar(&opts.victimPeer, "victim-peer", "", "peer id claimed by the quota spoof")
	flag.StringVar(&opts.budgetID, "budget-id", "", "target traffic budget id")
	flag.StringVar(&opts.assignmentID, "assignment-id", "", "certified assignment id")
	flag.StringVar(&opts.pathID, "path-id", "", "certified path id")
	flag.StringVar(&opts.sourcePeer, "source-peer", "", "certified source peer id to impersonate")
	flag.StringVar(&opts.destination, "destination-peer", "", "certified destination peer id")
	flag.StringVar(&opts.attacks, "attacks", "", "comma-separated attacks")
	flag.StringVar(&opts.protocolVersion, "protocol-version", version.ProtocolVersion, "protocol version")
	flag.Parse()

	if opts.manager == "" || opts.network == "" || opts.attacks == "" {
		fatal(" --manager, --network, and --attacks are required")
	}
	for _, attack := range strings.Split(opts.attacks, ",") {
		attack = strings.TrimSpace(attack)
		if attack == "" {
			continue
		}
		if err := runAttack(context.Background(), attack, opts); err != nil {
			fatal(fmt.Sprintf("%s: %v", attack, err))
		}
		fmt.Printf("OK: %s rejected or remained within its security boundary\n", attack)
	}
}

func runAttack(ctx context.Context, attack string, opts options) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	node, target, err := connectedNode(ctx, opts.manager)
	if err != nil {
		return err
	}
	defer node.Close()

	switch attack {
	case "unauthorized-admin":
		return unauthorizedAdmin(ctx, node, target.ID)
	case "setup-key-bruteforce":
		return setupKeyBruteforce(ctx, node, target.ID, opts)
	case "state-update-spoof":
		return stateUpdateSpoof(ctx, node, target.ID, opts)
	case "oversized-control":
		return oversizedControl(ctx, node, target.ID)
	case "quota-spoof":
		return quotaSpoof(ctx, node, target.ID, opts)
	case "forward-spoof":
		return forwardSpoof(ctx, node, target.ID, opts)
	case "manager-join-token":
		return managerJoinToken(ctx, node, target.ID, opts)
	default:
		return fmt.Errorf("unknown attack")
	}
}

func connectedNode(ctx context.Context, managerAddress string) (*p2p.Node, *peer.AddrInfo, error) {
	node, err := p2p.New(ctx, p2p.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("create attacker host: %w", err)
	}
	target, err := peer.AddrInfoFromString(managerAddress)
	if err != nil {
		_ = node.Close()
		return nil, nil, fmt.Errorf("parse manager address: %w", err)
	}
	if err := node.Host.Connect(ctx, *target); err != nil {
		_ = node.Close()
		return nil, nil, fmt.Errorf("connect manager: %w", err)
	}
	return node, target, nil
}

func unauthorizedAdmin(ctx context.Context, node *p2p.Node, managerID peer.ID) error {
	stream, err := node.Host.NewStream(ctx, managerID, p2p.AdminProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	request := wire.AdminRequestToProto("wrong-admin-token", model.StateTransition{Type: bft.TransitionGenesis})
	if err := p2p.WriteMessage(stream, p2p.AdminProtocol, request); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	response, err := readAdminResponse(stream)
	if err != nil {
		return err
	}
	if response.GetError() == "" || response.GetSnapshot() != nil {
		return fmt.Errorf("wrong admin token was accepted: error=%q snapshot=%v", response.GetError(), response.GetSnapshot() != nil)
	}
	return nil
}

func setupKeyBruteforce(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) error {
	var lastMessage string
	var lastCode string
	for attempt := 1; attempt <= 6; attempt++ {
		request := protocol.LoginRequest{
			NetworkID: opts.network, SetupKey: "wrong-setup-key",
			PeerID: node.Host.ID().String(), ProtocolVersion: opts.protocolVersion,
		}
		response, err := sendLogin(ctx, node, managerID, request)
		if err != nil {
			return fmt.Errorf("attempt %d: %w", attempt, err)
		}
		lastMessage, lastCode = response.Error, response.Code
		if attempt < 6 && (response.Code != protocol.CodeInvalidSetupKey || response.Error == "") {
			return fmt.Errorf("attempt %d unexpectedly accepted or classified: code=%q error=%q", attempt, response.Code, response.Error)
		}
	}
	if !strings.Contains(lastMessage, "rate limit") || lastCode != protocol.CodeInvalidSetupKey {
		return fmt.Errorf("sixth setup-key attempt was not rate limited: code=%q error=%q", lastCode, lastMessage)
	}
	return nil
}

func stateUpdateSpoof(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) error {
	before, err := certifiedHeight(ctx, node, managerID, opts)
	if err != nil {
		return fmt.Errorf("read height before spoof: %w", err)
	}
	stream, err := node.Host.NewStream(ctx, managerID, p2p.StateUpdateProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	message := model.CommitteeEnvelope{
		Type: "forward", Transition: &model.StateTransition{Type: bft.TransitionGenesis},
	}
	if err := p2p.WriteMessage(stream, p2p.StateUpdateProtocol, wire.CommitteeEnvelopeToProto(message)); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	time.Sleep(500 * time.Millisecond)
	after, err := certifiedHeight(ctx, node, managerID, opts)
	if err != nil {
		return fmt.Errorf("read height after spoof: %w", err)
	}
	if after != before {
		return fmt.Errorf("non-committee transition changed height from %d to %d", before, after)
	}
	return nil
}

func oversizedControl(ctx context.Context, node *p2p.Node, managerID peer.ID) error {
	stream, err := node.Host.NewStream(ctx, managerID, p2p.AdminProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	identifier := p2p.AdminProtocol
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(identifier)))
	if _, err := stream.Write(header); err != nil {
		return err
	}
	if _, err := stream.Write([]byte(identifier)); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header, uint32(p2p.MaxEnvelopePayloadLength+1))
	if _, err := stream.Write(header); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	return nil
}

func quotaSpoof(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) error {
	if opts.victimPeer == "" || opts.budgetID == "" {
		return fmt.Errorf("--victim-peer and --budget-id are required")
	}
	report := protocol.QuotaReport{
		PeerID: opts.victimPeer, ReportedAt: time.Now().UTC(),
		ProtocolVersion: opts.protocolVersion,
		Increments:      []protocol.BudgetIncrement{{BudgetID: opts.budgetID, Bytes: 4096}},
	}
	return node.Send(ctx, managerID, p2p.QuotaProtocol, wire.QuotaReportToProto(report))
}

func forwardSpoof(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) error {
	if opts.assignmentID == "" || opts.pathID == "" || opts.sourcePeer == "" || opts.destination == "" {
		return fmt.Errorf("--assignment-id, --path-id, --source-peer, and --destination-peer are required")
	}
	envelope, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: opts.sourcePeer, DestinationPeerID: opts.destination,
			AssignmentID: opts.assignmentID, PathID: opts.pathID, TTL: forward.DefaultTTL,
		},
		Payload: []byte("security-forward-spoof"),
	})
	if err != nil {
		return err
	}
	stream, err := node.Host.NewStream(ctx, managerID, p2p.FrameProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := transport.WriteEnvelopeFrame(stream, envelope); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	return nil
}

func managerJoinToken(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) error {
	if opts.joinToken == "" {
		return fmt.Errorf("--join-token is required")
	}
	if _, err := manager.QueryAdmin(ctx, node, managerID, opts.joinToken, "snapshot"); err != nil {
		return fmt.Errorf("valid join token could not perform its allowed snapshot query: %w", err)
	}
	if _, err := manager.SubmitAdmin(ctx, node, managerID, opts.joinToken, model.StateTransition{Type: bft.TransitionGenesis}); err == nil {
		return fmt.Errorf("join token submitted an administrative transition")
	}
	lastError := ""
	for attempt := 0; attempt < 30; attempt++ {
		_, err := manager.QueryAdmin(ctx, node, managerID, "wrong-join-token-"+strings.Repeat("x", attempt+1), "snapshot")
		if err == nil {
			return fmt.Errorf("wrong join token was accepted on attempt %d", attempt+1)
		}
		lastError = err.Error()
	}
	if !strings.Contains(lastError, "rate limit") {
		return fmt.Errorf("join-token brute force was not rate limited: %v", lastError)
	}
	return nil
}

func certifiedHeight(ctx context.Context, node *p2p.Node, managerID peer.ID, opts options) (uint64, error) {
	if opts.adminToken == "" {
		return 0, fmt.Errorf("--admin-token is required")
	}
	payload, err := manager.QueryAdmin(ctx, node, managerID, opts.adminToken, "snapshot")
	if err != nil {
		return 0, err
	}
	var snapshot struct {
		Height uint64 `json:"height"`
	}
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return 0, err
	}
	return snapshot.Height, nil
}

func sendLogin(ctx context.Context, node *p2p.Node, managerID peer.ID, request protocol.LoginRequest) (protocol.LoginResponse, error) {
	stream, err := node.Host.NewStream(ctx, managerID, p2p.LoginProtocol)
	if err != nil {
		return protocol.LoginResponse{}, err
	}
	defer stream.Close()
	if err := p2p.WriteMessage(stream, p2p.LoginProtocol, wire.LoginRequestToProto(request)); err != nil {
		return protocol.LoginResponse{}, err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return protocol.LoginResponse{}, err
	}
	var message pb.LoginResponse
	if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
		return protocol.LoginResponse{}, err
	}
	return wire.LoginResponseFromProto(&message), nil
}

func readAdminResponse(stream network.Stream) (*pb.AdminResponse, error) {
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return nil, err
	}
	var message pb.AdminResponse
	if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
		return nil, err
	}
	return &message, nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "FAIL: "+message)
	os.Exit(1)
}
