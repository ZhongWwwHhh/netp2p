// Package p2p builds and operates the libp2p host used by both client and manager.
package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/version"
	"google.golang.org/protobuf/proto"
)

// Version is the protocol revision embedded in every libp2p protocol id.
const Version = version.ProtocolVersion

// SyncVersion changes only the sync framing. The response became a oneof in
// 3.1.0, so old clients must negotiate to a different protocol ID.
const SyncVersion = "3.1.0"

const ProtocolPrefix = "/netp2p"

const (
	// MaxProtocolIDLength bounds the protocol identifier in a framed envelope.
	MaxProtocolIDLength = 256
	// MaxEnvelopePayloadLength bounds every control-plane payload before it is
	// allocated or read from an untrusted stream.
	MaxEnvelopePayloadLength = 4 << 20
	controlWriteDeadline     = 30 * time.Second
)

// controlReadDeadline is variable so tests can exercise partial-frame timeouts
// without holding a real libp2p stream open for ten seconds.
var controlReadDeadline = 10 * time.Second

var (
	LoginProtocol       = protocol.ID(ProtocolPrefix + "/control/login/" + Version)
	SyncProtocol        = protocol.ID(ProtocolPrefix + "/control/sync/" + SyncVersion)
	StateUpdateProtocol = protocol.ID(ProtocolPrefix + "/control/state-update/" + Version)
	ProbeProtocol       = protocol.ID(ProtocolPrefix + "/link/probe/" + Version)
	FrameProtocol       = protocol.ID(ProtocolPrefix + "/data/frame/" + Version)
	QuotaProtocol       = protocol.ID(ProtocolPrefix + "/data/quota/" + Version)
	AdminProtocol       = protocol.ID(ProtocolPrefix + "/control/admin/" + Version)
	WebAPIProtocol      = protocol.ID(ProtocolPrefix + "/web-api/" + Version)
	PresenceProtocol    = protocol.ID(ProtocolPrefix + "/presence/" + Version)
	LinkGossipProtocol  = protocol.ID(ProtocolPrefix + "/link/gossip/" + Version)
	WebSessionProtocol  = protocol.ID(ProtocolPrefix + "/control/web-session/" + Version)
	DKGProtocol         = protocol.ID(ProtocolPrefix + "/control/dkg/" + Version)
)

type Config struct {
	DataDir            string          `json:"dataDir"`
	Listen             []string        `json:"listen"`
	WebRTCListen       []string        `json:"webrtcListen,omitempty"`
	StaticRelays       []peer.AddrInfo `json:"staticRelays,omitempty"`
	EnableRelayService bool            `json:"enableRelayService,omitempty"`
	Bootstraps         []string        `json:"bootstraps"`
	IdentitySeed       int64           `json:"identitySeed,omitempty"`
	// Identity is an explicit in-memory private key. It takes precedence over
	// DataDir and IdentitySeed and is never written back to disk.
	Identity crypto.PrivKey `json:"-"`
}

type Node struct {
	Host host.Host
	// sendHook, when set, wraps every outbound control-plane send. Tests use it
	// to inject drops, delays and duplication; production nodes leave it nil so
	// there is no overhead on the hot path.
	sendHook SendHook
}

// SendFunc delivers one already-marshalled control-plane message.
type SendFunc func(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message) error

// SendHook intercepts an outbound control-plane send. Implementations must call
// next to deliver the message (possibly zero or many times) and are responsible
// for honouring ctx.
type SendHook func(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message, next SendFunc) error

// SetSendHook installs an outbound interceptor. It must be called before the
// node starts exchanging control messages.
func (node *Node) SetSendHook(hook SendHook) {
	node.sendHook = hook
}

// New creates a libp2p host. QUIC is enabled where available; TCP remains a
// practical bootstrap/listener fallback and is not used as an overlay transport
// protocol.
func New(ctx context.Context, config Config) (*Node, error) {
	var privateKey crypto.PrivKey
	var err error
	if config.Identity != nil {
		privateKey = config.Identity
	} else if config.IdentitySeed != 0 {
		privateKey, err = LoadOrCreateSeededIdentity(config.DataDir, config.IdentitySeed)
	} else {
		privateKey, err = LoadOrCreateIdentity(config.DataDir)
	}
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(config.Listen))
	addresses = append(addresses, config.Listen...)
	addresses = append(addresses, config.WebRTCListen...)
	if len(addresses) == 0 {
		addresses = []string{"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"}
	}
	listenAddrs := make([]multiaddr.Multiaddr, 0, len(addresses))
	for _, value := range addresses {
		address, parseErr := multiaddr.NewMultiaddr(value)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid listen address %q: %w", value, parseErr)
		}
		listenAddrs = append(listenAddrs, address)
	}
	opts := []libp2p.Option{
		libp2p.Identity(privateKey),
		libp2p.ListenAddrs(listenAddrs...),
		libp2p.EnableHolePunching(),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableRelay(),
	}
	if len(config.StaticRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(config.StaticRelays))
	}
	if config.EnableRelayService {
		opts = append(opts, libp2p.EnableRelayService())
	}
	libp2pHost, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}
	return &Node{Host: libp2pHost}, nil
}

func (node *Node) WebRTCAddresses() []string {
	result := make([]string, 0)
	for _, address := range node.Host.Addrs() {
		protocols := address.Protocols()
		hasWebRTC := false
		for _, protocol := range protocols {
			if protocol.Name == "webrtc-direct" {
				hasWebRTC = true
				break
			}
		}
		if !hasWebRTC {
			continue
		}
		result = append(result, fmt.Sprintf("%s/p2p/%s", address.String(), node.Host.ID()))
	}
	return result
}

// IdentityPublicKey returns the host's raw Ed25519 public key, which lets the
// browser authenticate this manager after the HTTP-only bootstrap step.
func (node *Node) IdentityPublicKey() ([]byte, error) {
	publicKey, err := node.Host.ID().ExtractPublicKey()
	if err != nil {
		return nil, fmt.Errorf("extract identity public key: %w", err)
	}
	raw, err := publicKey.Raw()
	if err != nil {
		return nil, fmt.Errorf("serialize identity public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity key is not Ed25519")
	}
	return raw, nil
}

func identityPath(dataDir string) string {
	return filepath.Join(dataDir, "identity.key")
}

func LoadOrCreateIdentity(dataDir string) (crypto.PrivKey, error) {
	return loadOrCreateIdentity(dataDir, 0)
}

func LoadOrCreateSeededIdentity(dataDir string, seed int64) (crypto.PrivKey, error) {
	return loadOrCreateIdentity(dataDir, seed)
}

func loadOrCreateIdentity(dataDir string, seed int64) (crypto.PrivKey, error) {
	if dataDir == "" {
		privateKey, _, err := crypto.GenerateEd25519Key(seedReader(seed))
		return privateKey, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := identityPath(dataDir)
	data, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	privateKey, _, err := crypto.GenerateEd25519Key(seedReader(seed))
	if err != nil {
		return nil, err
	}
	encoded, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func seedReader(seed int64) io.Reader {
	if seed == 0 {
		return rand.Reader
	}
	seedBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedBytes, uint64(seed))
	hash := sha256.Sum256(seedBytes)
	return bytes.NewReader(hash[:])
}

func (node *Node) Addresses() []string {
	result := make([]string, 0)
	for _, address := range node.Host.Addrs() {
		result = append(result, fmt.Sprintf("%s/p2p/%s", address, node.Host.ID()))
	}
	return result
}

func (node *Node) Handle(id protocol.ID, handler func(network.Stream)) {
	node.Host.SetStreamHandler(id, handler)
}

// ControlReadDeadline exposes the framed control-plane read budget so
// long-poll protocols can keep their heartbeat cadence safely inside it.
func ControlReadDeadline() time.Duration {
	return controlReadDeadline
}

type Envelope struct {
	Protocol protocol.ID
	Payload  []byte
}

// EncodeEnvelope writes a length-prefixed protocol id and payload. Both lengths
// are explicit so a reader never has to wait for EOF, which keeps
// request/response exchanges on a single stream working. Control-plane payloads
// are protobuf messages; data-plane framing lives in internal/transport.
func EncodeEnvelope(writer io.Writer, id protocol.ID, payload []byte) error {
	if len(id) > MaxProtocolIDLength {
		return fmt.Errorf("protocol id too long: %d", len(id))
	}
	if len(payload) > MaxEnvelopePayloadLength {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	if deadlineSetter, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := deadlineSetter.SetWriteDeadline(time.Now().Add(controlWriteDeadline)); err != nil {
			return fmt.Errorf("set control write deadline: %w", err)
		}
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(id)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, string(id)); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// WriteMessage marshals a protobuf message and frames it as an envelope. It is
// used to write responses on a stream opened for a request/response exchange.
func WriteMessage(writer io.Writer, id protocol.ID, message proto.Message) error {
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	return EncodeEnvelope(writer, id, payload)
}

func (node *Node) Send(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message) error {
	if node.sendHook != nil {
		return node.sendHook(ctx, peerID, id, message, node.sendDirect)
	}
	return node.sendDirect(ctx, peerID, id, message)
}

func (node *Node) sendDirect(ctx context.Context, peerID peer.ID, id protocol.ID, message proto.Message) error {
	stream, err := node.Host.NewStream(ctx, peerID, id)
	if err != nil {
		return fmt.Errorf("open %s stream: %w", id, err)
	}
	defer stream.Close()
	if err := WriteMessage(stream, id, message); err != nil {
		return err
	}
	// CloseWrite tells the remote handler the request body is complete while
	// keeping the libp2p stream open for a response.
	if fullStream, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = fullStream.CloseWrite()
	}
	if id == StateUpdateProtocol {
		// Committee messages need delivery evidence, not merely a successful
		// QUIC write. State-update handlers close their stream after validation
		// and side effects, so EOF is the minimal stream-level acknowledgement.
		_ = stream.SetReadDeadline(time.Now().Add(time.Second))
		var ack [1]byte
		if _, err := stream.Read(ack[:]); err == nil {
			return fmt.Errorf("unexpected state-update response")
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("wait for state-update acknowledgement: %w", err)
		}
	}
	return nil
}

func DecodeEnvelope(stream network.Stream) (Envelope, error) {
	if err := stream.SetReadDeadline(time.Now().Add(controlReadDeadline)); err != nil {
		return Envelope{}, fmt.Errorf("set control read deadline: %w", err)
	}
	reader := io.LimitReader(stream, int64(MaxEnvelopePayloadLength+MaxProtocolIDLength+8))
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Envelope{}, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxProtocolIDLength {
		return Envelope{}, fmt.Errorf("protocol id too long: %d", length)
	}
	identifier := make([]byte, length)
	if _, err := io.ReadFull(reader, identifier); err != nil {
		return Envelope{}, err
	}
	if _, err := io.ReadFull(reader, header); err != nil {
		return Envelope{}, err
	}
	payloadLength := binary.BigEndian.Uint32(header)
	if payloadLength > MaxEnvelopePayloadLength {
		return Envelope{}, fmt.Errorf("payload too large: %d", payloadLength)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Envelope{}, err
	}
	return Envelope{Protocol: protocol.ID(identifier), Payload: payload}, nil
}

func (node *Node) Close() error {
	return node.Host.Close()
}
