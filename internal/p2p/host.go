// Package p2p builds and operates the libp2p host used by both client and manager.
package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

const ProtocolPrefix = "/netp2p"

var (
	LoginProtocol       = protocol.ID(ProtocolPrefix + "/control/login/1.0.0")
	SyncProtocol        = protocol.ID(ProtocolPrefix + "/control/sync/1.0.0")
	StateUpdateProtocol = protocol.ID(ProtocolPrefix + "/control/state-update/1.0.0")
	ProbeProtocol       = protocol.ID(ProtocolPrefix + "/link/probe/1.0.0")
	FrameProtocol       = protocol.ID(ProtocolPrefix + "/data/frame/1.0.0")
	QuotaProtocol       = protocol.ID(ProtocolPrefix + "/data/quota/1.0.0")
	AdminProtocol       = protocol.ID(ProtocolPrefix + "/control/admin/1.0.0")
)

type Config struct {
	DataDir      string   `json:"dataDir"`
	Listen       []string `json:"listen"`
	Bootstraps   []string `json:"bootstraps"`
	IdentitySeed int64    `json:"identitySeed,omitempty"`
}

type Node struct {
	Host host.Host
}

// New creates a libp2p host. QUIC is enabled where available; TCP remains a
// practical bootstrap/listener fallback and is not used as an overlay transport
// protocol.
func New(ctx context.Context, config Config) (*Node, error) {
	var privateKey crypto.PrivKey
	var err error
	if config.IdentitySeed != 0 {
		privateKey, err = LoadOrCreateSeededIdentity(config.DataDir, config.IdentitySeed)
	} else {
		privateKey, err = LoadOrCreateIdentity(config.DataDir)
	}
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(config.Listen))
	addresses = append(addresses, config.Listen...)
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
	libp2pHost, err := libp2p.New(libp2p.Identity(privateKey), libp2p.ListenAddrs(listenAddrs...))
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}
	return &Node{Host: libp2pHost}, nil
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

type Envelope struct {
	Protocol protocol.ID     `json:"protocol"`
	Payload  json.RawMessage `json:"payload"`
}

func (node *Node) Send(ctx context.Context, peerID peer.ID, id protocol.ID, payload any) error {
	stream, err := node.Host.NewStream(ctx, peerID, id)
	if err != nil {
		return fmt.Errorf("open %s stream: %w", id, err)
	}
	defer stream.Close()
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	envelope := Envelope{Protocol: id, Payload: encoded}
	if err := json.NewEncoder(stream).Encode(envelope); err != nil {
		return err
	}
	// CloseWrite tells the remote handler the request body is complete while
	// keeping the libp2p stream open for a response.
	if fullStream, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = fullStream.CloseWrite()
	}
	return nil
}

func DecodeEnvelope(stream network.Stream) (Envelope, error) {
	var envelope Envelope
	err := json.NewDecoder(io.LimitReader(stream, 8<<20)).Decode(&envelope)
	return envelope, err
}

func (node *Node) Close() error {
	return node.Host.Close()
}
