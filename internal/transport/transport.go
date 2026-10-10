package transport

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/netp2p/netp2p/internal/forward"
)

const (
	defaultQueueDepth = 1024
	minBackoff        = 250 * time.Millisecond
	maxBackoff        = 5 * time.Second
	writeDeadline     = 5 * time.Second
)

// ErrQueueFull reports that the per-peer send queue was full and the frame was
// dropped. Callers treat it as backpressure rather than a fatal error.
var ErrQueueFull = errors.New("frame queue full")

// PacketHandler receives a decoded frame from a remote peer.
type PacketHandler func(remote peer.ID, payload []byte)

// EnvelopeHandler receives a binary forwarding frame without decoding it. The
// forwarding codec lives with the forwarding table so client and manager cannot
// drift apart.
type EnvelopeHandler func(remote peer.ID, wire []byte)

type outboundFrame struct {
	protocol string
	payload  []byte
}

// Transport multiplexes framed overlay packets over persistent libp2p streams,
// one outbound stream per remote peer.
type Transport struct {
	host       host.Host
	protocol   protocol.ID
	onPacket   PacketHandler
	onEnvelope EnvelopeHandler
	depth      int

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  map[peer.ID]*frameConn
	closed bool
}

// New installs the inbound stream handler and returns a Transport bound to ctx.
func New(ctx context.Context, node host.Host, protocolID protocol.ID, onPacket PacketHandler) *Transport {
	return NewWithEnvelope(ctx, node, protocolID, onPacket, nil)
}

func NewWithEnvelope(ctx context.Context, node host.Host, protocolID protocol.ID, onPacket PacketHandler, onEnvelope EnvelopeHandler) *Transport {
	child, cancel := context.WithCancel(ctx)
	transport := &Transport{
		host:       node,
		protocol:   protocolID,
		onPacket:   onPacket,
		onEnvelope: onEnvelope,
		depth:      defaultQueueDepth,
		ctx:        child,
		cancel:     cancel,
		conns:      make(map[peer.ID]*frameConn),
	}
	node.SetStreamHandler(protocolID, transport.handleStream)
	return transport
}

// Send enqueues a packet for the remote peer, dialing lazily on first use. It
// never blocks: when the queue is full the frame is dropped and ErrQueueFull is
// returned so the data path cannot stall behind one slow peer.
func (transport *Transport) Send(remote peer.ID, payload []byte) error {
	return transport.sendFrame(remote, frameProtocolFor(payload), payload)
}

// SendPacket sends an explicit raw-packet frame.
func (transport *Transport) SendPacket(remote peer.ID, payload []byte) error {
	return transport.sendFrame(remote, ProtocolPacket, payload)
}

// SendEnvelope sends an explicit forwarded-envelope frame.
func (transport *Transport) SendEnvelope(remote peer.ID, payload []byte) error {
	return transport.sendFrame(remote, ProtocolEnvelope, payload)
}

func (transport *Transport) sendFrame(remote peer.ID, protocolID string, payload []byte) error {
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return errors.New("transport closed")
	}
	conn, ok := transport.conns[remote]
	if !ok {
		conn = newFrameConn(transport.ctx, transport.host, transport.protocol, remote, transport.depth)
		transport.conns[remote] = conn
		go conn.run()
	}
	transport.mu.Unlock()
	return conn.send(protocolID, payload)
}

// Stats reports sent and dropped frame counts for one peer. It exists for tests
// and diagnostics.
func (transport *Transport) Stats(remote peer.ID) (sent, dropped uint64) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	conn, ok := transport.conns[remote]
	if !ok {
		return 0, 0
	}
	return conn.sent.Load(), conn.dropped.Load()
}

func (transport *Transport) handleStream(stream network.Stream) {
	defer stream.Close()
	remote := stream.Conn().RemotePeer()
	for {
		frame, err := ReadProtocolFrame(stream)
		if err != nil {
			if transport.ctx.Err() != nil {
				return
			}
			if !errors.Is(err, network.ErrReset) {
				log.Printf("frame stream from %s ended: %v", remote.ShortString(), err)
			}
			return
		}
		switch frame.Protocol {
		case ProtocolPacket:
			if transport.onPacket != nil {
				transport.onPacket(remote, frame.Payload)
			}
		case ProtocolEnvelope:
			if transport.onEnvelope != nil {
				transport.onEnvelope(remote, frame.Payload)
			}
		default:
			log.Printf("frame stream from %s used unknown protocol %q", remote.ShortString(), frame.Protocol)
		}
	}
}

// Close stops every outbound stream and releases the inbound handler.
func (transport *Transport) Close() error {
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return nil
	}
	transport.closed = true
	conns := make([]*frameConn, 0, len(transport.conns))
	for _, conn := range transport.conns {
		conns = append(conns, conn)
	}
	transport.conns = make(map[peer.ID]*frameConn)
	transport.mu.Unlock()

	transport.cancel()
	transport.host.RemoveStreamHandler(transport.protocol)
	for _, conn := range conns {
		conn.close()
	}
	return nil
}

// frameConn owns one persistent outbound stream to a remote peer.
type frameConn struct {
	ctx      context.Context
	host     host.Host
	protocol protocol.ID
	remote   peer.ID
	queue    chan outboundFrame
	done     chan struct{}

	sent    atomic.Uint64
	dropped atomic.Uint64

	mu      sync.Mutex
	stream  network.Stream
	closing bool
}

func newFrameConn(ctx context.Context, node host.Host, protocolID protocol.ID, remote peer.ID, depth int) *frameConn {
	return &frameConn{
		ctx:      ctx,
		host:     node,
		protocol: protocolID,
		remote:   remote,
		queue:    make(chan outboundFrame, depth),
		done:     make(chan struct{}),
	}
}

func (conn *frameConn) send(protocolID string, payload []byte) error {
	limit := MaxProtocolFramePayloadSize
	if protocolID == ProtocolPacket {
		limit = MaxFrameSize
	}
	if protocolID == "" || len(payload) == 0 || len(payload) > limit {
		return errors.New("invalid frame size")
	}
	select {
	case conn.queue <- outboundFrame{protocol: protocolID, payload: payload}:
		return nil
	default:
		conn.dropped.Add(1)
		return ErrQueueFull
	}
}

// run drains the send queue, dialing and redialing the outbound stream as
// needed. Write failures drop the current frame and back off so a peer that is
// unreachable cannot spin the CPU.
func (conn *frameConn) run() {
	backoff := minBackoff
	for {
		select {
		case <-conn.ctx.Done():
			return
		case <-conn.done:
			return
		case frame := <-conn.queue:
			stream, err := conn.outboundStream()
			if err != nil {
				conn.dropped.Add(1)
				if !conn.sleep(backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			backoff = minBackoff
			_ = stream.SetWriteDeadline(time.Now().Add(writeDeadline))
			if err := WriteProtocolFrame(stream, frame.protocol, frame.payload); err != nil {
				conn.resetStream()
				conn.dropped.Add(1)
				continue
			}
			conn.sent.Add(1)
		}
	}
}

func frameProtocolFor(payload []byte) string {
	if len(payload) > 0 && payload[0] == forward.MagicByte {
		if _, err := forward.DecodeEnvelope(payload); err == nil {
			return ProtocolEnvelope
		}
	}
	return ProtocolPacket
}

func (conn *frameConn) outboundStream() (network.Stream, error) {
	conn.mu.Lock()
	stream := conn.stream
	conn.mu.Unlock()
	if stream != nil {
		return stream, nil
	}
	dialContext, cancel := context.WithTimeout(conn.ctx, 10*time.Second)
	defer cancel()
	opened, err := conn.host.NewStream(dialContext, conn.remote, conn.protocol)
	if err != nil {
		return nil, err
	}
	conn.mu.Lock()
	if conn.closing {
		conn.mu.Unlock()
		_ = opened.Reset()
		return nil, errors.New("connection closing")
	}
	conn.stream = opened
	conn.mu.Unlock()
	return opened, nil
}

func (conn *frameConn) resetStream() {
	conn.mu.Lock()
	stream := conn.stream
	conn.stream = nil
	conn.mu.Unlock()
	if stream != nil {
		_ = stream.Reset()
	}
}

func (conn *frameConn) sleep(duration time.Duration) bool {
	select {
	case <-conn.ctx.Done():
		return false
	case <-conn.done:
		return false
	case <-time.After(duration):
		return true
	}
}

func (conn *frameConn) close() {
	conn.mu.Lock()
	if conn.closing {
		conn.mu.Unlock()
		return
	}
	conn.closing = true
	stream := conn.stream
	conn.stream = nil
	conn.mu.Unlock()
	close(conn.done)
	if stream != nil {
		_ = stream.Reset()
	}
}

func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}
