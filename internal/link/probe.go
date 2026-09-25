package link

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

const (
	// ProbeKindPing is a minimal request/response used to sample round-trip
	// time, jitter and loss.
	ProbeKindPing = "ping"
	// ProbeKindBandwidth asks the responder to read a burst of Bytes from the
	// stream and acknowledge how much it received.
	ProbeKindBandwidth = "bandwidth"

	probeSamples           = 5
	defaultProbeInterval   = 15 * time.Second
	defaultProbeTimeout    = 2000 * time.Millisecond
	defaultBandwidthBudget = 128 * 1024
	minBandwidthBurst      = 32 * 1024
	maxProbeFrame          = 1 << 20
	maxProbeBurst          = 4 << 20
	probeResponderDeadline = 30 * time.Second
)

// ProbeRequest is the JSON header of a probe stream. A bandwidth probe is
// followed by exactly Bytes raw bytes on the same stream.
type ProbeRequest struct {
	Kind  string `json:"kind"`
	Nonce uint64 `json:"nonce"`
	Bytes int    `json:"bytes,omitempty"`
}

type ProbeReply struct {
	Nonce         uint64 `json:"nonce"`
	ReceivedBytes int    `json:"receivedBytes"`
}

// ProbeResponder answers link probes. Managers and clients both install it, so
// a manager can measure the access link to the clients it serves.
type ProbeResponder struct{}

func NewProbeResponder() *ProbeResponder { return &ProbeResponder{} }

func (responder *ProbeResponder) Handle(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(probeResponderDeadline))
	payload, err := readProbeFrame(stream)
	if err != nil {
		return
	}
	var request ProbeRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return
	}
	reply := ProbeReply{Nonce: request.Nonce}
	if request.Kind == ProbeKindBandwidth && request.Bytes > 0 {
		expected := request.Bytes
		if expected > maxProbeBurst {
			expected = maxProbeBurst
		}
		read, err := io.CopyN(io.Discard, stream, int64(expected))
		if err != nil {
			return
		}
		reply.ReceivedBytes = int(read)
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		return
	}
	_ = writeProbeFrame(stream, encoded)
}

func writeProbeFrame(writer io.Writer, payload []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func readProbeFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > maxProbeFrame {
		return nil, errors.New("probe frame too large")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// Prober actively measures the manager mesh and its client access links. It
// never trusts client-reported measurements: only the numbers this manager
// observed itself are published, and the manager mesh matrix ignores anything
// else.
type Prober struct {
	node      *p2p.Node
	state     func() model.NetworkState
	committee func() []model.CommitteeMember
	gossiper  *Gossiper
	localID   string
	cycle     int
}

func NewProber(node *p2p.Node, state func() model.NetworkState, committee func() []model.CommitteeMember, gossiper *Gossiper) *Prober {
	return &Prober{
		node: node, state: state, committee: committee, gossiper: gossiper,
		localID: node.Host.ID().String(),
	}
}

// Run measures once immediately (so certified paths do not wait a full
// interval) and then on the certified probe interval until ctx is cancelled.
func (prober *Prober) Run(ctx context.Context) {
	for {
		settings := prober.state().Settings
		prober.ProbeOnce(ctx, settings)
		select {
		case <-ctx.Done():
			return
		case <-time.After(ProbeInterval(settings)):
		}
	}
}

type probeTarget struct {
	peerID peer.ID
	scope  Scope
}

// ProbeOnce measures every reachable manager and client once and publishes the
// result. The total bandwidth burst per cycle is bounded by the certified
// budget; targets rotate so a limited budget is spread fairly over time.
func (prober *Prober) ProbeOnce(ctx context.Context, settings model.NetworkSettings) {
	targets := prober.targets()
	if len(targets) == 0 {
		return
	}
	timeout := ProbeTimeout(settings)
	budget := ProbeBudgetBytes(settings)
	observations := make([]Observation, 0, len(targets))
	start := prober.cycle % len(targets)
	prober.cycle++
	for offset := range targets {
		target := targets[(start+offset)%len(targets)]
		observation, used := prober.probeTarget(ctx, target, timeout, budget)
		budget -= used
		if budget < 0 {
			budget = 0
		}
		if observation != nil {
			observations = append(observations, *observation)
		}
	}
	if len(observations) > 0 {
		prober.gossiper.Publish(observations)
	}
}

func (prober *Prober) targets() []probeTarget {
	state := prober.state()
	committeeIDs := make(map[string]struct{})
	targets := make([]probeTarget, 0)
	for _, member := range prober.committee() {
		if member.PeerID == "" || member.PeerID == prober.localID {
			continue
		}
		committeeIDs[member.PeerID] = struct{}{}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			continue
		}
		targets = append(targets, probeTarget{peerID: peerID, scope: ScopeManagerMesh})
	}
	for _, record := range state.Peers {
		if record.PeerID == "" || record.PeerID == prober.localID {
			continue
		}
		if _, isManager := committeeIDs[record.PeerID]; isManager {
			continue
		}
		peerID, err := peer.Decode(record.PeerID)
		if err != nil {
			continue
		}
		targets = append(targets, probeTarget{peerID: peerID, scope: ScopeAccess})
	}
	return targets
}

func (prober *Prober) probeTarget(ctx context.Context, target probeTarget, timeout time.Duration, budget int) (*Observation, int) {
	samples := make([]time.Duration, 0, probeSamples)
	for attempt := 0; attempt < probeSamples; attempt++ {
		if ctx.Err() != nil {
			break
		}
		elapsed, err := prober.ping(ctx, target.peerID, timeout)
		if err != nil {
			continue
		}
		samples = append(samples, elapsed)
	}
	// No reply at all means the peer is currently unreachable; publishing a
	// zero-latency, 100%-loss segment would make an unusable path look
	// attractive, so omit the segment entirely.
	if len(samples) == 0 {
		return nil, 0
	}
	rtt, jitter, loss := summarizePings(samples, probeSamples)
	observation := &Observation{
		ObserverID: prober.localID, SubjectID: target.peerID.String(), Scope: target.scope,
		Direction: DirectionRoundTrip, RTTMilliseconds: rtt, LossPercent: loss,
		JitterMilliseconds: jitter, Samples: probeSamples,
		MeasuredAt: time.Now().UTC(), Sequence: uint64(time.Now().UnixNano()),
	}
	if budget < minBandwidthBurst {
		return observation, 0
	}
	burst := budget
	if burst > defaultBandwidthBudget {
		burst = defaultBandwidthBudget
	}
	if elapsed, received, err := prober.bandwidth(ctx, target.peerID, timeout, burst); err == nil && received > 0 {
		observation.BandwidthMbps = bandwidthMbps(received, elapsed)
	}
	return observation, burst
}

func (prober *Prober) ping(ctx context.Context, target peer.ID, timeout time.Duration) (time.Duration, error) {
	stream, err := prober.openProbeStream(ctx, target, timeout)
	if err != nil {
		return 0, err
	}
	defer stream.Close()
	start := time.Now()
	if err := writeProbeRequest(stream, ProbeRequest{Kind: ProbeKindPing, Nonce: nextNonce()}, nil); err != nil {
		return 0, err
	}
	if _, err := readProbeReply(stream); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func (prober *Prober) bandwidth(ctx context.Context, target peer.ID, timeout time.Duration, burstBytes int) (time.Duration, int, error) {
	stream, err := prober.openProbeStream(ctx, target, timeout)
	if err != nil {
		return 0, 0, err
	}
	defer stream.Close()
	burst := make([]byte, burstBytes)
	start := time.Now()
	request := ProbeRequest{Kind: ProbeKindBandwidth, Nonce: nextNonce(), Bytes: burstBytes}
	if err := writeProbeRequest(stream, request, burst); err != nil {
		return 0, 0, err
	}
	reply, err := readProbeReply(stream)
	if err != nil {
		return 0, 0, err
	}
	return time.Since(start), reply.ReceivedBytes, nil
}

func (prober *Prober) openProbeStream(ctx context.Context, target peer.ID, timeout time.Duration) (network.Stream, error) {
	attemptContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, err := prober.node.Host.NewStream(attemptContext, target, p2p.ProbeProtocol)
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(timeout))
	return stream, nil
}

func writeProbeRequest(stream network.Stream, request ProbeRequest, burst []byte) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := writeProbeFrame(stream, encoded); err != nil {
		return err
	}
	if len(burst) == 0 {
		return nil
	}
	_, err = stream.Write(burst)
	return err
}

func readProbeReply(stream network.Stream) (ProbeReply, error) {
	payload, err := readProbeFrame(stream)
	if err != nil {
		return ProbeReply{}, err
	}
	var reply ProbeReply
	if err := json.Unmarshal(payload, &reply); err != nil {
		return ProbeReply{}, err
	}
	return reply, nil
}

func nextNonce() uint64 {
	return uint64(time.Now().UnixNano())
}

// summarizePings returns the mean RTT, the mean absolute jitter and the loss
// percentage of a probe round.
func summarizePings(samples []time.Duration, sent int) (rttMs, jitterMs, lossPct float64) {
	if sent <= 0 {
		sent = len(samples)
	}
	if len(samples) == 0 || sent <= 0 {
		return 0, 0, 100
	}
	total := 0.0
	for _, sample := range samples {
		total += sample.Seconds() * 1000
	}
	rttMs = total / float64(len(samples))
	if len(samples) > 1 {
		delta := 0.0
		for index := 1; index < len(samples); index++ {
			delta += math.Abs((samples[index] - samples[index-1]).Seconds()) * 1000
		}
		jitterMs = delta / float64(len(samples)-1)
	}
	lossPct = float64(sent-len(samples)) / float64(sent) * 100
	if lossPct < 0 {
		lossPct = 0
	}
	return rttMs, jitterMs, lossPct
}

// bandwidthMbps converts an observed burst into a throughput estimate.
func bandwidthMbps(bytes int, elapsed time.Duration) float64 {
	if bytes <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(bytes*8) / elapsed.Seconds() / 1e6
}

// ProbeInterval is the certified probe cadence, defaulting to 15s.
func ProbeInterval(settings model.NetworkSettings) time.Duration {
	seconds := settings.LinkProbeIntervalSeconds
	if seconds <= 0 {
		return defaultProbeInterval
	}
	return time.Duration(seconds) * time.Second
}

// ProbeTimeout is the per-attempt probe deadline, defaulting to 2s.
func ProbeTimeout(settings model.NetworkSettings) time.Duration {
	milliseconds := settings.LinkProbeTimeoutMs
	if milliseconds <= 0 {
		return defaultProbeTimeout
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// ProbeBudgetBytes is the total bandwidth-probe budget per cycle, defaulting to
// 128 KiB.
func ProbeBudgetBytes(settings model.NetworkSettings) int {
	kilobytes := settings.ProbeBandwidthBudgetKB
	if kilobytes <= 0 {
		return defaultBandwidthBudget
	}
	return kilobytes * 1024
}
