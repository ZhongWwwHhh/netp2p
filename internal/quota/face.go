package quota

import (
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/path"
)

const (
	defaultFaceReserveFraction = 0.10
	defaultRealtimeShare       = 0.20
	defaultFaceQueueLow        = 0.30
	defaultFaceQueueHigh       = 0.70
	minimumFaceBackoff         = 0.10
	maximumFaceBackoff         = 1.0
)

// FaceConfig is the certified manager-side capacity profile for one outbound
// face. Runtime queue pressure does not replace this limit; it multiplies it.
type FaceConfig struct {
	FaceID                 string
	CapacityBytesPerSecond uint64
	ReserveFraction        float64
	RealtimeShare          float64
	QueueLow               float64
	QueueHigh              float64
}

type classBucket struct {
	class       path.FlowClass
	rate        float64
	reserved    bool
	tokenBucket *TokenBucket
}

type faceBudget struct {
	config       FaceConfig
	queueEWMA    float64
	backoff      float64
	lastObserved time.Time
	classes      map[path.FlowClass]*classBucket
}

// FaceBudgetSet enforces the local fast loop on every manager face. A
// modified client cannot bypass a RoutingEpoch by ignoring its local weights.
type FaceBudgetSet struct {
	mu      sync.Mutex
	faces   map[string]*faceBudget
	NowFunc func() time.Time
}

func NewFaceBudgetSet(configs []FaceConfig) (*FaceBudgetSet, error) {
	set := &FaceBudgetSet{faces: make(map[string]*faceBudget), NowFunc: time.Now}
	if err := set.Replace(configs); err != nil {
		return nil, err
	}
	return set, nil
}

func (set *FaceBudgetSet) Replace(configs []FaceConfig) error {
	normalized := make(map[string]FaceConfig, len(configs))
	for _, config := range configs {
		if config.FaceID == "" {
			return errors.New("face id is required")
		}
		if config.CapacityBytesPerSecond == 0 {
			return errors.New("face capacity must be positive")
		}
		if config.ReserveFraction < 0 || config.ReserveFraction >= 1 {
			config.ReserveFraction = defaultFaceReserveFraction
		}
		if config.RealtimeShare <= 0 || config.RealtimeShare >= 1 {
			config.RealtimeShare = defaultRealtimeShare
		}
		if config.QueueLow <= 0 {
			config.QueueLow = defaultFaceQueueLow
		}
		if config.QueueHigh <= config.QueueLow || config.QueueHigh >= 1 {
			config.QueueHigh = defaultFaceQueueHigh
		}
		if _, exists := normalized[config.FaceID]; exists {
			return errors.New("duplicate face id")
		}
		normalized[config.FaceID] = config
	}

	set.mu.Lock()
	defer set.mu.Unlock()
	now := set.nowLocked()
	for id, config := range normalized {
		if existing, ok := set.faces[id]; ok {
			existing.config = config
			continue
		}
		set.faces[id] = newFaceBudget(config, now)
	}
	for id := range set.faces {
		if _, ok := normalized[id]; !ok {
			delete(set.faces, id)
		}
	}
	return nil
}

func newFaceBudget(config FaceConfig, now time.Time) *faceBudget {
	face := &faceBudget{
		config: config, backoff: 1,
		classes: make(map[path.FlowClass]*classBucket, 5),
	}
	for _, class := range []path.FlowClass{path.FlowLatency, path.FlowThroughput, path.FlowCost, path.FlowReliability, path.FlowRealtime} {
		face.classes[class] = &classBucket{class: class, reserved: class == path.FlowRealtime}
	}
	return face
}

type FaceFeedback struct {
	FaceID             string        `json:"faceId"`
	Congested          bool          `json:"congested"`
	QueueDepthEWMA     float64       `json:"queueDepthEwma"`
	Backoff            float64       `json:"backoff"`
	RateBytesPerSecond float64       `json:"rateBytesPerSecond"`
	SuggestedWait      time.Duration `json:"suggestedWait,omitempty"`
}

// ObserveQueue updates the face's queue-pressure EWMA and congestion backoff.
// depth and capacity are queue entries, not bytes.
func (set *FaceBudgetSet) ObserveQueue(faceID string, depth, capacity uint64, now time.Time) (FaceFeedback, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	face, ok := set.faces[faceID]
	if !ok {
		return FaceFeedback{}, errors.New("unknown face")
	}
	if capacity == 0 {
		return FaceFeedback{}, errors.New("face queue capacity must be positive")
	}
	pressure := float64(depth) / float64(capacity)
	if face.lastObserved.IsZero() {
		face.queueEWMA = pressure
	} else {
		face.queueEWMA = 0.7*face.queueEWMA + 0.3*pressure
	}
	face.lastObserved = now
	switch {
	case face.queueEWMA < face.config.QueueLow:
		face.backoff = math.Min(maximumFaceBackoff, face.backoff*1.05)
	case face.queueEWMA >= face.config.QueueHigh*1.5:
		face.backoff = math.Max(minimumFaceBackoff, face.backoff*0.60)
	case face.queueEWMA >= face.config.QueueHigh:
		face.backoff = math.Max(minimumFaceBackoff, face.backoff*0.85)
	}
	return face.feedback(), nil
}

// Admit consumes tokens only when a frame can be sent immediately. A delayed
// decision leaves tokens untouched because the manager forwarding path drops
// rather than queues the frame. Realtime receives a protected share and a less
// aggressive backoff so ordinary bulk traffic cannot starve it.
func (set *FaceBudgetSet) Admit(faceID string, class path.FlowClass, bytes uint64, now time.Time) Decision {
	set.mu.Lock()
	defer set.mu.Unlock()
	face, ok := set.faces[faceID]
	if !ok {
		return Decision{Allowed: false, Action: ActionBlock, BudgetID: faceID}
	}
	bucket, ok := face.classes[class]
	if !ok {
		return Decision{Allowed: false, Action: ActionBlock, BudgetID: faceID + ":" + string(class)}
	}
	rate := face.admissionRate(bucket)
	bucket.rate = rate
	if bucket.tokenBucket == nil {
		burst := uint64(math.Max(1, rate/10))
		if burst > face.config.CapacityBytesPerSecond {
			burst = face.config.CapacityBytesPerSecond
		}
		bucket.tokenBucket = NewTokenBucket(uint64(rate), burst, now)
	} else {
		bucket.tokenBucket.rate = rate
		if rate > 0 && bucket.tokenBucket.burst > rate {
			bucket.tokenBucket.burst = rate
		}
	}
	allowed, wait := bucket.tokenBucket.Allow(bytes, now, 0)
	if allowed {
		return Decision{Allowed: true, Action: ActionAllow, BudgetID: faceID + ":" + string(class)}
	}
	return Decision{
		Allowed: false, Action: ActionThrottle, BudgetID: faceID + ":" + string(class),
		Delay: wait,
	}
}

func (face *faceBudget) admissionRate(bucket *classBucket) float64 {
	base := float64(face.config.CapacityBytesPerSecond) * (1 - face.config.ReserveFraction)
	share := (1 - face.config.RealtimeShare) / 4
	if bucket.reserved {
		share = face.config.RealtimeShare
	}
	backoff := face.backoff
	if bucket.reserved {
		backoff = math.Max(backoff, 0.5)
	}
	return base * share * backoff
}

func (set *FaceBudgetSet) Feedback(faceID string) (FaceFeedback, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	face, ok := set.faces[faceID]
	if !ok {
		return FaceFeedback{}, errors.New("unknown face")
	}
	return face.feedback(), nil
}

func (set *FaceBudgetSet) Faces() []string {
	set.mu.Lock()
	defer set.mu.Unlock()
	result := make([]string, 0, len(set.faces))
	for faceID := range set.faces {
		result = append(result, faceID)
	}
	sort.Strings(result)
	return result
}

func (face *faceBudget) feedback() FaceFeedback {
	rate := face.admissionRate(face.classes[path.FlowLatency])
	return FaceFeedback{
		FaceID:             face.config.FaceID,
		Congested:          face.queueEWMA >= face.config.QueueHigh,
		QueueDepthEWMA:     face.queueEWMA,
		Backoff:            face.backoff,
		RateBytesPerSecond: rate,
		SuggestedWait:      time.Duration((1 - face.backoff) * float64(time.Second)),
	}
}

func (set *FaceBudgetSet) nowLocked() time.Time {
	if set.NowFunc != nil {
		return set.NowFunc()
	}
	return time.Now()
}
