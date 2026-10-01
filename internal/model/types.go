package model

import (
	"crypto/sha256"
	"time"
)

type CommitteeMember struct {
	ID                string `json:"id"`
	PeerID            string `json:"peerId"`
	Address           string `json:"address"`
	KeySeed           int64  `json:"keySeed,omitempty"`
	PublicKey         []byte `json:"publicKey,omitempty"`
	ListenAddr        string `json:"listenAddr,omitempty"`
	ForwardingEnabled bool   `json:"forwardingEnabled"`
	// BLSPublicKey is the member's threshold-signature share public key. It is
	// derived deterministically from KeySeed in v1; DKG is a later stage.
	BLSPublicKey []byte `json:"blsPublicKey,omitempty"`
}

// CommitteeConfig pins the threshold parameters a snapshot's QC must satisfy.
// Only rotate_committee_keys changes it, and every change bumps CommitteeEpoch.
type CommitteeConfig struct {
	Threshold      uint32 `json:"threshold"`
	Size           uint32 `json:"size"`
	GroupPublicKey []byte `json:"groupPublicKey,omitempty"`
	CommitteeEpoch uint64 `json:"committeeEpoch"`
}

// BudgetUsage is a certified aggregate of client-reported traffic against one
// budget. Periods make the daily/monthly reset deterministic across managers.
type BudgetUsage struct {
	BudgetID     string `json:"budgetId"`
	DailyBytes   uint64 `json:"dailyBytes"`
	MonthlyBytes uint64 `json:"monthlyBytes"`
	// PeriodDay is the UTC day the daily counter belongs to (YYYY-MM-DD).
	PeriodDay string `json:"periodDay,omitempty"`
	// PeriodMonth is the UTC month the monthly counter belongs to (YYYY-MM).
	PeriodMonth string `json:"periodMonth,omitempty"`
}

type PeerRecord struct {
	PeerID        string   `json:"peerId"`
	OverlayIP     string   `json:"overlayIp"`
	Addresses     []string `json:"addresses,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"clientVersion,omitempty"`
	UserID        string   `json:"userId,omitempty"`
	// DNSLabel is the peer's unique name inside the overlay DNS domain,
	// assigned once at registration.
	DNSLabel string `json:"dnsLabel,omitempty"`
	// LastLogin is when the peer last authenticated. SSO-registered peers can
	// be required to re-authenticate periodically.
	LastLogin string `json:"lastLogin,omitempty"`
	// IsExitNode marks a certified client that may forward overlay traffic
	// toward certified subnet destinations. It is admin controlled.
	IsExitNode bool `json:"isExitNode,omitempty"`
}

// NetworkSettings carries network-wide toggles that are part of certified
// state rather than policy.
type NetworkSettings struct {
	// DNSDomain is the search domain and suffix for peer names.
	DNSDomain string `json:"dnsDomain,omitempty"`
	// LoginExpirationDays forces SSO-registered peers to re-authenticate after
	// this many days. Zero disables expiration.
	LoginExpirationDays int `json:"loginExpirationDays,omitempty"`
	// JWTGroupsEnabled turns IdP group claims into managed groups.
	JWTGroupsEnabled bool `json:"jwtGroupsEnabled,omitempty"`
	// JWTGroupsClaimName is the claim holding group names.
	JWTGroupsClaimName string `json:"jwtGroupsClaimName,omitempty"`
	// JWTAllowGroups, when non-empty, restricts access to these IdP groups.
	JWTAllowGroups []string `json:"jwtAllowGroups,omitempty"`
	// Link selection tuning. These thresholds parameterise the scoring
	// function so that via-manager paths must offer a measurable advantage over
	// direct connections before the planner switches away from P2P.
	LinkMinBandwidthMbps         float64 `json:"linkMinBandwidthMbps,omitempty"`
	ViaManagerLatencyAdvantageMs float64 `json:"viaManagerLatencyAdvantageMs,omitempty"`
	ViaManagerLossAdvantagePct   float64 `json:"viaManagerLossAdvantagePct,omitempty"`
	LinkProbeIntervalSeconds     int     `json:"linkProbeIntervalSeconds,omitempty"`
	LinkProbeTimeoutMs           int     `json:"linkProbeTimeoutMs,omitempty"`
	ViaManagerEnabled            bool    `json:"viaManagerEnabled,omitempty"`
	DirectPathEnabled            bool    `json:"directPathEnabled,omitempty"`
	MaxManagerHops               int     `json:"maxManagerHops,omitempty"`
	ProbeBandwidthBudgetKB       int     `json:"probeBandwidthBudgetKb,omitempty"`
	// QuotaEnforcementEnabled turns TrafficBudget enforcement on. With it
	// disabled budgets are still accounted and shown in the console.
	QuotaEnforcementEnabled bool `json:"quotaEnforcementEnabled,omitempty"`
	// QuotaReportIntervalSeconds is how often clients flush usage to the
	// manager. Aggregated settlement into certified state is rate limited
	// separately so reporting cannot churn consensus.
	QuotaReportIntervalSeconds int `json:"quotaReportIntervalSeconds,omitempty"`
	// DefaultFlowClass is the planner's default scoring class when no route or
	// policy overrides it.
	DefaultFlowClass string `json:"defaultFlowClass,omitempty"`
	// ExitNodeEnabled enables subnet/exit routing globally. Individual traffic
	// still requires a certified Route.
	ExitNodeEnabled bool `json:"exitNodeEnabled,omitempty"`
}

type PathKind string

const (
	PathKindDirect     PathKind = "direct"
	PathKindViaManager PathKind = "via_manager"
	PathKindMultiHop   PathKind = "multi_hop"
)

type PathSpec struct {
	ID              string   `json:"id"`
	Kind            PathKind `json:"kind"`
	ManagerHops     []string `json:"managerHops,omitempty"`
	RTTMilliseconds float64  `json:"rttMilliseconds"`
	LossPercent     float64  `json:"lossPercent"`
	BandwidthMbps   float64  `json:"bandwidthMbps"`
	Confidence      float64  `json:"confidence"`
	// Cost is the estimated forwarding cost of this path: the sum of per-hop
	// forwarding cost. It breaks score ties and drives cost-class routing.
	Cost uint64 `json:"cost,omitempty"`
}

func (path PathSpec) Normalized() PathSpec {
	if path.ID == "" {
		path.ID = string(path.Kind)
	}
	path.ManagerHops = dedupe(path.ManagerHops)
	return path
}

func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

type RouteAssignment struct {
	ID                string     `json:"id"`
	NetworkID         string     `json:"networkId"`
	SourcePeerID      string     `json:"sourcePeerId"`
	DestinationPeerID string     `json:"destinationPeerId"`
	Epoch             uint64     `json:"epoch"`
	Primary           PathSpec   `json:"primary"`
	Fallbacks         []PathSpec `json:"fallbacks"`
	UpdatedAt         time.Time  `json:"updatedAt"`
	RequiresAdmission bool       `json:"requiresAdmission"`
	// MaxHops is the certified ceiling on manager hops for this assignment.
	MaxHops int `json:"maxHops,omitempty"`
}

// Paths returns the primary followed by fallbacks in certified order.
func (assignment RouteAssignment) Paths() []PathSpec {
	result := make([]PathSpec, 0, len(assignment.Fallbacks)+1)
	result = append(result, assignment.Primary)
	result = append(result, assignment.Fallbacks...)
	return result
}

// User is an authenticated human identity, mirrored from the IdP.
type User struct {
	ID         string   `json:"id"`
	Email      string   `json:"email,omitempty"`
	Name       string   `json:"name,omitempty"`
	Role       string   `json:"role"`
	AutoGroups []string `json:"autoGroups,omitempty"`
	Blocked    bool     `json:"blocked,omitempty"`
	Issued     string   `json:"issued,omitempty"`
	LastLogin  string   `json:"lastLogin,omitempty"`
}

type SetupKey struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Token is the plaintext secret. It only appears in the response that
	// creates a key; list endpoints return the prefix and hash instead.
	Token       string   `json:"token,omitempty"`
	TokenPrefix string   `json:"tokenPrefix,omitempty"`
	TokenHash   []byte   `json:"tokenHash,omitempty"`
	Type        string   `json:"type,omitempty"`
	Groups      []string `json:"groups"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
	UsageLimit  int      `json:"usageLimit,omitempty"`
	UsedCount   int      `json:"usedCount,omitempty"`
	Revoked     bool     `json:"revoked,omitempty"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	LastUsedAt  string   `json:"lastUsedAt,omitempty"`
}

const (
	SetupKeyReusable = "reusable"
	SetupKeyOneOff   = "one-off"
)

// SetupKeyValid reports whether a setup key can be used right now.
func (key SetupKey) SetupKeyValid(now string) bool {
	if key.Revoked {
		return false
	}
	if key.ExpiresAt != "" && key.ExpiresAt <= now {
		return false
	}
	if key.Type == SetupKeyOneOff {
		return key.UsedCount < 1
	}
	if key.UsageLimit > 0 && key.UsedCount >= key.UsageLimit {
		return false
	}
	return true
}

// SetupKeyHash computes the stored hash for a plaintext token.
func SetupKeyHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Nameserver is a certified DNS resolver that applies to the groups listed in
// Groups. MatchDomains scopes the resolver to specific suffixes; an empty list
// makes it a general-purpose resolver.
type Nameserver struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Groups       []string `json:"groups"`
	MatchDomains []string `json:"matchDomains,omitempty"`
	Servers      []string `json:"servers"`
	Primary      bool     `json:"primary,omitempty"`
	Enabled      bool     `json:"enabled"`
}

// DNSRecord is a single resource record inside a DNSZone.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// DNSZone is a certified authoritative zone the overlay resolves locally.
type DNSZone struct {
	ID      string      `json:"id"`
	Domain  string      `json:"domain"`
	Records []DNSRecord `json:"records"`
	Groups  []string    `json:"groups,omitempty"`
	Enabled bool        `json:"enabled"`
}

// DNSSettings carries network-wide DNS toggles. Disabled turns off all overlay
// DNS handling for the listed Groups.
type DNSSettings struct {
	Disabled bool     `json:"disabled"`
	Groups   []string `json:"groups,omitempty"`
}

type StateTransition struct {
	Type        string           `json:"type"`
	Peer        PeerRecord       `json:"peer,omitempty"`
	SetupKey    string           `json:"setupKey,omitempty"`
	RequestID   string           `json:"requestId,omitempty"`
	Group       *Group           `json:"group,omitempty"`
	Policy      *Policy          `json:"policy,omitempty"`
	Route       *Route           `json:"route,omitempty"`
	Budget      *TrafficBudget   `json:"budget,omitempty"`
	Record      *SetupKey        `json:"setupKeyRecord,omitempty"`
	Nameserver  *Nameserver      `json:"nameserver,omitempty"`
	Zone        *DNSZone         `json:"zone,omitempty"`
	DNSSettings *DNSSettings     `json:"dnsSettings,omitempty"`
	User        *User            `json:"user,omitempty"`
	Settings    *NetworkSettings `json:"settings,omitempty"`
	Assignment  *RouteAssignment `json:"assignment,omitempty"`
	TargetID    string           `json:"targetId,omitempty"`
	// Committee carries the full replacement committee for update_committee.
	Committee []CommitteeMember `json:"committee,omitempty"`
	// CommitteeConfig carries the new threshold parameters for
	// rotate_committee_keys.
	CommitteeConfig *CommitteeConfig `json:"committeeConfig,omitempty"`
	// BudgetUsage settles aggregated client-reported usage into certified state.
	BudgetUsage *BudgetUsage `json:"budgetUsage,omitempty"`
	// Actor records who submitted the transition. It is assigned by the manager
	// from the authenticated identity and flows into TransitionHash, so the
	// decision log cannot be rewritten by a single manager.
	Actor *Actor `json:"actor,omitempty"`
}

// Actor is the audit identity attached to a certified transition. ID is the
// stable subject (user id, peer id or "static-admin"); Name and Role are
// captured at submission time for display. Actor never participates in
// authorization — it is evidence, not a credential.
type Actor struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	Static bool   `json:"static,omitempty"`
}

type QuorumCertificate struct {
	Height         uint64 `json:"height"`
	Round          uint64 `json:"round"`
	StateHash      []byte `json:"stateHash"`
	TransitionHash []byte `json:"transitionHash"`
	// AggregateSignature is one BLS signature over the canonical vote message,
	// produced by interpolating the collected share signatures at threshold.
	AggregateSignature []byte `json:"aggregateSignature,omitempty"`
	// SignerBitmap marks which committee members contributed, for diagnostics
	// and duplicate detection. Cryptographic authority comes from the
	// aggregate signature, not the bitmap.
	SignerBitmap []byte `json:"signerBitmap,omitempty"`
	// CommitteeEpoch binds the QC to the committee configuration that produced
	// it, so signatures from before a key rotation are rejected.
	CommitteeEpoch uint64 `json:"committeeEpoch,omitempty"`
}

type SignedSnapshot struct {
	Epoch     uint64            `json:"epoch"`
	Height    uint64            `json:"height"`
	StateHash []byte            `json:"stateHash"`
	State     NetworkState      `json:"state"`
	Committee []CommitteeMember `json:"committee"`
	QC        QuorumCertificate `json:"qc"`
	// CommitteeConfig is the threshold configuration this snapshot was
	// certified under.
	CommitteeConfig CommitteeConfig `json:"committeeConfig"`
	Transition      StateTransition `json:"transition"`
	LeaderID        string          `json:"leaderId"`
}

type NetworkState struct {
	NetworkID    string            `json:"networkId"`
	OverlayCIDR  string            `json:"overlayCidr"`
	Peers        []PeerRecord      `json:"peers"`
	Users        []User            `json:"users"`
	Groups       []Group           `json:"groups"`
	Policies     []Policy          `json:"policies"`
	Routes       []Route           `json:"routes"`
	Budgets      []TrafficBudget   `json:"budgets"`
	SetupKeys    []SetupKey        `json:"setupKeys"`
	Nameservers  []Nameserver      `json:"nameservers"`
	Zones        []DNSZone         `json:"zones"`
	DNSSettings  DNSSettings       `json:"dnsSettings"`
	Settings     NetworkSettings   `json:"settings"`
	Assignments  []RouteAssignment `json:"assignments"`
	NextIPOffset uint32            `json:"nextIpOffset"`
	// CommitteeConfig is mirrored into certified state so a client can verify a
	// snapshot using only the snapshot itself.
	CommitteeConfig CommitteeConfig `json:"committeeConfig"`

	// EngineCommittee is runtime-only context supplied by BFT. It is never
	// marshalled into certified state because the authoritative committee list
	// lives on SignedSnapshot.
	EngineCommittee []CommitteeMember `json:"-"`
}

type engineContext struct {
	EngineCommittee []CommitteeMember `json:"-"`
}

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Direction string

const (
	DirectionUnidirectional Direction = "unidirectional"
	DirectionBidirectional  Direction = "bidirectional"
)

type Group struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	UserIDs  []string `json:"userIds,omitempty"`
	PeerIDs  []string `json:"peerIds,omitempty"`
	Managed  bool     `json:"managed,omitempty"`
	SSOClaim string   `json:"ssoClaim,omitempty"`
	// Issued records how the group came to exist: "api" for administrator
	// created groups, "jwt" for groups mirrored from an IdP claim.
	Issued string `json:"issued,omitempty"`
}

const (
	GroupIssuedAPI = "api"
	GroupIssuedJWT = "jwt"
)

// User roles, mirroring NetBird's role model.
const (
	RoleOwner        = "owner"
	RoleAdmin        = "admin"
	RoleNetworkAdmin = "network_admin"
	RoleAuditor      = "auditor"
	RoleUsageViewer  = "usage_viewer"
	RoleUser         = "user"
)

// ValidRole reports whether role is one of the roles the overlay understands.
func ValidRole(role string) bool {
	switch role {
	case RoleOwner, RoleAdmin, RoleNetworkAdmin, RoleAuditor, RoleUsageViewer, RoleUser:
		return true
	}
	return false
}

type Service struct {
	Protocol  string `json:"protocol"`
	StartPort uint16 `json:"startPort"`
	EndPort   uint16 `json:"endPort"`
}

type Policy struct {
	ID                string    `json:"id"`
	SourceGroups      []string  `json:"sourceGroups"`
	DestinationGroups []string  `json:"destinationGroups"`
	Services          []Service `json:"services"`
	Effect            Effect    `json:"effect"`
	Direction         Direction `json:"direction"`
	Posture           []string  `json:"postureRequirements,omitempty"`
	LinkConstraints   []string  `json:"linkConstraints,omitempty"`
	Priority          int       `json:"priority"`
	// FlowClass selects the planner's scoring weights for traffic this policy
	// authorizes. Empty falls back to the network default.
	FlowClass string `json:"flowClass,omitempty"`
}

type Route struct {
	ID                string   `json:"id"`
	Destination       string   `json:"destination"`
	RoutingGroup      string   `json:"routingGroup"`
	DistributionGroup []string `json:"distributionGroups"`
	Metric            int      `json:"metric"`
	AllowedPathTypes  []string `json:"allowedPathTypes,omitempty"`
	MaxHops           int      `json:"maxHops,omitempty"`
	BudgetIDs         []string `json:"budgetIds,omitempty"`
	// FlowClass overrides the network default scoring class for this route.
	FlowClass string `json:"flowClass,omitempty"`
	// Masquerade asks an exit node to SNAT traffic toward this destination.
	Masquerade bool `json:"masquerade,omitempty"`
}

type TrafficBudget struct {
	ID                  string    `json:"id"`
	SubjectType         string    `json:"subjectType"`
	SubjectID           string    `json:"subjectID"`
	DailyBytes          uint64    `json:"dailyBytes"`
	MonthlyBytes        uint64    `json:"monthlyBytes"`
	PeakBPS             uint64    `json:"peakBps"`
	PeakBurstBytes      uint64    `json:"peakBurstBytes,omitempty"`
	ForwardingCostLimit uint64    `json:"forwardingCostLimit"`
	OnExhausted         string    `json:"onExhausted"`
	UsedDailyBytes      uint64    `json:"usedDailyBytes"`
	UsedMonthlyBytes    uint64    `json:"usedMonthlyBytes"`
	UpdatedAt           time.Time `json:"updatedAt"`
}
