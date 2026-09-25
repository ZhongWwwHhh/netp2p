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
}

type QuorumCertificate struct {
	Height         uint64   `json:"height"`
	Round          uint64   `json:"round"`
	StateHash      []byte   `json:"stateHash"`
	TransitionHash []byte   `json:"transitionHash"`
	Signers        []string `json:"signers"`
	Signatures     [][]byte `json:"signatures"`
}

type SignedSnapshot struct {
	Epoch      uint64            `json:"epoch"`
	Height     uint64            `json:"height"`
	StateHash  []byte            `json:"stateHash"`
	State      NetworkState      `json:"state"`
	Committee  []CommitteeMember `json:"committee"`
	QC         QuorumCertificate `json:"qc"`
	Transition StateTransition   `json:"transition"`
	LeaderID   string            `json:"leaderId"`
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
}

type TrafficBudget struct {
	ID                  string    `json:"id"`
	SubjectType         string    `json:"subjectType"`
	SubjectID           string    `json:"subjectID"`
	DailyBytes          uint64    `json:"dailyBytes"`
	MonthlyBytes        uint64    `json:"monthlyBytes"`
	PeakBPS             uint64    `json:"peakBps"`
	ForwardingCostLimit uint64    `json:"forwardingCostLimit"`
	OnExhausted         string    `json:"onExhausted"`
	UsedDailyBytes      uint64    `json:"usedDailyBytes"`
	UsedMonthlyBytes    uint64    `json:"usedMonthlyBytes"`
	UpdatedAt           time.Time `json:"updatedAt"`
}
