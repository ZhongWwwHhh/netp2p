package model

import "time"

type CommitteeMember struct {
	ID         string `json:"id"`
	PeerID     string `json:"peerId"`
	Address    string `json:"address"`
	KeySeed    int64  `json:"keySeed,omitempty"`
	PublicKey  []byte `json:"publicKey,omitempty"`
	ListenAddr string `json:"listenAddr,omitempty"`
}

type PeerRecord struct {
	PeerID        string   `json:"peerId"`
	OverlayIP     string   `json:"overlayIp"`
	Addresses     []string `json:"addresses,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	OS            string   `json:"os,omitempty"`
	ClientVersion string   `json:"clientVersion,omitempty"`
}

type SetupKey struct {
	Key    string   `json:"key"`
	Groups []string `json:"groups"`
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
	Type        string         `json:"type"`
	Peer        PeerRecord     `json:"peer,omitempty"`
	SetupKey    string         `json:"setupKey,omitempty"`
	RequestID   string         `json:"requestId,omitempty"`
	Group       *Group         `json:"group,omitempty"`
	Policy      *Policy        `json:"policy,omitempty"`
	Route       *Route         `json:"route,omitempty"`
	Budget      *TrafficBudget `json:"budget,omitempty"`
	Record      *SetupKey      `json:"setupKeyRecord,omitempty"`
	Nameserver  *Nameserver    `json:"nameserver,omitempty"`
	Zone        *DNSZone       `json:"zone,omitempty"`
	DNSSettings *DNSSettings   `json:"dnsSettings,omitempty"`
	TargetID    string         `json:"targetId,omitempty"`
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
	NetworkID    string          `json:"networkId"`
	OverlayCIDR  string          `json:"overlayCidr"`
	Peers        []PeerRecord    `json:"peers"`
	Groups       []Group         `json:"groups"`
	Policies     []Policy        `json:"policies"`
	Routes       []Route         `json:"routes"`
	Budgets      []TrafficBudget `json:"budgets"`
	SetupKeys    []SetupKey      `json:"setupKeys"`
	Nameservers  []Nameserver    `json:"nameservers"`
	Zones        []DNSZone       `json:"zones"`
	DNSSettings  DNSSettings     `json:"dnsSettings"`
	NextIPOffset uint32          `json:"nextIpOffset"`
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
	UserIDs  []string `json:"userIds,omitempty"`
	PeerIDs  []string `json:"peerIds,omitempty"`
	Managed  bool     `json:"managed,omitempty"`
	SSOClaim string   `json:"ssoClaim,omitempty"`
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
	ID               string    `json:"id"`
	SubjectType      string    `json:"subjectType"`
	SubjectID        string    `json:"subjectID"`
	DailyBytes       uint64    `json:"dailyBytes"`
	MonthlyBytes     uint64    `json:"monthlyBytes"`
	PeakBPS          uint64    `json:"peakBps"`
	RelayCostLimit   uint64    `json:"relayCostLimit"`
	OnExhausted      string    `json:"onExhausted"`
	UsedDailyBytes   uint64    `json:"usedDailyBytes"`
	UsedMonthlyBytes uint64    `json:"usedMonthlyBytes"`
	UpdatedAt        time.Time `json:"updatedAt"`
}
