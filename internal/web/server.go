package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http"
	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/store"
	"github.com/netp2p/netp2p/internal/version"
)

type BootstrapResponse struct {
	PeerID          string                  `json:"peerId"`
	PublicKey       []byte                  `json:"publicKey"`
	WebRTCAddresses []string                `json:"webrtcAddresses"`
	APIProtocol     string                  `json:"apiProtocol"`
	APIBase         string                  `json:"apiBase"`
	NetworkID       string                  `json:"networkId"`
	Version         string                  `json:"version"`
	ProtocolVersion string                  `json:"protocolVersion"`
	Committee       []model.CommitteeMember `json:"committee"`
	OIDC            *BootstrapOIDC          `json:"oidc,omitempty"`
}

// BootstrapOIDC is the browser-facing slice of the OIDC configuration. The
// console uses it to run a PKCE authorization code flow.
type BootstrapOIDC struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	Audience              string   `json:"audience,omitempty"`
	Scopes                []string `json:"scopes"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string   `json:"tokenEndpoint,omitempty"`
	RedirectURI           string   `json:"redirectUri,omitempty"`
}

// ScopedSnapshot is the least state a limited console user needs: their own
// peers and the policy, route, and DNS objects that apply to those peers. It
// deliberately does not reuse SignedSnapshot, so a scoped response cannot leak
// the full certified network.
type ScopedSnapshot struct {
	NetworkID   string                `json:"networkId"`
	OverlayCIDR string                `json:"overlayCidr,omitempty"`
	Epoch       uint64                `json:"epoch"`
	Height      uint64                `json:"height"`
	User        model.User            `json:"user"`
	Peers       []model.PeerRecord    `json:"peers"`
	Groups      []model.Group         `json:"groups"`
	Policies    []model.Policy        `json:"policies"`
	Routes      []model.Route         `json:"routes"`
	Nameservers []model.Nameserver    `json:"nameservers"`
	Zones       []model.DNSZone       `json:"zones"`
	DNSSettings model.DNSSettings     `json:"dnsSettings"`
	Settings    model.NetworkSettings `json:"settings"`
}

type TransitionRequest struct {
	Transition model.StateTransition `json:"transition"`
}

func normalizeTransitionForSubmit(transition model.StateTransition, now time.Time) model.StateTransition {
	if transition.Type == bft.TransitionUpdateAssignment && transition.Assignment != nil &&
		transition.Assignment.UpdatedAt.IsZero() {
		assignment := *transition.Assignment
		assignment.UpdatedAt = now.UTC()
		transition.Assignment = &assignment
	}
	return transition
}

type SetupKeyCreateRequest struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Groups     []string `json:"groups"`
	ExpiresIn  string   `json:"expiresAt"`
	UsageLimit int      `json:"usageLimit"`
}

type CommitteeStatus struct {
	LocalID       string                   `json:"localId"`
	Height        uint64                   `json:"height"`
	LeaderAtHead  string                   `json:"leaderAtHead"`
	NextRound     uint64                   `json:"nextRound"`
	QuorumSize    int                      `json:"quorumSize"`
	CommitteeSize int                      `json:"committeeSize"`
	Connected     map[string]bool          `json:"connected"`
	LatestQC      *model.QuorumCertificate `json:"latestQc,omitempty"`
}

// ReadinessStatus is the unauthenticated readiness projection used by load
// balancers and deployment validation.
type ReadinessStatus struct {
	Status          string   `json:"status"`
	Height          uint64   `json:"height"`
	KnownHeight     uint64   `json:"knownHeight,omitempty"`
	HeightLag       uint64   `json:"heightLag,omitempty"`
	CommitteeOnline int      `json:"committeeOnline"`
	CommitteeSize   int      `json:"committeeSize"`
	QuorumSize      int      `json:"quorumSize"`
	LedgerReady     bool     `json:"ledgerReady"`
	Degraded        bool     `json:"degraded"`
	Reasons         []string `json:"reasons"`
}

// ReadinessFunc lets a manager provide a richer readiness signal, for example
// SQLite write health, without the web package depending on storage internals.
type ReadinessFunc func() ReadinessStatus

type Config struct {
	AdminToken string
	// SessionSecret is shared by every manager so local web sessions remain
	// valid across the round-robin console hostname.
	SessionSecret string
	// AuthStore persists local login audit and lockout state.
	AuthStore *store.Store
	// Authenticator, when set, resolves an SSO bearer token to an identity.
	// The static admin token always works as break-glass.
	Authenticator Authenticator
	// OIDC is advertised to the browser console for PKCE login.
	OIDC *BootstrapOIDC
	// SessionSyncer exchanges manager-local web-session records with the other
	// committee members. It keeps round-robin console cookies valid and makes
	// logout revocation global without writing interactive logins into BFT.
	SessionSyncer SessionSyncer
	// Readiness overrides the default manager/node-derived readiness signal.
	Readiness ReadinessFunc
	// RoutingStatus supplies signed epochs, manager telemetry, demand, and FEC
	// counters from the runtime planner. When nil, the API returns an explicit
	// derived view instead of fabricating runtime state.
	RoutingStatus RoutingStatusFunc
}

// Authenticator resolves an SSO ID token to an authenticated identity. It is
// implemented by the OIDC verifier.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (auth.Identity, error)
}

type SessionSyncer interface {
	Sync(ctx context.Context) error
}

type Server struct {
	manager                    *manager.Manager
	node                       *p2p.Node
	config                     Config
	httpHost                   *libp2phttp.Host
	publicKey                  []byte
	addresses                  []string
	bootstrap                  []byte
	httpServer                 *http.Server
	oidcProxy                  *oidcProxy
	accounts                   accountDirectory
	authStore                  *store.Store
	sessions                   *auth.SessionManager
	sessionSyncer              SessionSyncer
	sessionReplicationDegraded atomic.Bool
	readinessFunc              ReadinessFunc
	dummyPasswordVerifier      []byte
	loginLimiter               *loginRateLimiter
	loginLimiterOnce           sync.Once
}

func NewServer(node *p2p.Node, manager *manager.Manager, config Config) (*Server, error) {
	if strings.TrimSpace(config.AdminToken) == "" {
		return nil, fmt.Errorf("admin token is required")
	}
	publicKey, err := node.IdentityPublicKey()
	if err != nil {
		return nil, err
	}
	addresses := node.WebRTCAddresses()
	if len(addresses) == 0 {
		return nil, fmt.Errorf("manager has no WebRTC addresses")
	}
	sessions, err := auth.NewSessionManager(config.SessionSecret, time.Hour)
	if err != nil {
		return nil, err
	}
	if config.AuthStore == nil {
		return nil, fmt.Errorf("auth store is required")
	}
	oidcProxy, err := newOIDCProxy(config.OIDC)
	if err != nil {
		return nil, err
	}
	server := &Server{
		manager:               manager,
		node:                  node,
		config:                config,
		httpHost:              &libp2phttp.Host{StreamHost: node.Host},
		publicKey:             publicKey,
		addresses:             addresses,
		oidcProxy:             oidcProxy,
		accounts:              manager,
		authStore:             config.AuthStore,
		sessions:              sessions,
		sessionSyncer:         config.SessionSyncer,
		readinessFunc:         config.Readiness,
		dummyPasswordVerifier: model.HashPassword("netp2p-dummy-verifier"),
		loginLimiter:          newLoginRateLimiter(),
	}
	if server.oidcProxy != nil && config.Authenticator != nil {
		server.oidcProxy.recordSession = func(ctx context.Context, token string, expires time.Time) error {
			identity, authErr := config.Authenticator.Authenticate(ctx, token)
			if authErr != nil {
				return authErr
			}
			if err := server.authStore.RecordWebSession(store.WebSession{
				ID: auth.ExternalSessionID(token), UserID: identity.UserID,
				IssuedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return err
			}
			server.syncWebSessionsWithRetry()
			return nil
		}
	}
	server.httpHost.SetHTTPHandler(p2p.WebAPIProtocol, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.handleAPI(writer, request)
	}))
	server.bootstrap, err = json.Marshal(BootstrapResponse{
		PeerID:          node.Host.ID().String(),
		PublicKey:       publicKey,
		WebRTCAddresses: addresses,
		APIProtocol:     string(p2p.WebAPIProtocol),
		APIBase:         "/api/v1",
		NetworkID:       manager.NetworkID(),
		Version:         version.Version,
		ProtocolVersion: version.ProtocolVersion,
		Committee:       manager.Committee(),
		OIDC:            config.OIDC,
	})
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (server *Server) StartInsecureBootstrap(listen string) error {
	if server.httpServer != nil {
		return fmt.Errorf("bootstrap server already started")
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	server.httpServer = &http.Server{Handler: server.BootstrapHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := server.httpServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Printf("web bootstrap server stopped: %v", serveErr)
		}
	}()
	return nil
}

func (server *Server) Stop() {
	if server.httpServer != nil {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.httpServer.Shutdown(shutdownContext)
		server.httpServer = nil
	}
	_ = server.httpHost.Close()
}

func (server *Server) HTTPHost() *libp2phttp.Host {
	return server.httpHost
}

func (server *Server) handleAPI(writer http.ResponseWriter, request *http.Request) {
	if !server.validateMutationOrigin(writer, request) {
		return
	}
	if server.handlePublicAuth(writer, request) {
		return
	}
	identity, ok := server.authenticate(request)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	path := strings.TrimSuffix(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodGet && path == "/api/v1/session":
		writeJSON(writer, http.StatusOK, map[string]any{
			"identity":    identity,
			"permissions": auth.Permissions(identity.Role),
		})
	case request.Method == http.MethodGet && path == "/api/v1/snapshot":
		if !identity.Allows(auth.ModulePeers, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		server.handleSnapshot(writer, request, identity)
	case request.Method == http.MethodGet && path == "/api/v1/presence":
		if !identity.Allows(auth.ModulePresence, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"observations": server.manager.Presence()})
	case request.Method == http.MethodGet && path == "/api/v1/users":
		if !identity.Allows(auth.ModuleUsers, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"users": publicUsers(server.accounts.Users())})
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/credentials"):
		targetID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/users/"), "/credentials")
		server.handleUserCredentials(writer, request, targetID, identity)
	case request.Method == http.MethodGet && path == "/api/v1/auth/events":
		if !identity.Allows(auth.ModuleEvents, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		limit := 200
		if raw := request.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeError(writer, http.StatusBadRequest, "invalid limit")
				return
			}
			if parsed > 1000 {
				parsed = 1000
			}
			limit = parsed
		}
		events, err := server.authStore.AuthEvents(limit)
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "cannot read auth events")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"events": events})
	case request.Method == http.MethodGet && path == "/api/v1/activity":
		if !identity.Allows(auth.ModuleEvents, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		server.handleActivity(writer, request)
	case request.Method == http.MethodGet && path == "/api/v1/events":
		if !identity.Allows(auth.ModuleEvents, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		server.handleEvents(writer, request)
	case request.Method == http.MethodGet && path == "/api/v1/diagnostics":
		if !identity.Allows(auth.ModuleDiagnostics, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, server.diagnostics())
	case request.Method == http.MethodGet && path == "/api/v1/committee/status":
		if !identity.Allows(auth.ModuleDiagnostics, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, server.committeeStatus())
	case request.Method == http.MethodGet && path == "/api/v1/link-view":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"linkView": server.manager.LinkView()})
	case request.Method == http.MethodGet && path == "/api/v1/routing/status":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		status := server.routingStatus()
		if !identity.Allows(auth.ModuleBudgets, auth.OpRead) {
			status.ManagerCapacity = []ManagerCapacityStatus{}
		}
		writeJSON(writer, http.StatusOK, map[string]any{"routing": status})
	case request.Method == http.MethodGet && path == "/api/v1/routing/domains":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"domains": server.routingStatus().Domains})
	case request.Method == http.MethodGet && path == "/api/v1/routing/path-families":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"pathFamilies": server.routingStatus().PathFamilies})
	case request.Method == http.MethodGet && path == "/api/v1/routing/telemetry":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"telemetry": server.routingStatus().Telemetry})
	case request.Method == http.MethodGet && path == "/api/v1/routing/demand":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"demand": server.routingStatus().Demand})
	case request.Method == http.MethodGet && path == "/api/v1/routing/epoch/current":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"epoch": server.routingStatus().Epoch})
	case request.Method == http.MethodGet && path == "/api/v1/routing/fec":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"fec": server.routingStatus().Fec})
	case request.Method == http.MethodGet && path == "/api/v1/managers/capacity":
		if !identity.Allows(auth.ModuleBudgets, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"managers": server.routingStatus().ManagerCapacity})
	case request.Method == http.MethodGet && path == "/api/v1/assignments":
		if !identity.Allows(auth.ModulePaths, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"assignments": server.manager.Snapshot().State.Assignments,
			"admissions":  server.manager.Admissions(),
		})
	case request.Method == http.MethodGet && path == "/api/v1/quota":
		if !identity.Allows(auth.ModuleBudgets, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"usage": server.manager.QuotaUsage()})
	case request.Method == http.MethodGet && path == "/api/v1/quota/history":
		if !identity.Allows(auth.ModuleBudgets, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		period := request.URL.Query().Get("period")
		if period == "" {
			period = "daily"
		}
		if period != "daily" && period != "monthly" {
			writeError(writer, http.StatusBadRequest, "period must be daily or monthly")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"period":  period,
			"entries": server.manager.QuotaHistory(period),
		})
	case request.Method == http.MethodGet && path == "/api/v1/alerts":
		if !identity.Allows(auth.ModuleDiagnostics, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"alerts": server.manager.ActiveAlerts()})
	case request.Method == http.MethodGet && path == "/api/v1/schema":
		writeJSON(writer, http.StatusOK, map[string]string{"protocol": string(p2p.WebAPIProtocol)})
	case request.Method == http.MethodPost && path == "/api/v1/setup-keys":
		var body SetupKeyCreateRequest
		if err := decodeJSONBody(writer, request, 1<<20, &body); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid request")
			return
		}
		if err := auth.AuthorizeTransition(identity, bft.TransitionUpsertSetupKey); err != nil {
			writeError(writer, http.StatusForbidden, err.Error())
			return
		}
		token, record, err := newSetupKey(body)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		snapshot, err := server.accounts.SubmitAs(model.StateTransition{
			Type: bft.TransitionUpsertSetupKey, Record: &record,
		}, auth.ActorOf(identity))
		if err != nil {
			writeError(writer, http.StatusConflict, err.Error())
			return
		}
		if server.manager != nil {
			err = bft.ValidateSnapshot(snapshot)
		}
		if err != nil {
			writeError(writer, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"token": token, "snapshot": model.ClientSnapshot(snapshot)})
	case request.Method == http.MethodPost && path == "/api/v1/transitions":
		var body TransitionRequest
		if err := decodeJSONBody(writer, request, 1<<20, &body); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid request")
			return
		}
		if err := auth.AuthorizeTransition(identity, body.Transition.Type); err != nil {
			writeError(writer, http.StatusForbidden, err.Error())
			return
		}
		body.Transition = normalizeTransitionForSubmit(body.Transition, time.Now())
		// The actor is derived from the authenticated identity, never from the
		// request body, so a caller cannot forge an audit identity.
		snapshot, err := server.manager.SubmitAs(body.Transition, auth.ActorOf(identity))
		if err != nil {
			writeError(writer, http.StatusConflict, err.Error())
			return
		}
		if err := server.revokeSessionsForTransition(body.Transition); err != nil {
			writeError(writer, http.StatusInternalServerError, "cannot revoke affected sessions")
			return
		}
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			writeError(writer, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(writer, http.StatusOK, model.ClientSnapshot(snapshot))
	default:
		writeError(writer, http.StatusNotFound, "not found")
	}
}

// handleSnapshot serves the latest certified state, or a historical height when
// ?height= is given. Historical lookups are how the console inspects the
// decision log without trusting any single manager's memory.
func (server *Server) handleSnapshot(writer http.ResponseWriter, request *http.Request, identity auth.Identity) {
	fullState := canReadFullSnapshot(identity)
	if raw := request.URL.Query().Get("height"); raw != "" {
		if !fullState {
			writeError(writer, http.StatusForbidden, "historical snapshots require full-state permission")
			return
		}
		height, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid height")
			return
		}
		snapshot, ok := server.manager.SnapshotAt(height)
		if !ok {
			writeError(writer, http.StatusNotFound, "unknown height")
			return
		}
		writeJSON(writer, http.StatusOK, model.ClientSnapshot(snapshot))
		return
	}
	if !fullState {
		writeJSON(writer, http.StatusOK, scopedSnapshot(server.accounts.Snapshot(), identity))
		return
	}
	snapshot, ok := server.manager.LatestSnapshot()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "no certified snapshot")
		return
	}
	writeJSON(writer, http.StatusOK, model.ClientSnapshot(snapshot))
}

func (server *Server) handleActivity(writer http.ResponseWriter, request *http.Request) {
	limit := 100
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(writer, http.StatusBadRequest, "invalid limit")
			return
		}
		if parsed > 500 {
			parsed = 500
		}
		limit = parsed
	}
	var before uint64
	if raw := request.URL.Query().Get("before"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid before")
			return
		}
		before = parsed
	}
	entries := server.manager.Activity(limit, before)
	for index := range entries {
		entries[index] = model.ClientSnapshot(entries[index])
	}
	writeJSON(writer, http.StatusOK, map[string]any{"entries": entries})
}

func canReadFullSnapshot(identity auth.Identity) bool {
	return identity.Allows(auth.ModulePeers, auth.OpRead) &&
		identity.Allows(auth.ModuleEvents, auth.OpRead)
}

func scopedSnapshot(snapshot model.SignedSnapshot, identity auth.Identity) ScopedSnapshot {
	subject := identity.UserID
	if subject == "" {
		subject = identity.Subject
	}
	result := ScopedSnapshot{
		NetworkID: snapshot.State.NetworkID, OverlayCIDR: snapshot.State.OverlayCIDR,
		Epoch: snapshot.Epoch, Height: snapshot.Height,
	}
	relevantGroups := make(map[string]struct{})
	addGroups := func(groups []string) {
		for _, group := range groups {
			if group != "" {
				relevantGroups[group] = struct{}{}
			}
		}
	}

	for _, user := range snapshot.State.Users {
		if user.ID == subject {
			result.User = publicUsers([]model.User{user})[0]
			addGroups(user.AutoGroups)
			break
		}
	}
	for _, peer := range snapshot.State.Peers {
		if peer.UserID == subject {
			result.Peers = append(result.Peers, peer)
			addGroups(peer.Groups)
		}
	}
	ownPeerIDs := make(map[string]struct{}, len(result.Peers))
	for _, peer := range result.Peers {
		ownPeerIDs[peer.PeerID] = struct{}{}
	}
	for _, group := range snapshot.State.Groups {
		matchesUser := containsString(group.UserIDs, subject)
		matchesPeer := false
		for peerID := range ownPeerIDs {
			if containsString(group.PeerIDs, peerID) {
				matchesPeer = true
				break
			}
		}
		if !matchesUser && !matchesPeer {
			continue
		}
		relevantGroups[group.ID] = struct{}{}
		scoped := group
		scoped.UserIDs = nil
		scoped.PeerIDs = nil
		result.Groups = append(result.Groups, scoped)
	}
	for _, policy := range snapshot.State.Policies {
		if intersectsGroups(policy.SourceGroups, relevantGroups) ||
			intersectsGroups(policy.DestinationGroups, relevantGroups) {
			result.Policies = append(result.Policies, policy)
		}
	}
	for _, route := range snapshot.State.Routes {
		if intersectsGroups([]string{route.RoutingGroup}, relevantGroups) ||
			intersectsGroups(route.DistributionGroup, relevantGroups) {
			result.Routes = append(result.Routes, route)
		}
	}
	for _, nameserver := range snapshot.State.Nameservers {
		if len(nameserver.Groups) == 0 || intersectsGroups(nameserver.Groups, relevantGroups) {
			result.Nameservers = append(result.Nameservers, nameserver)
		}
	}
	for _, zone := range snapshot.State.Zones {
		if len(zone.Groups) == 0 || intersectsGroups(zone.Groups, relevantGroups) {
			result.Zones = append(result.Zones, zone)
		}
	}
	if len(snapshot.State.DNSSettings.Groups) == 0 ||
		intersectsGroups(snapshot.State.DNSSettings.Groups, relevantGroups) {
		result.DNSSettings = snapshot.State.DNSSettings
	}
	result.Settings = snapshot.State.Settings
	return result
}

func intersectsGroups(groups []string, relevant map[string]struct{}) bool {
	for _, group := range groups {
		if _, ok := relevant[group]; ok {
			return true
		}
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (server *Server) validateMutationOrigin(writer http.ResponseWriter, request *http.Request) bool {
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		if _, hasCookie := sessionToken(request); hasCookie {
			writeError(writer, http.StatusForbidden, "missing same-origin header")
			return false
		}
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		!strings.EqualFold(parsed.Host, request.Host) {
		writeError(writer, http.StatusForbidden, "cross-origin request rejected")
		return false
	}
	return true
}

func (server *Server) revokeSessionsForTransition(transition model.StateTransition) error {
	target := transition.TargetID
	if target == "" && transition.User != nil {
		target = transition.User.ID
	}
	if target == "" {
		return nil
	}
	switch transition.Type {
	case bft.TransitionUpdateUserCredentials, bft.TransitionUpdateUserRole,
		bft.TransitionSetUserBlocked, bft.TransitionRemoveUser:
		return server.authStore.RevokeUserWebSessions(target, time.Now())
	default:
		return nil
	}
}

// AuditEvent is the authenticated decision-log entry exposed to the console.
// Every field comes from a certified snapshot, so the log can be recomputed
// from the quorum certificate rather than trusted from the manager.
type AuditEvent struct {
	Height         uint64       `json:"height"`
	Type           string       `json:"type"`
	LeaderID       string       `json:"leaderId"`
	Actor          *model.Actor `json:"actor,omitempty"`
	SignerBitmap   []byte       `json:"signerBitmap,omitempty"`
	StateHash      string       `json:"stateHash"`
	TransitionHash string       `json:"transitionHash"`
	CommitteeEpoch uint64       `json:"committeeEpoch"`
	RecordedAt     string       `json:"recordedAt,omitempty"`
}

func (server *Server) handleEvents(writer http.ResponseWriter, request *http.Request) {
	limit := 200
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(writer, http.StatusBadRequest, "invalid limit")
			return
		}
		if parsed > 1000 {
			parsed = 1000
		}
		limit = parsed
	}
	var before uint64
	if raw := request.URL.Query().Get("before"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid before")
			return
		}
		before = parsed
	}
	typeFilter := request.URL.Query().Get("type")
	actorFilter := request.URL.Query().Get("actor")
	events := make([]AuditEvent, 0, limit)
	for _, snapshot := range server.manager.Activity(limit, before) {
		if typeFilter != "" && snapshot.Transition.Type != typeFilter {
			continue
		}
		if actorFilter != "" && (snapshot.Transition.Actor == nil || snapshot.Transition.Actor.ID != actorFilter) {
			continue
		}
		events = append(events, AuditEvent{
			Height:         snapshot.Height,
			Type:           snapshot.Transition.Type,
			LeaderID:       snapshot.LeaderID,
			Actor:          snapshot.Transition.Actor,
			SignerBitmap:   snapshot.QC.SignerBitmap,
			StateHash:      fmt.Sprintf("%x", snapshot.StateHash),
			TransitionHash: fmt.Sprintf("%x", snapshot.QC.TransitionHash),
			CommitteeEpoch: snapshot.QC.CommitteeEpoch,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"events": events})
}

// diagnostics returns a human-readable health snapshot for operators.
func (server *Server) diagnostics() map[string]any {
	state := server.manager.Snapshot().State
	linkView := server.manager.LinkView()
	committeeParams := server.manager.CommitteeParams()
	forwarded, dropped := server.manager.ForwardingStats()
	problems := make([]string, 0)
	if server.manager.Height() == 0 {
		problems = append(problems, "no committed height yet")
	}
	if len(state.Peers) == 0 {
		problems = append(problems, "no peers registered")
	}
	if dropped > 0 {
		problems = append(problems, fmt.Sprintf("%d forwarded frames were dropped", dropped))
	}
	status := server.committeeStatus()
	for memberID, connected := range status.Connected {
		if !connected {
			problems = append(problems, fmt.Sprintf("committee member %s is not connected", memberID))
		}
	}
	return map[string]any{
		"protocolVersion": version.ProtocolVersion,
		"manager":         server.manager.LocalID(),
		"networkId":       state.NetworkID,
		"height":          server.manager.Height(),
		"quorumSize":      committeeParams.QuorumSize,
		"committeeSize":   committeeParams.Size,
		"peers":           len(state.Peers),
		"groups":          len(state.Groups),
		"policies":        len(state.Policies),
		"budgets":         len(state.Budgets),
		"assignments":     len(state.Assignments),
		"linkSegments":    len(linkView.Segments) + len(linkView.AccessSegments),
		"presence":        server.manager.Presence(),
		"forwarding":      map[string]uint64{"forwarded": forwarded, "dropped": dropped},
		"quotaUsage":      server.manager.QuotaUsage(),
		"alerts":          server.manager.ActiveAlerts(),
		"problems":        problems,
	}
}

func newSetupKey(request SetupKeyCreateRequest) (string, model.SetupKey, error) {
	if strings.TrimSpace(request.Name) == "" {
		return "", model.SetupKey{}, errors.New("name is required")
	}
	if len(request.Groups) == 0 {
		return "", model.SetupKey{}, errors.New("at least one group is required")
	}
	keyType := request.Type
	if keyType == "" {
		keyType = model.SetupKeyReusable
	}
	if keyType != model.SetupKeyReusable && keyType != model.SetupKeyOneOff {
		return "", model.SetupKey{}, errors.New("type must be reusable or one-off")
	}
	if request.UsageLimit < 0 {
		return "", model.SetupKey{}, errors.New("usage limit cannot be negative")
	}
	expiresAt, err := setupKeyExpiry(request.ExpiresIn)
	if err != nil {
		return "", model.SetupKey{}, err
	}
	token, err := randomToken("netp2p-sk-", 32)
	if err != nil {
		return "", model.SetupKey{}, fmt.Errorf("generate setup key: %w", err)
	}
	id, err := randomToken("key-", 12)
	if err != nil {
		return "", model.SetupKey{}, fmt.Errorf("generate setup key id: %w", err)
	}
	usageLimit := request.UsageLimit
	if keyType == model.SetupKeyOneOff {
		usageLimit = 1
	}
	return token, model.SetupKey{
		ID: id, Name: strings.TrimSpace(request.Name), TokenPrefix: token[:8],
		TokenHash: model.SetupKeyHash(token), Type: keyType, Groups: append([]string(nil), request.Groups...),
		ExpiresAt: expiresAt, UsageLimit: usageLimit, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func randomToken(prefix string, bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func setupKeyExpiry(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasSuffix(value, "d") {
		return "", errors.New("expiry must be empty or Nd")
	}
	days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
	if err != nil || days < 1 || days > 3650 {
		return "", errors.New("expiry must be between 1d and 3650d")
	}
	return time.Now().UTC().AddDate(0, 0, days).Format(time.RFC3339), nil
}

func (server *Server) committeeStatus() CommitteeStatus {
	latest, _ := server.manager.LatestSnapshot()
	height := server.manager.Height()
	committee := server.manager.Committee()
	committeeParams := server.manager.CommitteeParams()
	status := CommitteeStatus{
		LocalID:       server.manager.LocalID(),
		Height:        height,
		LeaderAtHead:  server.manager.Leader(height+1, 0).ID,
		NextRound:     0,
		QuorumSize:    committeeParams.QuorumSize,
		CommitteeSize: committeeParams.Size,
		Connected:     make(map[string]bool, len(committee)),
	}
	if latest.Height > 0 {
		qc := latest.QC
		status.LatestQC = &qc
	}
	for _, member := range committee {
		if member.ID == server.manager.LocalID() {
			status.Connected[member.ID] = true
			continue
		}
		peerID, err := peer.Decode(member.PeerID)
		status.Connected[member.ID] = err == nil && server.node.Host.Network().Connectedness(peerID) == network.Connected
	}
	return status
}

func (server *Server) readinessStatus() ReadinessStatus {
	if server.readinessFunc != nil {
		status := server.readinessFunc()
		if status.Reasons == nil {
			status.Reasons = []string{}
		}
		return status
	}
	return server.readinessFromManager()
}

func (server *Server) readinessFromManager() ReadinessStatus {
	if server.manager == nil {
		return ReadinessStatus{
			Status: "degraded", Degraded: true,
			Reasons: []string{"manager is unavailable"},
		}
	}
	status := ReadinessStatus{
		QuorumSize: server.manager.CommitteeParams().QuorumSize,
		Reasons:    []string{},
	}

	snapshot, hasSnapshot := server.manager.LatestSnapshot()
	status.Height = server.manager.Height()
	status.KnownHeight = server.manager.KnownHeight()
	if status.KnownHeight > status.Height {
		status.HeightLag = status.KnownHeight - status.Height
		status.Reasons = append(status.Reasons, fmt.Sprintf(
			"certified height is behind the committee: local %d, known %d",
			status.Height, status.KnownHeight,
		))
	}
	status.LedgerReady = hasSnapshot && snapshot.Height > 0 && snapshot.Height == status.Height
	if !status.LedgerReady {
		if status.Height == 0 {
			status.Reasons = append(status.Reasons, "ledger has no certified height")
		} else {
			status.Reasons = append(status.Reasons, "latest certified snapshot is not loaded at the current height")
		}
	}

	committee := server.manager.Committee()
	status.CommitteeSize = len(committee)
	for _, member := range committee {
		if member.ID == server.manager.LocalID() {
			status.CommitteeOnline++
			continue
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			status.Reasons = append(status.Reasons, fmt.Sprintf("committee member %s has an invalid peer ID", member.ID))
			continue
		}
		if server.node == nil || server.node.Host.Network().Connectedness(peerID) != network.Connected {
			status.Reasons = append(status.Reasons, fmt.Sprintf("committee member %s is not connected", member.ID))
			continue
		}
		status.CommitteeOnline++
	}
	if status.QuorumSize <= 0 {
		status.Reasons = append(status.Reasons, "committee quorum is not configured")
	} else if status.CommitteeOnline < status.QuorumSize {
		status.Reasons = append(status.Reasons, fmt.Sprintf(
			"committee quorum is unavailable: %d of %d members online, quorum %d",
			status.CommitteeOnline, status.CommitteeSize, status.QuorumSize,
		))
	}

	status.Degraded = !status.LedgerReady || status.QuorumSize <= 0 ||
		status.CommitteeOnline < status.QuorumSize || status.HeightLag > 0
	if status.Degraded {
		status.Status = "degraded"
	} else {
		status.Status = "ready"
	}
	return status
}

func readinessIsReady(status ReadinessStatus) bool {
	return !status.Degraded && status.LedgerReady &&
		status.QuorumSize > 0 && status.CommitteeOnline >= status.QuorumSize &&
		status.HeightLag == 0
}

func (server *Server) BootstrapHandler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.oidcProxy != nil && strings.HasPrefix(request.URL.Path, "/auth/") {
			if server.oidcProxy.handle(writer, request) {
				return
			}
		}
		switch request.URL.Path {
		case "/api/bootstrap":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer)
				return
			}
			writeJSON(writer, http.StatusOK, json.RawMessage(server.bootstrap))
			return
		case "/healthz":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer)
				return
			}
			writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
			return
		case "/readyz":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer)
				return
			}
			status := server.readinessStatus()
			responseStatus := http.StatusServiceUnavailable
			if readinessIsReady(status) {
				responseStatus = http.StatusOK
			}
			writer.Header().Set("Cache-Control", "no-store")
			writeJSON(writer, responseStatus, status)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/api/") {
			server.handleAPI(writer, request)
			return
		}
		// Serve the SPA shell for deep links such as /peers, so client-side
		// routing works on a hard refresh. Asset paths keep their file
		// semantics and still 404 when missing.
		if request.Method == http.MethodGet && !strings.HasPrefix(request.URL.Path, "/assets/") && !hasFileExtension(request.URL.Path) {
			request = request.Clone(request.Context())
			request.URL.Path = "/"
		}
		fileServer.ServeHTTP(writer, request)
	})
}

func hasFileExtension(path string) bool {
	base := path
	if index := strings.LastIndex(base, "/"); index >= 0 {
		base = base[index+1:]
	}
	return strings.Contains(base, ".")
}

// authenticate resolves the request's bearer token to an identity. The static
// admin token is always accepted as break-glass; any other token is delegated
// to the configured SSO verifier.
func (server *Server) authenticate(request *http.Request) (auth.Identity, bool) {
	token, ok := requestSessionToken(request)
	if !ok {
		return auth.Identity{}, false
	}
	if adminToken := server.config.AdminToken; adminToken != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1 {
		return auth.BreakGlass(), true
	}
	identity, persisted := server.validPersistedSession(token, time.Now())
	if !persisted {
		return auth.Identity{}, false
	}
	if strings.HasPrefix(token, auth.LocalSessionPrefix) {
		issuedAt, err := server.sessions.IssuedAt(token)
		if err != nil {
			return auth.Identity{}, false
		}
		if server.accounts == nil {
			return auth.Identity{}, false
		}
		for _, user := range server.accounts.Users() {
			if user.ID != identity.UserID || user.Blocked {
				continue
			}
			if changedAt, parseErr := time.Parse(time.RFC3339Nano, user.CredentialsChangedAt); parseErr == nil && issuedAt.Before(changedAt) {
				return auth.Identity{}, false
			}
			identity.Email = user.Email
			identity.Name = user.Name
			identity.Role = user.Role
			return identity, true
		}
		return auth.Identity{}, false
	}
	return identity, true
}

func (server *Server) validPersistedSession(token string, now time.Time) (auth.Identity, bool) {
	if server.authStore == nil {
		return auth.Identity{}, false
	}
	if strings.HasPrefix(token, auth.LocalSessionPrefix) {
		identity, err := server.sessions.Verify(token, now)
		if err != nil {
			return auth.Identity{}, false
		}
		sessionID, err := server.sessions.SessionID(token)
		if err != nil {
			return auth.Identity{}, false
		}
		if !server.persistedSessionIsValid(sessionID, identity.UserID, now) {
			// A valid signed cookie can reach a manager that missed the login
			// broadcast, for example after a restart. Pull the committee
			// projection once before rejecting; this also fetches revocations.
			if server.sessionSyncer == nil || server.syncWebSessions() != nil {
				return auth.Identity{}, false
			}
			if !server.persistedSessionIsValid(sessionID, identity.UserID, now) {
				return auth.Identity{}, false
			}
		}
		return identity, true
	}
	if server.config.Authenticator == nil {
		return auth.Identity{}, false
	}
	identity, err := server.config.Authenticator.Authenticate(context.Background(), token)
	if err != nil || identity.Role == "" {
		return auth.Identity{}, false
	}
	if !server.persistedSessionIsValid(auth.ExternalSessionID(token), identity.UserID, time.Now()) {
		if server.sessionSyncer == nil || server.syncWebSessions() != nil {
			return auth.Identity{}, false
		}
		if !server.persistedSessionIsValid(auth.ExternalSessionID(token), identity.UserID, time.Now()) {
			return auth.Identity{}, false
		}
	}
	return identity, true
}

func (server *Server) persistedSessionIsValid(sessionID, userID string, now time.Time) bool {
	session, found, err := server.authStore.WebSession(sessionID)
	if err != nil || !found || session.UserID != userID || session.RevokedAt != "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	return err == nil && !now.UTC().After(expiresAt)
}

func (server *Server) revokeSessionToken(token string, now time.Time) error {
	if strings.HasPrefix(token, auth.LocalSessionPrefix) {
		sessionID, err := server.sessions.SessionID(token)
		if err != nil {
			return err
		}
		if err := server.authStore.RevokeWebSession(sessionID, now); err != nil {
			return err
		}
		return server.syncWebSessions()
	}
	if server.config.Authenticator == nil {
		return nil
	}
	if err := server.authStore.RevokeWebSession(auth.ExternalSessionID(token), now); err != nil {
		return err
	}
	server.syncWebSessionsWithRetry()
	return nil
}

func requestSessionToken(request *http.Request) (string, bool) {
	if token, ok := bearerToken(request); ok {
		return token, true
	}
	return sessionToken(request)
}

func sessionToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie("netp2p_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func bearerToken(request *http.Request) (string, bool) {
	header := request.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}
