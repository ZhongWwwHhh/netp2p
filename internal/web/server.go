package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http"
	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
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
	Committee       []model.CommitteeMember `json:"committee"`
	OIDC            *BootstrapOIDC          `json:"oidc,omitempty"`
}

// BootstrapOIDC is the browser-facing slice of the OIDC configuration. The
// console uses it to run a PKCE authorization code flow.
type BootstrapOIDC struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	Scopes                []string `json:"scopes"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string   `json:"tokenEndpoint,omitempty"`
	RedirectURI           string   `json:"redirectUri,omitempty"`
}

type TransitionRequest struct {
	Transition model.StateTransition `json:"transition"`
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

type Config struct {
	AdminToken string
	// Authenticator, when set, resolves an SSO bearer token to an identity.
	// The static admin token always works as break-glass.
	Authenticator Authenticator
	// OIDC is advertised to the browser console for PKCE login.
	OIDC *BootstrapOIDC
}

// Authenticator resolves an SSO ID token to an authenticated identity. It is
// implemented by the OIDC verifier.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (auth.Identity, error)
}

type Server struct {
	manager    *manager.Manager
	node       *p2p.Node
	config     Config
	httpHost   *libp2phttp.Host
	publicKey  []byte
	addresses  []string
	bootstrap  []byte
	httpServer *http.Server
	oidcProxy  *oidcProxy
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
	server := &Server{
		manager:   manager,
		node:      node,
		config:    config,
		httpHost:  &libp2phttp.Host{StreamHost: node.Host},
		publicKey: publicKey,
		addresses: addresses,
		oidcProxy: newOIDCProxy(config.OIDC),
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
		server.handleSnapshot(writer, request)
	case request.Method == http.MethodGet && path == "/api/v1/presence":
		writeJSON(writer, http.StatusOK, map[string]any{"observations": server.manager.Presence()})
	case request.Method == http.MethodGet && path == "/api/v1/users":
		if !identity.Allows(auth.ModuleUsers, auth.OpRead) {
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"users": server.manager.Users()})
	case request.Method == http.MethodGet && path == "/api/v1/activity":
		server.handleActivity(writer, request)
	case request.Method == http.MethodGet && path == "/api/v1/committee/status":
		writeJSON(writer, http.StatusOK, server.committeeStatus())
	case request.Method == http.MethodGet && path == "/api/v1/schema":
		writeJSON(writer, http.StatusOK, map[string]string{"protocol": string(p2p.WebAPIProtocol)})
	case request.Method == http.MethodPost && path == "/api/v1/transitions":
		var body TransitionRequest
		if err := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20)).Decode(&body); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid request")
			return
		}
		if err := auth.AuthorizeTransition(identity, body.Transition.Type); err != nil {
			writeError(writer, http.StatusForbidden, err.Error())
			return
		}
		snapshot, err := server.manager.Submit(body.Transition)
		if err != nil {
			writeError(writer, http.StatusConflict, err.Error())
			return
		}
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			writeError(writer, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(writer, http.StatusOK, snapshot)
	default:
		writeError(writer, http.StatusNotFound, "not found")
	}
}

// handleSnapshot serves the latest certified state, or a historical height when
// ?height= is given. Historical lookups are how the console inspects the
// decision log without trusting any single manager's memory.
func (server *Server) handleSnapshot(writer http.ResponseWriter, request *http.Request) {
	if raw := request.URL.Query().Get("height"); raw != "" {
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
		writeJSON(writer, http.StatusOK, snapshot)
		return
	}
	snapshot, ok := server.manager.LatestSnapshot()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "no certified snapshot")
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
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
	writeJSON(writer, http.StatusOK, map[string]any{"entries": server.manager.Activity(limit, before)})
}

func (server *Server) committeeStatus() CommitteeStatus {
	latest, _ := server.manager.LatestSnapshot()
	height := server.manager.Height()
	committee := server.manager.Committee()
	status := CommitteeStatus{
		LocalID:       server.manager.LocalID(),
		Height:        height,
		LeaderAtHead:  server.manager.Leader(height+1, 0).ID,
		NextRound:     0,
		QuorumSize:    bft.QuorumSize,
		CommitteeSize: len(committee),
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
		status.Connected[member.ID] = err == nil && server.node.Host.Network().Connectedness(peerID) == 1
	}
	return status
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
		}
		if strings.HasPrefix(request.URL.Path, "/api/") {
			writeError(writer, http.StatusNotFound, "not found")
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
	token, ok := bearerToken(request)
	if !ok {
		return auth.Identity{}, false
	}
	if adminToken := server.config.AdminToken; adminToken != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1 {
		return auth.BreakGlass(), true
	}
	if server.config.Authenticator != nil {
		identity, err := server.config.Authenticator.Authenticate(request.Context(), token)
		if err == nil && identity.Role != "" {
			return identity, true
		}
	}
	return auth.Identity{}, false
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
