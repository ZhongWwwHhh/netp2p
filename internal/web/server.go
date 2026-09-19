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
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/http"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

type BootstrapResponse struct {
	PeerID          string                  `json:"peerId"`
	PublicKey       []byte                  `json:"publicKey"`
	WebRTCAddresses []string                `json:"webrtcAddresses"`
	APIProtocol     string                  `json:"apiProtocol"`
	APIBase         string                  `json:"apiBase"`
	NetworkID       string                  `json:"networkId"`
	Committee       []model.CommitteeMember `json:"committee"`
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
		Committee:       manager.Committee(),
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
	if !authorize(request, server.config.AdminToken) {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	path := strings.TrimSuffix(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodGet && path == "/api/v1/snapshot":
		snapshot, ok := server.manager.LatestSnapshot()
		if !ok {
			writeError(writer, http.StatusServiceUnavailable, "no certified snapshot")
			return
		}
		writeJSON(writer, http.StatusOK, snapshot)
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
		fileServer.ServeHTTP(writer, request)
	})
}

func authorize(request *http.Request, adminToken string) bool {
	header := request.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	token := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1
}
