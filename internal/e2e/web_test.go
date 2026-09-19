package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/web"
)

func newWebServer(t *testing.T, group *cluster, index int) (*web.Server, *httptest.Server) {
	t.Helper()
	server, err := web.NewServer(group.nodes[index], group.managers[index], web.Config{AdminToken: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := httptest.NewServer(server.BootstrapHandler())
	t.Cleanup(bootstrap.Close)
	return server, bootstrap
}

func TestWebBootstrapAndAPI(t *testing.T) {
	group := newCluster(t, testState())
	for _, address := range group.nodes[0].Host.Addrs() {
		if strings.Contains(address.String(), "/webrtc-direct") {
			t.Logf("manager WebRTC address: %s", address)
		}
	}
	_, bootstrap := newWebServer(t, group, 0)

	response, err := http.Get(bootstrap.URL + "/api/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap status %d", response.StatusCode)
	}
	var info web.BootstrapResponse
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.PeerID == "" || len(info.WebRTCAddresses) == 0 || info.NetworkID != networkID || len(info.Committee) != bft.CommitteeSize {
		t.Fatalf("unexpected bootstrap: %+v", info)
	}

	page, err := http.Get(bootstrap.URL + "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("console status %d", page.StatusCode)
	}

	apiRequest, _ := http.NewRequest(http.MethodGet, bootstrap.URL+"/api/bootstrap", nil)
	response, err = http.DefaultClient.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unauthenticated bootstrap status %d, want 200", response.StatusCode)
	}
	apiRequest, _ = http.NewRequest(http.MethodGet, bootstrap.URL+"/index.html", nil)
	response, err = http.DefaultClient.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("console status %d, want 200", response.StatusCode)
	}
	apiRequest, _ = http.NewRequest(http.MethodGet, bootstrap.URL+"/healthz", nil)
	response, err = http.DefaultClient.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status %d, want 200", response.StatusCode)
	}
}

func TestWebAPITransitionAndSnapshot(t *testing.T) {
	group := newCluster(t, testState())
	server, bootstrap := newWebServer(t, group, 0)
	go func() {
		_ = server.HTTPHost().Serve()
	}()
	otherServer, _ := newWebServer(t, group, 1)
	go func() {
		_ = otherServer.HTTPHost().Serve()
	}()

	response, err := http.Get(bootstrap.URL + "/api/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var info web.BootstrapResponse
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.WebRTCAddresses[0], "/webrtc-direct/") {
		t.Fatalf("bootstrap does not advertise WebRTC: %q", info.WebRTCAddresses[0])
	}
	client, err := otherServer.HTTPHost().NamespacedClient(
		"/netp2p/web-api/1.0.0",
		peer.AddrInfo{ID: group.nodes[0].Host.ID(), Addrs: group.nodes[0].Host.Addrs()},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	snapshotRequest.Header.Set("Authorization", "Bearer test-token")
	snapshotResponse, err := client.Do(snapshotRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotResponse.Body.Close()
	if snapshotResponse.StatusCode != http.StatusOK {
		t.Fatalf("API snapshot status %d", snapshotResponse.StatusCode)
	}
	var snapshot model.SignedSnapshot
	if err := json.NewDecoder(snapshotResponse.Body).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if err := bft.ValidateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}

	transition := model.StateTransition{Type: bft.TransitionUpsertPolicy, Policy: &model.Policy{
		ID: "web-created", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
		Services: []model.Service{{Protocol: "tcp", StartPort: 80, EndPort: 80}}, Effect: model.EffectAllow, Direction: model.DirectionBidirectional,
	}}
	body, _ := json.Marshal(web.TransitionRequest{Transition: transition})
	writeRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/transitions", bytes.NewReader(body))
	writeRequest.Header.Set("Authorization", "Bearer test-token")
	writeRequest.Header.Set("Content-Type", "application/json")
	writeResponse, err := client.Do(writeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer writeResponse.Body.Close()
	if writeResponse.StatusCode != http.StatusOK {
		t.Fatalf("transition status %d", writeResponse.StatusCode)
	}
	var certified model.SignedSnapshot
	if err := json.NewDecoder(writeResponse.Body).Decode(&certified); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, policy := range certified.State.Policies {
		if policy.ID == "web-created" {
			found = true
		}
	}
	if !found {
		t.Fatal("certified snapshot missing web-created policy")
	}
}
