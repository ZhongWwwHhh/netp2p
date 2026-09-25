package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
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
		p2p.WebAPIProtocol,
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

	// The transition that produced this snapshot must survive validation, which
	// is what makes the Activity page an authenticated decision log.
	if certified.Transition.Type != bft.TransitionUpsertPolicy {
		t.Fatalf("snapshot does not carry its transition: %+v", certified.Transition)
	}
}

func TestWebSPAFallbackAndActivity(t *testing.T) {
	group := newCluster(t, testState())
	server, bootstrap := newWebServer(t, group, 0)

	// Deep links must serve the SPA shell so client-side routing survives a
	// hard refresh, while asset and API lookups keep their real semantics.
	for _, path := range []string{"/peers", "/policies", "/dns/nameservers"} {
		response, err := http.Get(bootstrap.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status %d", path, response.StatusCode)
		}
		if !strings.Contains(string(body), "<div id=\"app\">") {
			t.Fatalf("%s did not serve the SPA shell", path)
		}
	}
	missingAsset, err := http.Get(bootstrap.URL + "/assets/missing.js")
	if err != nil {
		t.Fatal(err)
	}
	missingAsset.Body.Close()
	if missingAsset.StatusCode != http.StatusNotFound {
		t.Fatalf("missing asset status %d, want 404", missingAsset.StatusCode)
	}
	unknownAPI, err := http.Get(bootstrap.URL + "/api/v1/nope")
	if err != nil {
		t.Fatal(err)
	}
	unknownAPI.Body.Close()
	if unknownAPI.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown api status %d, want 404", unknownAPI.StatusCode)
	}

	go func() { _ = server.HTTPHost().Serve() }()
	// Dial from a different manager: a host cannot open a stream to itself.
	otherServer, _ := newWebServer(t, group, 1)
	go func() { _ = otherServer.HTTPHost().Serve() }()
	client, err := otherServer.HTTPHost().NamespacedClient(
		p2p.WebAPIProtocol,
		peer.AddrInfo{ID: group.nodes[0].Host.ID(), Addrs: group.nodes[0].Host.Addrs()},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Unauthenticated reads must not leak certified state or presence.
	for _, path := range []string{"/api/v1/activity", "/api/v1/presence"} {
		request, _ := http.NewRequest(http.MethodGet, path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without a token status %d, want 401", path, response.StatusCode)
		}
	}

	activityRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/activity?limit=5", nil)
	activityRequest.Header.Set("Authorization", "Bearer test-token")
	activityResponse, err := client.Do(activityRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer activityResponse.Body.Close()
	if activityResponse.StatusCode != http.StatusOK {
		t.Fatalf("activity status %d", activityResponse.StatusCode)
	}
	var activity struct {
		Entries []model.SignedSnapshot `json:"entries"`
	}
	if err := json.NewDecoder(activityResponse.Body).Decode(&activity); err != nil {
		t.Fatal(err)
	}
	if len(activity.Entries) == 0 {
		t.Fatal("activity log is empty")
	}
	for index, entry := range activity.Entries {
		if err := bft.ValidateSnapshot(entry); err != nil {
			t.Fatalf("activity entry %d does not validate: %v", index, err)
		}
		if index > 0 && entry.Height >= activity.Entries[index-1].Height {
			t.Fatal("activity entries are not in descending height order")
		}
	}

	heightRequest, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/snapshot?height=%d", activity.Entries[0].Height), nil)
	heightRequest.Header.Set("Authorization", "Bearer test-token")
	heightResponse, err := client.Do(heightRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer heightResponse.Body.Close()
	if heightResponse.StatusCode != http.StatusOK {
		t.Fatalf("historical snapshot status %d", heightResponse.StatusCode)
	}

	missingRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/snapshot?height=99999", nil)
	missingRequest.Header.Set("Authorization", "Bearer test-token")
	missingResponse, err := client.Do(missingRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer missingResponse.Body.Close()
	if missingResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown height status %d, want 404", missingResponse.StatusCode)
	}
}

// TestWebOperationalEndpoints covers the diagnostics/audit/path/quota surface
// added for operators: every endpoint must require a token, and the payload
// must be derived from certified state plus explicitly non-certified local
// observations.
func TestWebOperationalEndpoints(t *testing.T) {
	group := newCluster(t, testState())
	server, _ := newWebServer(t, group, 0)
	go func() { _ = server.HTTPHost().Serve() }()
	otherServer, _ := newWebServer(t, group, 1)
	go func() { _ = otherServer.HTTPHost().Serve() }()
	client, err := otherServer.HTTPHost().NamespacedClient(
		p2p.WebAPIProtocol,
		peer.AddrInfo{ID: group.nodes[0].Host.ID(), Addrs: group.nodes[0].Host.Addrs()},
	)
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{"/api/v1/events", "/api/v1/diagnostics", "/api/v1/assignments", "/api/v1/quota"}
	for _, path := range paths {
		request, _ := http.NewRequest(http.MethodGet, path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without a token status %d, want 401", path, response.StatusCode)
		}
	}

	for _, path := range paths {
		request, _ := http.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer test-token")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]json.RawMessage
		decodeErr := json.NewDecoder(response.Body).Decode(&decoded)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status %d, want 200", path, response.StatusCode)
		}
		if decodeErr != nil {
			t.Fatalf("%s decode: %v", path, decodeErr)
		}
		if len(decoded) == 0 {
			t.Fatalf("%s returned an empty object", path)
		}
	}

	// The audit log is the authenticated decision log, so every event must map
	// back to a certified snapshot.
	eventsRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/events?limit=10", nil)
	eventsRequest.Header.Set("Authorization", "Bearer test-token")
	eventsResponse, err := client.Do(eventsRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer eventsResponse.Body.Close()
	var events struct {
		Events []web.AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(eventsResponse.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events.Events) == 0 {
		t.Fatal("audit event log is empty")
	}
	entry := events.Events[0]
	if entry.Height == 0 || entry.Type == "" || entry.TransitionHash == "" || entry.StateHash == "" {
		t.Fatalf("incomplete audit event: %+v", entry)
	}
	if entry.CommitteeEpoch != 0 && len(entry.SignerBitmap) == 0 {
		t.Fatalf("audit event lacks a signer bitmap: %+v", entry)
	}

	// The static admin token maps to a stable break-glass actor, and a caller
	// must not be able to forge one by sending it in the request body.
	transition := model.StateTransition{
		Type:  bft.TransitionUpsertGroup,
		Group: &model.Group{ID: "actor-forged"},
		Actor: &model.Actor{ID: "attacker", Name: "Mallory", Role: model.RoleOwner},
	}
	body, _ := json.Marshal(web.TransitionRequest{Transition: transition})
	writeRequest, _ := http.NewRequest(http.MethodPost, "/api/v1/transitions", bytes.NewReader(body))
	writeRequest.Header.Set("Authorization", "Bearer test-token")
	writeResponse, err := client.Do(writeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer writeResponse.Body.Close()
	if writeResponse.StatusCode != http.StatusOK {
		t.Fatalf("forged-actor transition status %d, want 200", writeResponse.StatusCode)
	}
	var certified model.SignedSnapshot
	if err := json.NewDecoder(writeResponse.Body).Decode(&certified); err != nil {
		t.Fatal(err)
	}
	if certified.Transition.Actor == nil {
		t.Fatal("certified transition has no actor")
	}
	if certified.Transition.Actor.ID != "static-admin" {
		t.Fatalf("caller-supplied actor was not overridden: %+v", certified.Transition.Actor)
	}

	// Filtering by actor must return the break-glass events and exclude others.
	filteredRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/events?actor=static-admin", nil)
	filteredRequest.Header.Set("Authorization", "Bearer test-token")
	filteredResponse, err := client.Do(filteredRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer filteredResponse.Body.Close()
	var filtered struct {
		Events []web.AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(filteredResponse.Body).Decode(&filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Events) == 0 {
		t.Fatal("actor filter returned no break-glass events")
	}
	for _, event := range filtered.Events {
		if event.Actor == nil || event.Actor.ID != "static-admin" {
			t.Fatalf("actor filter leaked a foreign event: %+v", event.Actor)
		}
	}

	missingRequest, _ := http.NewRequest(http.MethodGet, "/api/v1/events?actor=nobody", nil)
	missingRequest.Header.Set("Authorization", "Bearer test-token")
	missingResponse, err := client.Do(missingRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer missingResponse.Body.Close()
	var missing struct {
		Events []web.AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(missingResponse.Body).Decode(&missing); err != nil {
		t.Fatal(err)
	}
	if len(missing.Events) != 0 {
		t.Fatalf("unknown actor returned %d events, want 0", len(missing.Events))
	}
}
