package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func sampleRoutingStatus() RoutingStatus {
	now := time.Now().UTC()
	return RoutingStatus{
		NetworkID:            "net-test",
		SnapshotHeight:       42,
		Mode:                 "runtime",
		SupportedFlowClasses: model.AllFlowClasses(),
		Domains: []model.RoutingDomainAuthorization{{
			ID: "manager-1/workstations/group:servers/realtime",
			Key: model.RoutingDomainKey{
				SourceManagerID: "manager-1", SourceGroupID: "workstations",
				DestinationScope: "group:servers", FlowClass: model.FlowClassRealtime,
			},
			PathFamilyIDs: []string{"family-a"},
			PolicyIDs:     []string{"allow-workstations"},
		}},
		PathFamilies: []model.PathFamily{{
			ID: "family-a", Kind: model.PathKindViaManager,
			ManagerHops: []string{"manager-1"}, SourceGroups: []string{"workstations"},
			DestinationScopes: []string{"group:servers"}, FlowClasses: model.AllFlowClasses(),
			MaxJitterMilliseconds: 8,
		}},
		Epoch: &RoutingEpoch{
			NetworkID: "net-test", SnapshotHeight: 42, Version: 7,
			GeneratedAt: now, ExpiresAt: now.Add(time.Minute), ManagerID: "manager-1",
			SignatureVerified: true, ThresholdSigned: true,
			Allocations: []PathAllocation{{
				Key: RoutingAllocationKey{
					SourceManagerID: "manager-1", SourceGroupID: "workstations",
					DestinationScope: "group:servers", FlowClass: model.FlowClassRealtime,
				},
				Paths: []PathWeight{{PathID: "family-a", Weight: 1, Reason: "sla"}},
			}},
		},
		ManagerCapacity: []ManagerCapacityStatus{{
			ManagerID: "manager-1", Configured: true, MonthlyBytes: 1000, UsedBytes: 900,
			RemainingBytes: 100, Pressure: .9, State: "projected-exhaustion", UpdatedAt: now,
		}},
		Telemetry: []EdgeTelemetry{{
			EdgeID: "manager-1->manager-2", ManagerID: "manager-1", QueueDepth: 12,
			QueueDepthEWMA: 10, ActiveFlows: 1000, RTTMilliseconds: 25, UpdatedAt: now,
		}},
		Demand: []DemandSample{{
			PeerID: "peer-1", SourceGroupID: "workstations", DestinationScope: "group:servers",
			FlowClass: model.FlowClassRealtime, PathID: "family-a", Bytes: 4096,
			DurationMS: 1000, ObservedAt: now,
		}},
		Fec: FECDiagnostics{
			Enabled: true, DefaultCodec: "reed-solomon", MaxRedundancyPercent: 25,
			Classes: []FECClassDiagnostics{{
				FlowClass: model.FlowClassRealtime, Enabled: true, Packets: 1000,
				RecoveredPackets: 20, GeneratedRedundancyPackets: 250,
				OverheadRatio: .25, RecoveredRatio: .02,
			}},
		},
	}
}

func TestRoutingStatusAPISurfacesGlobalBalancerState(t *testing.T) {
	server := newTestServer()
	server.config.RoutingStatus = sampleRoutingStatus
	request := httptest.NewRequest(http.MethodGet, "/api/v1/routing/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %q, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Routing RoutingStatus `json:"routing"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	status := payload.Routing
	if !reflect.DeepEqual(status.SupportedFlowClasses, model.AllFlowClasses()) {
		t.Fatalf("flow classes = %v, want the complete five-class set", status.SupportedFlowClasses)
	}
	if len(status.Domains) != 1 || status.Domains[0].Key.FlowClass != model.FlowClassRealtime {
		t.Fatalf("domains = %+v", status.Domains)
	}
	if len(status.PathFamilies) != 1 || status.PathFamilies[0].ID != "family-a" {
		t.Fatalf("path families = %+v", status.PathFamilies)
	}
	if status.PathFamilies[0].MaxJitterMilliseconds != 8 {
		t.Fatalf("path family jitter SLA = %v, want 8ms", status.PathFamilies[0].MaxJitterMilliseconds)
	}
	if status.Epoch == nil || !status.Epoch.SignatureVerified || len(status.Epoch.Allocations) != 1 {
		t.Fatalf("epoch = %+v", status.Epoch)
	}
	if len(status.ManagerCapacity) != 1 || status.ManagerCapacity[0].State != "projected-exhaustion" {
		t.Fatalf("manager capacity = %+v", status.ManagerCapacity)
	}
	if len(status.Telemetry) != 1 || len(status.Demand) != 1 {
		t.Fatalf("telemetry = %+v demand = %+v", status.Telemetry, status.Demand)
	}
	if !status.Fec.Enabled || len(status.Fec.Classes) != 1 {
		t.Fatalf("fec = %+v", status.Fec)
	}
}

func TestRoutingPathFamiliesSubresource(t *testing.T) {
	server := newTestServer()
	server.config.RoutingStatus = sampleRoutingStatus
	request := httptest.NewRequest(http.MethodGet, "/api/v1/routing/path-families", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %q, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		PathFamilies []model.PathFamily `json:"pathFamilies"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.PathFamilies) != 1 || payload.PathFamilies[0].ID != "family-a" {
		t.Fatalf("path families = %+v", payload.PathFamilies)
	}
}

func TestRoutingStatusWithoutRuntimeIsExplicit(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/routing/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %q, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Routing RoutingStatus `json:"routing"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Routing.Mode != "unavailable" {
		t.Fatalf("mode = %q, want unavailable", payload.Routing.Mode)
	}
	if payload.Routing.Domains == nil || payload.Routing.PathFamilies == nil ||
		payload.Routing.Telemetry == nil || payload.Routing.Demand == nil ||
		payload.Routing.Fec.Classes == nil || payload.Routing.Problems == nil {
		t.Fatalf("status collections must serialize as arrays: %+v", payload.Routing)
	}
}
