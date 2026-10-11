package bft

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func TestPathFamilyAndRoutingDomainTransitions(t *testing.T) {
	state := testState()
	family := model.PathFamily{
		ID: "direct-a-b", Kind: model.PathKindDirect,
		SourceGroups: []string{"clients-a"}, DestinationScopes: []string{"group:clients-b"},
		FlowClasses: model.AllFlowClasses(), MaxRTTMilliseconds: 100,
		MaxJitterMilliseconds: 20, MaxLossPercent: 1, MinBandwidthMbps: 10,
	}
	apply(t, &state, model.StateTransition{Type: TransitionUpsertPathFamily, PathFamily: &family})
	if len(state.PathFamilies) != 1 {
		t.Fatalf("path families = %+v", state.PathFamilies)
	}
	if !reflect.DeepEqual(state.PathFamilies[0].FlowClasses, []string{
		"cost", "latency", "realtime", "reliability", "throughput",
	}) {
		t.Fatalf("flow classes = %v", state.PathFamilies[0].FlowClasses)
	}

	domain := model.RoutingDomainAuthorization{
		ID: "a-b-latency", Key: model.RoutingDomainKey{
			SourceManagerID: "A", SourceGroupID: "clients-a",
			DestinationScope: "group:clients-b", FlowClass: model.FlowClassLatency,
		},
		PathFamilyIDs: []string{"direct-a-b"}, PolicyIDs: []string{"a-to-b"},
	}
	apply(t, &state, model.StateTransition{Type: TransitionUpsertRoutingDomain, Domain: &domain})
	if len(state.RoutingDomains) != 1 || state.RoutingDomains[0].ID != "a-b-latency" {
		t.Fatalf("routing domains = %+v", state.RoutingDomains)
	}

	apply(t, &state, model.StateTransition{Type: TransitionRemoveRoutingDomain, TargetID: domain.ID})
	apply(t, &state, model.StateTransition{Type: TransitionRemovePathFamily, TargetID: family.ID})
	if len(state.RoutingDomains) != 0 || len(state.PathFamilies) != 0 {
		t.Fatalf("remove left routing objects: families=%d domains=%d", len(state.PathFamilies), len(state.RoutingDomains))
	}
}

func TestRoutingDomainValidationRejectsUnsafeOrIncompleteState(t *testing.T) {
	state := testState()
	family := model.PathFamily{
		ID: "realtime-family", Kind: model.PathKindDirect,
		SourceGroups: []string{"clients-a"}, DestinationScopes: []string{"group:clients-b"},
		FlowClasses: []string{model.FlowClassRealtime}, MaxRTTMilliseconds: 100,
		MaxLossPercent: 1, MinBandwidthMbps: 10,
	}
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionUpsertPathFamily, PathFamily: &family,
	}); err == nil {
		t.Fatal("realtime family without a jitter SLA was accepted")
	}
	family.MaxJitterMilliseconds = 20
	apply(t, &state, model.StateTransition{Type: TransitionUpsertPathFamily, PathFamily: &family})

	unknownFamily := model.RoutingDomainAuthorization{
		ID: "bad-family", Key: model.RoutingDomainKey{
			SourceManagerID: "manager-a", SourceGroupID: "clients-a",
			DestinationScope: "group:clients-b", FlowClass: model.FlowClassRealtime,
		},
		PathFamilyIDs: []string{"missing"}, PolicyIDs: []string{"a-to-b"},
	}
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionUpsertRoutingDomain, Domain: &unknownFamily,
	}); err == nil {
		t.Fatal("routing domain with an unknown path family was accepted")
	}

	wrongPolicy := model.RoutingDomainAuthorization{
		ID: "bad-policy", Key: unknownFamily.Key,
		PathFamilyIDs: []string{"realtime-family"}, PolicyIDs: []string{"missing"},
	}
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionUpsertRoutingDomain, Domain: &wrongPolicy,
	}); err == nil {
		t.Fatal("routing domain with an unknown policy was accepted")
	}

	unsupportedScope := family
	unsupportedScope.ID = "bad-scope"
	unsupportedScope.DestinationScopes = []string{"everywhere"}
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionUpsertPathFamily, PathFamily: &unsupportedScope,
	}); err == nil {
		t.Fatal("unsupported destination scope was accepted")
	}
}

func TestRoutingStateIsCoveredBySignedHashes(t *testing.T) {
	state := testState()
	baseHash := StateHash(state)
	baseTransitionHash := TransitionHash(model.StateTransition{Type: TransitionGenesis})

	family := model.PathFamily{
		ID: "hash-family", Kind: model.PathKindDirect,
		SourceGroups: []string{"clients-a"}, DestinationScopes: []string{"group:clients-b"},
		FlowClasses: []string{model.FlowClassLatency}, MaxRTTMilliseconds: 50,
	}
	state.PathFamilies = []model.PathFamily{family}
	if bytes.Equal(StateHash(state), baseHash) {
		t.Fatal("StateHash ignored certified path families")
	}
	if bytes.Equal(
		TransitionHash(model.StateTransition{Type: TransitionUpsertPathFamily, PathFamily: &family}),
		baseTransitionHash,
	) {
		t.Fatal("TransitionHash ignored path-family transitions")
	}

	state.RoutingDomains = []model.RoutingDomainAuthorization{{
		ID: "hash-domain", Key: model.RoutingDomainKey{
			SourceManagerID: "manager-a", SourceGroupID: "clients-a",
			DestinationScope: "group:clients-b", FlowClass: model.FlowClassLatency,
		},
		PathFamilyIDs: []string{"hash-family"}, PolicyIDs: []string{"a-to-b"},
	}}
	if bytes.Equal(StateHash(state), baseHash) {
		t.Fatal("StateHash ignored routing-domain authorization")
	}
}

func TestEnginePruneLedgerKeepsLatestCheckpoint(t *testing.T) {
	committee, keys := testCommittee()
	engines := make([]*Engine, len(committee))
	for index, key := range keys {
		engine, err := NewEngine(testState(), committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	for index := 0; index < 3; index++ {
		advance(t, keys, engines, model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{
			ID: string(rune('x' + index)),
		}})
	}
	latest, ok := engines[0].LatestSnapshot()
	if !ok || latest.Height != 3 {
		t.Fatalf("latest height = %d ok=%v", latest.Height, ok)
	}
	result, err := engines[0].PruneLedger(time.Now(), time.Hour, snapshotLedgerBytes(latest)+1)
	if err != nil {
		t.Fatalf("prune engine ledger: %v", err)
	}
	if result.RemovedSnapshots != 2 || result.RetainedSnapshots != 1 {
		t.Fatalf("prune result = %+v", result)
	}
	if _, ok := engines[0].Snapshot(1); ok {
		t.Fatal("old committed snapshot was retained")
	}
	if _, ok := engines[0].Snapshot(3); !ok {
		t.Fatal("latest checkpoint was pruned")
	}
}

func TestEnginePrunesLedgerAfterCommit(t *testing.T) {
	committee, keys := testCommittee()
	engines := make([]*Engine, len(committee))
	for index, key := range keys {
		engine, err := NewEngine(testState(), committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	first := advance(t, keys, engines, model.StateTransition{
		Type: TransitionUpsertGroup, Group: &model.Group{ID: "first"},
	})
	if err := engines[0].SetLedgerRetention(time.Hour, snapshotLedgerBytes(first)+100); err != nil {
		t.Fatal(err)
	}
	second := advance(t, keys, engines, model.StateTransition{
		Type: TransitionUpsertGroup, Group: &model.Group{ID: "second"},
	})
	if _, ok := engines[0].Snapshot(first.Height); ok {
		t.Fatal("automatic retention did not remove the prior checkpoint")
	}
	if _, ok := engines[0].Snapshot(second.Height); !ok {
		t.Fatal("automatic retention removed the latest checkpoint")
	}
	if err := engines[0].RetentionError(); err != nil {
		t.Fatalf("automatic retention reported an error: %v", err)
	}
}

func TestCommitteeCertifiesRoutingDomainState(t *testing.T) {
	committee, keys := testCommittee()
	engines := make([]*Engine, len(committee))
	for index, key := range keys {
		engine, err := NewEngine(testState(), committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	family := model.PathFamily{
		ID: "certified-direct", Kind: model.PathKindDirect,
		SourceGroups: []string{"clients-a"}, DestinationScopes: []string{"group:clients-b"},
		FlowClasses: []string{model.FlowClassLatency}, MaxRTTMilliseconds: 50,
	}
	snapshot := advance(t, keys, engines, model.StateTransition{
		Type: TransitionUpsertPathFamily, PathFamily: &family,
	})
	if len(snapshot.State.PathFamilies) != 1 {
		t.Fatalf("certified path families = %+v", snapshot.State.PathFamilies)
	}
	domain := model.RoutingDomainAuthorization{
		ID: "certified-domain", Key: model.RoutingDomainKey{
			SourceManagerID: "A", SourceGroupID: "clients-a",
			DestinationScope: "group:clients-b", FlowClass: model.FlowClassLatency,
		},
		PathFamilyIDs: []string{"certified-direct"}, PolicyIDs: []string{"a-to-b"},
	}
	snapshot = advance(t, keys, engines, model.StateTransition{
		Type: TransitionUpsertRoutingDomain, Domain: &domain,
	})
	if len(snapshot.State.RoutingDomains) != 1 {
		t.Fatalf("certified routing domains = %+v", snapshot.State.RoutingDomains)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("validate certified routing-domain snapshot: %v", err)
	}
}
