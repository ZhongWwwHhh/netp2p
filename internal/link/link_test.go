package link

import (
	"bytes"
	"testing"
	"time"
)

func TestAggregateIsDeterministicAndIgnoresClientReports(t *testing.T) {
	now := time.Now().UTC()
	managerObservations := []Observation{
		{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, Direction: DirectionRoundTrip, RTTMilliseconds: 20, LossPercent: 1, BandwidthMbps: 100, Samples: 5, MeasuredAt: now, Sequence: 2},
		{ObserverID: "m2", SubjectID: "m1", Scope: ScopeManagerMesh, Direction: DirectionRoundTrip, RTTMilliseconds: 22, LossPercent: 0, BandwidthMbps: 90, Samples: 5, MeasuredAt: now, Sequence: 1},
		{ObserverID: "m3", SubjectID: "m2", Scope: ScopeManagerMesh, Direction: DirectionOutbound, RTTMilliseconds: 24, LossPercent: 2, BandwidthMbps: 80, Samples: 5, MeasuredAt: now, Sequence: 1},
	}
	clientObservation := Observation{
		ObserverID: "client-a", SubjectID: "client-b", Scope: ScopePeerDirect,
		RTTMilliseconds: 1, LossPercent: 0, BandwidthMbps: 10000, Samples: 1, MeasuredAt: now,
	}
	meshOnly := append([]Observation{}, managerObservations...)
	first := Aggregate(append(meshOnly, clientObservation), now, time.Minute, 0)
	second := Aggregate(managerObservations, now, time.Minute, 0)
	if !bytes.Equal(first.Hash, second.Hash) {
		t.Fatal("client observation changed manager mesh view")
	}
	if len(first.Segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(first.Segments))
	}
	t.Logf("segments: %+v", second.Segments)
	if second.Segments[1].Confidence != 0.4 {
		t.Fatalf("one-observer segment confidence = %f", second.Segments[1].Confidence)
	}
	twoObserver := false
	for _, segment := range second.Segments {
		if segment.Confidence == 0.8 {
			twoObserver = true
			break
		}
	}
	if !twoObserver {
		t.Fatal("no two-observer segment in manager mesh view")
	}
}

func TestAggregateFiltersOutliersAndExpiredObservations(t *testing.T) {
	now := time.Now().UTC()
	fresh := Observation{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 30, BandwidthMbps: 100, Samples: 3, MeasuredAt: now}
	expired := Observation{ObserverID: "m3", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 1, BandwidthMbps: 100, Samples: 3, MeasuredAt: now.Add(-2 * time.Minute)}
	outlier := Observation{ObserverID: "m4", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 1000, BandwidthMbps: 100, Samples: 3, MeasuredAt: now}
	view := Aggregate([]Observation{fresh, expired, outlier}, now, time.Minute, 100)
	if len(view.Segments) != 1 || view.Segments[0].From != "m1" {
		t.Fatalf("unexpected segments %+v", view.Segments)
	}
}

func TestAggregateIsOrderIndependent(t *testing.T) {
	now := time.Now().UTC()
	observations := []Observation{
		{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 20, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "m2", SubjectID: "m3", Scope: ScopeManagerMesh, RTTMilliseconds: 30, BandwidthMbps: 80, Samples: 5, MeasuredAt: now},
		{ObserverID: "m3", SubjectID: "m1", Scope: ScopeManagerMesh, RTTMilliseconds: 40, BandwidthMbps: 60, Samples: 5, MeasuredAt: now},
		{ObserverID: "m1", SubjectID: "m3", Scope: ScopeManagerMesh, RTTMilliseconds: 25, BandwidthMbps: 90, Samples: 5, MeasuredAt: now},
	}
	reversed := make([]Observation, len(observations))
	for index := range observations {
		reversed[index] = observations[len(observations)-1-index]
	}
	first := Aggregate(observations, now, time.Minute, 0)
	second := Aggregate(reversed, now, time.Minute, 0)
	if !bytes.Equal(first.Hash, second.Hash) {
		t.Fatal("mesh hash depends on observation ordering")
	}
	if len(first.Centrality) != 3 {
		t.Fatalf("centrality nodes = %d, want 3", len(first.Centrality))
	}
	if len(first.AccessSegments) != 0 {
		t.Fatalf("access segments = %d, want 0", len(first.AccessSegments))
	}
}

func TestAggregateKeepsAccessSegmentsOutOfMesh(t *testing.T) {
	now := time.Now().UTC()
	mesh := Observation{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 20, BandwidthMbps: 100, Samples: 5, MeasuredAt: now}
	access := Observation{ObserverID: "m1", SubjectID: "client-a", Scope: ScopeAccess, RTTMilliseconds: 5, BandwidthMbps: 500, Samples: 5, MeasuredAt: now}
	view := Aggregate([]Observation{mesh, access}, now, time.Minute, 0)
	if len(view.Segments) != 1 {
		t.Fatalf("mesh segments = %d, want 1", len(view.Segments))
	}
	if len(view.AccessSegments) != 1 {
		t.Fatalf("access segments = %d, want 1", len(view.AccessSegments))
	}
	if view.AccessSegments[0].Confidence > accessConfidenceCap {
		t.Fatalf("access confidence = %f, want <= %f", view.AccessSegments[0].Confidence, accessConfidenceCap)
	}
	clientOnly := Aggregate([]Observation{access}, now, time.Minute, 0)
	if len(clientOnly.Centrality) != 0 {
		t.Fatalf("access-only centrality = %d, want 0", len(clientOnly.Centrality))
	}
}

func TestAggregateConfidenceTracksObserverRedundancy(t *testing.T) {
	now := time.Now().UTC()
	single := Aggregate([]Observation{
		{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 20, BandwidthMbps: 100, Samples: 1, MeasuredAt: now},
	}, now, time.Minute, 0)
	if single.Segments[0].Confidence != confidenceSingleObserver {
		t.Fatalf("single-observer confidence = %f", single.Segments[0].Confidence)
	}
	redundant := Aggregate([]Observation{
		{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, RTTMilliseconds: 20, BandwidthMbps: 100, Samples: 1, MeasuredAt: now},
		{ObserverID: "m2", SubjectID: "m1", Scope: ScopeManagerMesh, RTTMilliseconds: 22, BandwidthMbps: 95, Samples: 1, MeasuredAt: now},
	}, now, time.Minute, 0)
	if redundant.Segments[0].Confidence != confidenceTwoObservers {
		t.Fatalf("two-observer confidence = %f", redundant.Segments[0].Confidence)
	}
}

func TestOutlierWeightsDownweightsDeviatingObservation(t *testing.T) {
	weights := outlierWeights([]float64{100, 100, 1000}, []float64{10, 10, 10})
	if weights[0] != 1 || weights[1] != 1 {
		t.Fatalf("majority weights = %v, want 1", weights)
	}
	if weights[2] != outlierWeight {
		t.Fatalf("outlier weight = %f, want %f", weights[2], outlierWeight)
	}
	// Small samples are left alone: there is no majority to compare against.
	small := outlierWeights([]float64{100, 1000}, []float64{10, 10})
	if small[0] != 1 || small[1] != 1 {
		t.Fatalf("small-sample weights = %v, want 1", small)
	}
}
