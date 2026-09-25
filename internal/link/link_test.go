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
