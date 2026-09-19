package presence

import (
	"testing"
	"time"
)

func TestLastWriteWinsOnNewerObservation(t *testing.T) {
	table := NewTable()
	base := time.Now().UTC()
	table.Record(Observation{PeerID: "p1", Online: true, Observer: "manager-1", LastSeen: base, UpdatedAt: base})
	table.Record(Observation{PeerID: "p1", Online: false, Observer: "manager-2", LastSeen: base, UpdatedAt: base.Add(time.Second)})

	snapshot := table.SnapshotAt(base.Add(2 * time.Second))
	if len(snapshot) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snapshot))
	}
	if snapshot[0].Observer != "manager-2" || snapshot[0].Online {
		t.Fatalf("newer observation should win: %+v", snapshot[0])
	}
}

func TestTieBreaksByObserverID(t *testing.T) {
	table := NewTable()
	at := time.Now().UTC()
	table.Record(Observation{PeerID: "p1", Online: true, Observer: "manager-1", UpdatedAt: at})
	table.Record(Observation{PeerID: "p1", Online: false, Observer: "manager-3", UpdatedAt: at})
	table.Record(Observation{PeerID: "p1", Online: true, Observer: "manager-2", UpdatedAt: at})

	snapshot := table.SnapshotAt(at)
	if snapshot[0].Observer != "manager-3" {
		t.Fatalf("expected highest observer id to win the tie, got %q", snapshot[0].Observer)
	}

	// Merging the same set in another order must converge on the same entry.
	other := NewTable()
	other.Merge([]Observation{
		{PeerID: "p1", Online: true, Observer: "manager-2", UpdatedAt: at},
		{PeerID: "p1", Online: true, Observer: "manager-1", UpdatedAt: at},
		{PeerID: "p1", Online: false, Observer: "manager-3", UpdatedAt: at},
	})
	if got := other.SnapshotAt(at)[0].Observer; got != "manager-3" {
		t.Fatalf("merge order changed the winner: %q", got)
	}
}

func TestStaleObservationsGoOffline(t *testing.T) {
	table := NewTable()
	base := time.Now().UTC()
	table.Record(Observation{PeerID: "p1", Online: true, Observer: "manager-1", LastSeen: base, UpdatedAt: base})

	if !table.SnapshotAt(base.Add(StaleAfter - time.Second))[0].Online {
		t.Fatal("observation inside the freshness window should be online")
	}
	if table.SnapshotAt(base.Add(StaleAfter + time.Second))[0].Online {
		t.Fatal("observation past the freshness window should be offline")
	}
}

func TestDisconnectKeepsLastSeen(t *testing.T) {
	table := NewTable()
	seen := table.Observe("p1", "/ip4/10.0.0.1/udp/1/quic-v1", "manager-1")
	gone := table.Disconnect("p1", "/ip4/10.0.0.1/udp/1/quic-v1", "manager-1")
	if gone.Online {
		t.Fatal("disconnect should mark the peer offline")
	}
	if !gone.LastSeen.Equal(seen.LastSeen) {
		t.Fatalf("disconnect should preserve last seen: %v vs %v", gone.LastSeen, seen.LastSeen)
	}
}

func TestMergeIgnoresOlderAndEmpty(t *testing.T) {
	table := NewTable()
	now := time.Now().UTC()
	table.Record(Observation{PeerID: "p1", Online: true, Observer: "manager-2", LastSeen: now, UpdatedAt: now})

	changed := table.Merge([]Observation{
		{PeerID: "p1", Online: false, Observer: "manager-1", UpdatedAt: now.Add(-time.Minute)},
		{PeerID: "", Online: true, Observer: "manager-1", UpdatedAt: now.Add(time.Minute)},
	})
	if changed != 0 {
		t.Fatalf("expected no changes, got %d", changed)
	}
	if !table.SnapshotAt(now)[0].Online {
		t.Fatal("older/empty observations must not overwrite state")
	}
}

func TestSnapshotIsSortedByPeerID(t *testing.T) {
	table := NewTable()
	now := time.Now().UTC()
	for _, id := range []string{"peer-c", "peer-a", "peer-b"} {
		table.Record(Observation{PeerID: id, Online: true, Observer: "manager-1", UpdatedAt: now})
	}
	snapshot := table.SnapshotAt(now)
	for index, want := range []string{"peer-a", "peer-b", "peer-c"} {
		if snapshot[index].PeerID != want {
			t.Fatalf("index %d = %q, want %q", index, snapshot[index].PeerID, want)
		}
	}
}
