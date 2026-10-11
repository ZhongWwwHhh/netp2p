package store

import (
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

func TestRestoreFromValidatedBackup(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "netp2p-restore-test", OverlayCIDR: "100.72.0.0/24",
	}
	engines := newEngines(t, state)
	source := openRetentionStore(t)
	defer source.Close()
	for index := 0; index < 3; index++ {
		snapshot := certify(t, engines, model.StateTransition{
			Type:  bft.TransitionUpsertGroup,
			Group: &model.Group{ID: string(rune('a' + index))},
			Actor: &model.Actor{ID: "manager-a", Name: "Manager A", Role: model.RoleAdmin},
		})
		if err := source.RecordCommit(snapshot); err != nil {
			t.Fatalf("record height %d: %v", snapshot.Height, err)
		}
	}

	backupPath := filepath.Join(t.TempDir(), "manager-backup.sqlite")
	if err := source.Backup(backupPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	target := openRetentionStore(t)
	defer target.Close()
	if err := target.RestoreFrom(backupPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	latest, ok, err := target.LatestSnapshot()
	if err != nil || !ok || latest.Height != 3 {
		t.Fatalf("restored latest = height %d ok=%v err=%v", latest.Height, ok, err)
	}

	restarted := newEngines(t, state)
	if err := target.RestoreEngine(restarted[0]); err != nil {
		t.Fatalf("restore engine: %v", err)
	}
	if restarted[0].Height() != 3 {
		t.Fatalf("restored engine height = %d, want 3", restarted[0].Height())
	}
	if len(restarted[0].CurrentState().Groups) != 3 {
		t.Fatalf("restored groups = %+v", restarted[0].CurrentState().Groups)
	}
}
