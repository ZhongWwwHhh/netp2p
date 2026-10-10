package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/store"
)

func TestManagerBackupAndRestore(t *testing.T) {
	sourceDir := t.TempDir()
	stateStore, err := store.Open(filepath.Join(sourceDir, "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.RecordCommit(managerBackupTestSnapshot()); err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Close(); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(t.TempDir(), "manager-backup.sqlite")
	if err := runManagerCommand([]string{
		"backup", "--data-dir", sourceDir, "--output", backupPath,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal(err)
	}

	restoreDir := t.TempDir()
	if err := runManagerCommand([]string{
		"restore", "--backup", backupPath, "--data-dir", restoreDir,
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(filepath.Join(restoreDir, "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	hasLedger, err := restored.HasLedger()
	if err != nil {
		t.Fatal(err)
	}
	if !hasLedger {
		t.Fatal("restored manager database has no certified ledger")
	}
}

func TestManagerRestoreRequiresExplicitOverwrite(t *testing.T) {
	sourceDir := t.TempDir()
	stateStore, err := store.Open(filepath.Join(sourceDir, "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.RecordCommit(managerBackupTestSnapshot()); err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Close(); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "manager-backup.sqlite")
	if err := runManagerCommand([]string{
		"backup", "--data-dir", sourceDir, "--output", backupPath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := runManagerCommand([]string{
		"restore", "--backup", backupPath, "--data-dir", sourceDir,
	}); err == nil {
		t.Fatal("restore replaced an existing manager database without --overwrite")
	}
	if err := runManagerCommand([]string{
		"restore", "--backup", backupPath, "--data-dir", sourceDir, "--overwrite",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "manager.sqlite.pre-restore")); !os.IsNotExist(err) {
		t.Fatalf("staged previous database still exists: %v", err)
	}
}

func managerBackupTestSnapshot() model.SignedSnapshot {
	return model.SignedSnapshot{
		Epoch: 1, Height: 1, StateHash: []byte("test-state-hash"),
		State: model.NetworkState{
			NetworkID: "netp2p-backup-test", OverlayCIDR: "100.64.0.0/24",
		},
		Transition: model.StateTransition{Type: "genesis"},
	}
}
