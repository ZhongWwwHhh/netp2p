package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/netp2p/netp2p/internal/store"
)

func runManagerCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: netp2pd manager <backup|restore|join> [flags]")
	}
	switch args[0] {
	case "backup":
		return runManagerBackup(args[1:])
	case "restore":
		return runManagerRestore(args[1:])
	case "join":
		return runManagerJoin(args[1:])
	default:
		return fmt.Errorf("unknown manager command %q", args[0])
	}
}

func runManagerBackup(args []string) error {
	flags := flag.NewFlagSet("manager backup", flag.ContinueOnError)
	dataDir := flags.String("data-dir", "", "manager data directory")
	output := flags.String("output", "", "output SQLite backup path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *output == "" {
		return fmt.Errorf("--data-dir and --output are required")
	}

	stateStore, err := store.Open(filepath.Join(*dataDir, "manager.sqlite"))
	if err != nil {
		return err
	}
	defer stateStore.Close()
	hasLedger, err := stateStore.HasLedger()
	if err != nil {
		return err
	}
	if !hasLedger {
		return fmt.Errorf("manager database has no certified ledger; refusing an empty backup")
	}
	if err := stateStore.Backup(*output); err != nil {
		return err
	}
	if err := os.Chmod(*output, 0o600); err != nil {
		return fmt.Errorf("restrict backup permissions: %w", err)
	}
	fmt.Println(*output)
	return nil
}

func runManagerRestore(args []string) error {
	flags := flag.NewFlagSet("manager restore", flag.ContinueOnError)
	backupPath := flags.String("backup", "", "SQLite backup path")
	dataDir := flags.String("data-dir", "", "manager data directory")
	overwrite := flags.Bool("overwrite", false, "replace an existing manager database; stop the manager first")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *backupPath == "" || *dataDir == "" {
		return fmt.Errorf("--backup and --data-dir are required")
	}
	if err := validateManagerBackup(*backupPath); err != nil {
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create manager data directory: %w", err)
	}

	target := filepath.Join(*dataDir, "manager.sqlite")
	if _, err := os.Stat(target); err == nil && !*overwrite {
		return fmt.Errorf("target %s already exists; stop the manager and pass --overwrite to replace it", target)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("check restore target: %w", err)
	}

	temp, err := copyManagerBackup(*backupPath, *dataDir)
	if err != nil {
		return err
	}
	previous := target + ".pre-restore"
	if _, err := os.Stat(previous); err == nil {
		_ = os.Remove(temp)
		return fmt.Errorf("incomplete previous restore detected at %s", previous)
	} else if err != nil && !os.IsNotExist(err) {
		_ = os.Remove(temp)
		return fmt.Errorf("check previous restore marker: %w", err)
	}

	replacedExisting := false
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, previous); err != nil {
			_ = os.Remove(temp)
			return fmt.Errorf("stage existing manager database: %w", err)
		}
		replacedExisting = true
	} else if err != nil && !os.IsNotExist(err) {
		_ = os.Remove(temp)
		return fmt.Errorf("check manager database: %w", err)
	}
	if err := os.Rename(temp, target); err != nil {
		if replacedExisting {
			_ = os.Rename(previous, target)
		}
		_ = os.Remove(temp)
		return fmt.Errorf("install restored manager database: %w", err)
	}
	_ = os.Remove(previous)
	_ = os.Remove(target + "-wal")
	_ = os.Remove(target + "-shm")
	fmt.Println(target)
	return nil
}

func validateManagerBackup(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("check backup: %w", err)
	}
	backup, err := store.Open(path)
	if err != nil {
		return err
	}
	defer backup.Close()
	hasLedger, err := backup.HasLedger()
	if err != nil {
		return err
	}
	if !hasLedger {
		return fmt.Errorf("backup has no certified ledger")
	}
	return nil
}

func copyManagerBackup(source, directory string) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", fmt.Errorf("open backup: %w", err)
	}
	defer input.Close()
	temp, err := os.CreateTemp(directory, ".manager-restore-*.sqlite")
	if err != nil {
		return "", fmt.Errorf("create restore temporary file: %w", err)
	}
	if _, err := io.Copy(temp, input); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return "", fmt.Errorf("copy backup: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return "", fmt.Errorf("sync restored backup: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(temp.Name())
		return "", fmt.Errorf("close restored backup: %w", err)
	}
	if err := os.Chmod(temp.Name(), 0o600); err != nil {
		_ = os.Remove(temp.Name())
		return "", fmt.Errorf("restrict restored backup: %w", err)
	}
	return temp.Name(), nil
}
