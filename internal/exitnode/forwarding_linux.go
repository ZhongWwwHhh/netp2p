//go:build linux

package exitnode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// forwardingState enables net.ipv4.ip_forward once and restores the previous
// value when the last route goes away. The previous value is saved atomically
// before the sysctl is changed so a crash cannot erase the recovery value.
type forwardingState struct {
	enabled    bool
	previous   string
	backupPath string
}

func (state *forwardingState) enable(reconciler *Reconciler) error {
	if state.enabled {
		return nil
	}
	if state.backupPath == "" {
		state.backupPath = filepath.Join(os.TempDir(), "netp2p-ip-forward.previous")
	}
	previous := ""
	if saved, err := os.ReadFile(state.backupPath); err == nil {
		previous = strings.TrimSpace(string(saved))
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read forwarding backup: %w", err)
	}
	if previous == "" {
		if current, err := os.ReadFile(reconciler.forwardingPath); err == nil {
			previous = strings.TrimSpace(string(current))
		}
	}
	if previous == "" {
		previous = "0"
	}
	if err := writeFileAtomic(state.backupPath, []byte(previous), 0o600); err != nil {
		return fmt.Errorf("save forwarding state: %w", err)
	}
	state.previous = previous

	reconciler.record("sysctl -w net.ipv4.ip_forward=1")
	if writeErr := os.WriteFile(reconciler.forwardingPath, []byte("1"), 0o644); writeErr != nil {
		current, readErr := os.ReadFile(reconciler.forwardingPath)
		if readErr != nil || strings.TrimSpace(string(current)) != "1" {
			return fmt.Errorf("enable ip forwarding: %w", writeErr)
		}
	}
	state.enabled = true
	return nil
}

func (state *forwardingState) disable(reconciler *Reconciler) error {
	if !state.enabled {
		return nil
	}
	restore := state.previous
	if restore == "" {
		restore = "0"
	}
	reconciler.record("sysctl -w net.ipv4.ip_forward=" + restore)
	state.enabled = false
	if err := os.WriteFile(reconciler.forwardingPath, []byte(restore), 0o644); err != nil {
		current, readErr := os.ReadFile(reconciler.forwardingPath)
		if readErr != nil || strings.TrimSpace(string(current)) != restore {
			return err
		}
	}
	if err := os.Remove(state.backupPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".netp2p-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}
