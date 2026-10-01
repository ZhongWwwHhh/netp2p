//go:build linux

package exitnode

import (
	"fmt"
	"os"
	"strings"
)

// forwardingState enables net.ipv4.ip_forward once and restores the previous
// value when the last route goes away, so we do not leave host forwarding on.
type forwardingState struct {
	enabled  bool
	previous string
}

func (state *forwardingState) enable(reconciler *Reconciler) error {
	if state.enabled {
		return nil
	}
	previous, err := os.ReadFile(reconciler.forwardingPath)
	if err == nil {
		state.previous = strings.TrimSpace(string(previous))
	}
	// Write /proc/sys directly: minimal images (and non-Debian hosts) may not
	// ship the sysctl(8) binary, but the proc interface is always present.
	reconciler.record("sysctl -w net.ipv4.ip_forward=1")
	if writeErr := os.WriteFile(reconciler.forwardingPath, []byte("1"), 0o644); writeErr != nil {
		// A container may mount /proc/sys read-only and have the operator set
		// net.ipv4.ip_forward=1 from outside (docker --sysctl). If forwarding
		// is already on, keep going; otherwise surface the error.
		if current, readErr := os.ReadFile(reconciler.forwardingPath); readErr != nil || strings.TrimSpace(string(current)) != "1" {
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
	// Best effort: a read-only /proc/sys must not fail teardown.
	if err := os.WriteFile(reconciler.forwardingPath, []byte(restore), 0o644); err != nil {
		if current, readErr := os.ReadFile(reconciler.forwardingPath); readErr != nil || strings.TrimSpace(string(current)) != restore {
			return err
		}
	}
	return nil
}
