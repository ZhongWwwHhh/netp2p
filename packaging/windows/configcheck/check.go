// Package configcheck validates the Windows MSI runtime profile before the
// NetP2P service is installed. It accepts an intentionally empty first-run
// profile, but rejects partial credentials or non-Windows defaults.
package configcheck

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/netp2p/netp2p/internal/runtimeconfig"
)

// Validate parses a Windows client profile. allowFirstRun accepts the
// intentionally unprovisioned profile installed by the MSI.
func Validate(path string, allowFirstRun bool) (string, error) {
	cfg, err := runtimeconfig.Parse(path)
	if err != nil {
		return "", err
	}
	if cfg.Version != runtimeconfig.Version {
		return "", fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Role != "client" {
		return "", fmt.Errorf("role must be client, got %q", cfg.Role)
	}
	if cfg.IPC.Path != `\\.\pipe\netp2pd` {
		return "", fmt.Errorf("ipc.path must be \\\\.\\pipe\\netp2pd, got %q", cfg.IPC.Path)
	}
	if _, err := runtimeconfig.ClientMetricsListen(cfg.MetricsListen); err != nil {
		return "", err
	}
	if err := validateWindowsPath("dataDir", cfg.DataDir); err != nil {
		return "", err
	}
	if err := validateWindowsPath("trust", cfg.TrustPath); err != nil {
		return "", err
	}
	if err := validateWindowsPath("setupKeyFile", cfg.SetupKeyFile); err != nil {
		return "", err
	}

	target := cfg.Manager != "" || cfg.TrustPath != ""
	credentials := cfg.SetupKey != "" || cfg.SetupKeyFile != "" || cfg.SSO
	if !target && !credentials {
		if !allowFirstRun {
			return "", fmt.Errorf("client is not provisioned; login is required before service start")
		}
		return "first-run", nil
	}
	if target != credentials {
		if target && !credentials && allowFirstRun {
			return "logged-out", nil
		}
		return "", fmt.Errorf("client target and credentials must be provisioned together")
	}
	if err := runtimeconfig.Validate(cfg); err != nil {
		return "", err
	}
	return "configured", nil
}

func validateWindowsPath(name, value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "/var/") || strings.HasPrefix(value, "/etc/") ||
		strings.HasPrefix(value, "/run/") || strings.HasPrefix(value, "~/.netp2p/") {
		return fmt.Errorf("%s must use a Windows path, got %q", name, value)
	}
	if !filepath.IsAbs(value) || filepath.VolumeName(value) == "" {
		return fmt.Errorf("%s must be an absolute Windows path, got %q", name, value)
	}
	return nil
}

// Secure removes inherited ProgramData access and leaves the profile to
// LocalSystem (service read/run) and Administrators (management) only.
func Secure(path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("securing the Windows profile requires Windows")
	}
	icacls, err := exec.LookPath("icacls.exe")
	if err != nil {
		return fmt.Errorf("find icacls.exe: %w", err)
	}
	command := exec.Command(icacls, path,
		"/grant:r", "*S-1-5-18:F",
		"/grant:r", "*S-1-5-32-544:F",
		"/inheritance:r",
	)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("restrict config permissions: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
