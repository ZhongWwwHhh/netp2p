package main

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/netp2p/netp2p/internal/runtimeconfig"
)

const runtimeConfigVersion = runtimeconfig.Version

type runtimeConfig = runtimeconfig.Config
type telemetryConfig = runtimeconfig.TelemetryConfig
type alertConfig = runtimeconfig.AlertConfig
type ipcConfig = runtimeconfig.IPCConfig

func defaultRuntimeConfig() runtimeConfig {
	return runtimeconfig.Default()
}

func defaultIPCPath() string {
	return runtimeconfig.DefaultIPCPath()
}

func loadRuntimeConfig(path string) (runtimeConfig, error) {
	return runtimeconfig.Load(path)
}

// loadRuntimeConfigForIPC reads only the local endpoint fields needed to talk
// with an idle first-run daemon. Full validation remains on connect/login.
func loadRuntimeConfigForIPC(path string) (runtimeConfig, error) {
	cfg, err := parseRuntimeConfig(path)
	if err != nil {
		// MSI-installed profiles are intentionally writable only by the service.
		// Local CLI commands know the packaged IPC endpoint and can ask the
		// daemon to provision the protected file.
		if os.IsPermission(err) {
			cfg = runtimeconfig.Default()
			cfg.Role = "client"
			if runtime.GOOS == "windows" && os.Getenv("ProgramData") != "" {
				cfg.DataDir = filepath.Join(os.Getenv("ProgramData"), "netp2p", "data")
			}
			return cfg, nil
		}
		return runtimeConfig{}, err
	}
	if err := validateRuntimeConfig(cfg); err != nil && !runtimeconfig.IsUnprovisionedClientError(err) {
		return runtimeConfig{}, err
	}
	return cfg, nil
}

func parseRuntimeConfig(path string) (runtimeConfig, error) {
	return runtimeconfig.Parse(path)
}

func validateRuntimeConfig(cfg runtimeConfig) error {
	return runtimeconfig.Validate(cfg)
}
