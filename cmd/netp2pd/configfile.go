package main

import (
	"os"

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

func loadRuntimeConfig(path string) (runtimeConfig, error) {
	return runtimeconfig.Load(path)
}

func parseRuntimeConfig(path string) (runtimeConfig, error) {
	return runtimeconfig.Parse(path)
}

func validateRuntimeConfig(cfg runtimeConfig) error {
	return runtimeconfig.Validate(cfg)
}

func writeDaemonRuntimeConfig(path string, encoded []byte) error {
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return err
	}
	return secureRuntimeConfig(path)
}
