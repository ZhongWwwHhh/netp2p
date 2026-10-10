package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func daemonExecutable() (string, error) {
	current, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate CLI executable: %w", err)
	}
	name := "netp2pd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidate := filepath.Join(filepath.Dir(current), name)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	if resolved, err := exec.LookPath(name); err == nil {
		return resolved, nil
	}
	return "", fmt.Errorf("netp2pd executable not found next to %s or in PATH", current)
}

func startDaemon(configPath string) (*exec.Cmd, error) {
	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	logPath := filepath.Join(cfg.DataDir, "netp2pd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon log: %w", err)
	}
	daemon, err := daemonExecutable()
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	command := exec.Command(daemon, "--config-file", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	command.Stdin = nil
	prepareDaemonCommand(command)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start netp2pd: %w", err)
	}
	go func() {
		_ = command.Wait()
		_ = logFile.Close()
	}()
	return command, nil
}

func waitForDaemon(ctx context.Context, client *ipcClient) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.call(ctx, http.MethodGet, "/v1/ping", nil, nil); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("daemon did not answer IPC within 10s")
}
