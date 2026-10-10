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

type daemonChild struct {
	cmd *exec.Cmd

	closeLog func() error
}

func startDaemon(configPath string) (*exec.Cmd, error) {
	child, err := launchDaemon(configPath)
	if err != nil {
		return nil, err
	}
	go func() {
		_ = child.cmd.Wait()
		_ = child.closeLog()
	}()
	return child.cmd, nil
}

func launchDaemon(configPath string) (*daemonChild, error) {
	// First-run MSI installs start an idle client before provisioning. Full
	// semantic validation happens when the user asks that client to connect.
	cfg, err := parseRuntimeConfig(configPath)
	if err != nil {
		recordDaemonStartError(configPath, "load config", err)
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		recordDaemonStartError(configPath, "create data directory", err)
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	logPath := filepath.Join(cfg.DataDir, "netp2pd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		recordDaemonStartError(configPath, "open daemon log", err)
		return nil, fmt.Errorf("open daemon log: %w", err)
	}
	daemon, err := daemonExecutable()
	if err != nil {
		_ = logFile.Close()
		recordDaemonStartError(configPath, "locate daemon", err)
		return nil, err
	}
	command := exec.Command(daemon, "--config-file", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	command.Stdin = nil
	prepareDaemonCommand(command)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		recordDaemonStartError(configPath, "start daemon", err)
		return nil, fmt.Errorf("start netp2pd: %w", err)
	}
	return &daemonChild{cmd: command, closeLog: logFile.Close}, nil
}

func recordDaemonStartError(configPath, stage string, err error) {
	path := filepath.Join(filepath.Dir(configPath), "service-start.err")
	message := fmt.Sprintf("%s: %s (%v)\n", time.Now().UTC().Format(time.RFC3339Nano), stage, err)
	_ = os.WriteFile(path, []byte(message), 0o600)
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
