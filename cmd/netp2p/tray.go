package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func runTray(args []string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("tray app is only implemented on Windows")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	script := filepath.Join(filepath.Dir(executable), "tray.ps1")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("tray script not found: %w", err)
	}
	command := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
