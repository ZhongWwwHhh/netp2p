//go:build !windows

package main

import "fmt"

func runServiceProcess(configPath string) error {
	return fmt.Errorf("native service mode is only implemented on Windows")
}

func manageService(action, configPath string) error {
	return fmt.Errorf("native service management is only implemented on Windows")
}
