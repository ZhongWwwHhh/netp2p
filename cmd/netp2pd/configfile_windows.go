//go:build windows

package main

import (
	"errors"
	"os/exec"
	"strings"
)

func secureRuntimeConfig(path string) error {
	icacls, err := exec.LookPath("icacls.exe")
	if err != nil {
		return err
	}
	command := exec.Command(icacls, path,
		"/grant:r", "*S-1-5-18:F",
		"/grant:r", "*S-1-5-32-544:F",
		"/inheritance:r",
	)
	if output, err := command.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(output)))
	}
	return nil
}
