//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func enableNRPT(namespace, server string) error {
	command := fmt.Sprintf(`Add-DnsClientNrptRule -Namespace %s -NameServers %s -ErrorAction Stop`, quotePowerShell(namespace), quotePowerShell(server))
	return runPowerShell(command)
}

func disableNRPT(namespace string) error {
	command := fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq %s } | Remove-DnsClientNrptRule -Force -ErrorAction Stop`, quotePowerShell(namespace))
	return runPowerShell(command)
}

func runPowerShell(command string) error {
	output, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
