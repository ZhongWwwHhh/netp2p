//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func prepareDaemonCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows_CREATE_NEW_PROCESS_GROUP | windows_DETACHED_PROCESS}
}

const (
	windows_CREATE_NEW_PROCESS_GROUP = 0x00000200
	windows_DETACHED_PROCESS         = 0x00000008
)
