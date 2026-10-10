//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

func runServiceProcess(configPath string) error {
	return svc.Run("NetP2PClient", &windowsService{configPath: configPath})
}

func manageService(action, configPath string) error {
	switch action {
	case "create":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		binary := fmt.Sprintf(`"%s" service run --config "%s"`, executable, configPath)
		return runSC("create", "NetP2PClient", "binPath=", binary, "start=", "auto")
	case "delete":
		return runSC("delete", "NetP2PClient")
	case "start":
		return runSC("start", "NetP2PClient")
	case "stop":
		return runSC("stop", "NetP2PClient")
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
}

func runSC(arguments ...string) error {
	command := exec.Command("sc.exe", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}

type windowsService struct {
	configPath string

	daemonMu sync.Mutex
	daemon   *daemonChild
}

func (service *windowsService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	daemon, err := launchDaemon(service.configPath)
	if err != nil {
		return true, 1
	}
	service.setDaemon(daemon)
	done := make(chan error, 1)
	go func() { done <- daemon.cmd.Wait() }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			service.clearDaemon(daemon)
			_ = daemon.closeLog()
			if err == nil {
				return false, 0
			}
			return true, 1
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				service.stopDaemon()
				select {
				case <-done:
					_ = daemon.closeLog()
				case <-time.After(5 * time.Second):
					if daemon.cmd.Process != nil {
						_ = daemon.cmd.Process.Kill()
					}
					<-done
					_ = daemon.closeLog()
				}
				return false, 0
			}
		}
	}
}

func (service *windowsService) stopDaemon() {
	daemon := service.currentDaemon()
	cfg, err := loadRuntimeConfigForIPC(service.configPath)
	if err != nil {
		return
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = client.call(ctx, "POST", "/v1/down", map[string]any{}, nil)
	// down intentionally leaves an idle daemon listening for subsequent IPC.
	// A service stop must also end that child or SCM waits forever and
	// upgrades leave the previous daemon bound to the named pipe.
	if daemon != nil && daemon.cmd.Process != nil {
		_ = daemon.cmd.Process.Kill()
	}
}

func (service *windowsService) setDaemon(daemon *daemonChild) {
	service.daemonMu.Lock()
	service.daemon = daemon
	service.daemonMu.Unlock()
}

func (service *windowsService) clearDaemon(daemon *daemonChild) {
	service.daemonMu.Lock()
	if service.daemon == daemon {
		service.daemon = nil
	}
	service.daemonMu.Unlock()
}

func (service *windowsService) currentDaemon() *daemonChild {
	service.daemonMu.Lock()
	defer service.daemonMu.Unlock()
	return service.daemon
}
