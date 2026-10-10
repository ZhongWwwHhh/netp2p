package main

import (
	"flag"
	"fmt"
)

func runService(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: netp2p service <run|install|uninstall|start|stop> [flags]")
	}
	action := args[0]
	flags := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	switch action {
	case "run":
		return runServiceProcess(*configPath)
	case "install":
		return manageWindowsService("create", *configPath)
	case "uninstall":
		return manageWindowsService("delete", *configPath)
	case "start":
		return manageWindowsService("start", *configPath)
	case "stop":
		return manageWindowsService("stop", *configPath)
	default:
		return fmt.Errorf("unknown service action %q", action)
	}
}

func manageWindowsService(action, configPath string) error {
	return manageService(action, configPath)
}
