package main

import (
	"fmt"
	"os"
)

const usage = `NetP2P client CLI

Usage:
  netp2p init network [flags]
  netp2p init production [flags]
  netp2p up [flags]
  netp2p down [flags]
  netp2p status [--json]
  netp2p ip [flags]
  netp2p login [flags]
  netp2p logout [flags]
  netp2p ping <overlay-ip> [flags]
  netp2p netcheck [flags]
  netp2p doctor [flags]
  netp2p debug bundle [flags]
  netp2p debug restore-profile [flags]
  netp2p service <run|install|uninstall|start|stop> [flags]
  netp2p tray [flags]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command := os.Args[1]
	args := os.Args[2:]
	var err error
	switch command {
	case "init":
		if len(args) == 0 || (args[0] != "network" && args[0] != "production") {
			fmt.Fprintln(os.Stderr, "usage: netp2p init network [flags]\n       netp2p init production [flags]")
			os.Exit(2)
		}
		if args[0] == "network" {
			err = runInitNetwork(args[1:])
		} else {
			err = runInitProduction(args[1:])
		}
	case "up":
		err = runUp(args)
	case "down":
		err = runDown(args)
	case "status":
		err = runStatus(args)
	case "ip":
		err = runIP(args)
	case "login":
		err = runLogin(args)
	case "logout":
		err = runLogout(args)
	case "ping":
		err = runPing(args)
	case "netcheck":
		err = runNetcheck(args)
	case "doctor":
		err = runDoctor(args)
	case "debug":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: netp2p debug bundle|restore-profile [flags]")
			os.Exit(2)
		}
		switch args[0] {
		case "bundle":
			err = runDebugBundle(args[1:])
		case "restore-profile":
			err = runDebugProfileRestore(args[1:])
		default:
			fmt.Fprintln(os.Stderr, "usage: netp2p debug bundle|restore-profile [flags]")
			os.Exit(2)
		}
	case "service":
		err = runService(args)
	case "tray":
		err = runTray(args)
	case "version":
		err = runVersion()
	case "-v", "--version":
		err = runVersion()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", command, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netp2p:", err)
		os.Exit(1)
	}
}
