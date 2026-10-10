// Command configcheck validates the Windows MSI runtime profile before a
// NetP2P service is installed.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netp2p/netp2p/packaging/windows/configcheck"
)

func main() {
	configPath := flag.String("config", defaultConfigPath(), "Windows client runtime profile")
	firstRun := flag.Bool("first-run", false, "accept an intentionally unprovisioned client profile")
	secure := flag.Bool("secure", false, "restrict the profile to SYSTEM and Administrators")
	flag.Parse()

	mode, err := configcheck.Validate(*configPath, *firstRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid NetP2P client profile: %v\n", err)
		os.Exit(1)
	}
	if *secure {
		if err := configcheck.Secure(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "invalid NetP2P client profile permissions: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("NetP2P client profile is valid (%s)\n", mode)
}

func defaultConfigPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return filepath.Join("C:", "ProgramData", "netp2p", "runtime.yaml")
	}
	return filepath.Join(programData, "netp2p", "runtime.yaml")
}
