package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/netp2p/netp2p/test/loadtest"
)

func main() {
	scenario := flag.String("scenario", "quick", "quick, production, or architecture")
	peers := flag.Int("peers", 0, "fixture peer count")
	flows := flag.Int("flows", 0, "active flow count")
	domains := flag.Int("domains", 0, "routing domain count")
	managers := flag.Int("managers", 0, "manager count")
	registryPeers := flag.Int("registry-peers", 0, "durable registry peer count")
	shards := flag.Int("shards", 0, "registry shard count")
	samples := flag.Int("samples", 0, "authorization and lookup sample count")
	output := flag.String("output", "", "verification manifest path")
	registryRoot := flag.String("registry-root", "", "optional durable registry root")
	keepRegistry := flag.Bool("keep-registry", false, "keep the registry after verification")
	flag.Parse()

	options := loadtest.VerificationOptions{Scenario: *scenario}
	switch *scenario {
	case "quick":
		options.Config = loadtest.ScaleConfig{Peers: 10000, Flows: 100000, Domains: 1000, Managers: 3}
		options.RegistryPeers = 10000
		options.ShardCount = 8
		options.SampleCount = 20000
	case "production":
		options.Config = loadtest.DefaultScaleConfig()
		options.RegistryPeers = 1000000
		options.ShardCount = 16
		options.SampleCount = 100000
	case "architecture":
		options.Config = loadtest.ScaleConfig{Peers: 1000000, Flows: 0, Domains: 10000, Managers: 3}
		options.RegistryPeers = 1000000
		options.ShardCount = 32
		options.SampleCount = 100000
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q\n", *scenario)
		os.Exit(2)
	}
	if *peers != 0 {
		options.Config.Peers = *peers
	}
	if *flows != 0 {
		options.Config.Flows = *flows
	}
	if *domains != 0 {
		options.Config.Domains = *domains
	}
	if *managers != 0 {
		options.Config.Managers = *managers
	}
	if *registryPeers != 0 {
		options.RegistryPeers = *registryPeers
	}
	if *shards != 0 {
		options.ShardCount = *shards
	}
	if *samples != 0 {
		options.SampleCount = *samples
	}
	options.RegistryRoot = *registryRoot
	options.KeepRegistry = *keepRegistry
	if *output == "" {
		*output = filepath.Join("tmp", "doc", "verification",
			fmt.Sprintf("loadtest-%s-%s.json", *scenario, time.Now().UTC().Format("20060102T150405Z")))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	manifest, err := loadtest.RunScaleVerification(ctx, options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadtest failed: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode manifest: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "write manifest: %v\n", err)
		os.Exit(1)
	}
	if err := loadtest.WriteManifest(manifest, *output); err != nil {
		fmt.Fprintf(os.Stderr, "write manifest file: %v\n", err)
		os.Exit(1)
	}
	if !manifest.Pass {
		os.Exit(1)
	}
}
