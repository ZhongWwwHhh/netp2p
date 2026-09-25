package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// applyRuntimeConfig loads a YAML or JSON file whose keys are flag names and
// applies each value to its flag, unless that flag was set explicitly on the
// command line. This keeps the seed (cryptographic topology) separate from the
// runtime configuration (addresses, roles, tuning) while preserving the
// familiar flag interface.
//
// JSON is accepted because it is a subset of YAML, so a single decoder handles
// both formats. Example:
//
//	role: manager
//	dataDir: /var/lib/netp2p
//	webListen: 0.0.0.0:8080
//	metricsListen: 127.0.0.1:9100
func applyRuntimeConfig(path string) error {
	if path == "" {
		return nil
	}
	explicit := make(map[string]bool)
	flag.Visit(func(flagValue *flag.Flag) { explicit[flagValue.Name] = true })
	return applyConfigToFlags(flag.CommandLine, path, explicit)
}

func applyConfigToFlags(flags *flag.FlagSet, path string, explicit map[string]bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	values := make(map[string]any)
	if err := yaml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("decode config file: %w", err)
	}
	for name, value := range values {
		if explicit[name] {
			continue
		}
		target := flags.Lookup(name)
		if target == nil {
			return fmt.Errorf("config file has unknown key %q", name)
		}
		if err := target.Value.Set(fmt.Sprint(value)); err != nil {
			return fmt.Errorf("config file key %q: %w", name, err)
		}
	}
	return nil
}
