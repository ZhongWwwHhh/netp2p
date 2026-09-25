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
//	alert:
//	  webhook: https://hooks.example/netp2p
//	  interval: 30s
//	  dropCount: 250
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
		// The alert block is nested because it groups related knobs; flatten it
		// onto the individual flags so one config schema covers everything.
		if name == "alert" {
			if err := applyAlertConfig(flags, value, explicit); err != nil {
				return err
			}
			continue
		}
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

// alertFlagNames maps the nested alert keys onto flag names.
var alertFlagNames = map[string]string{
	"webhook":         "alert-webhook",
	"webhookSecret":   "alert-webhook-secret",
	"interval":        "alert-interval",
	"dropCount":       "alert-drop-count",
	"dropRatePercent": "alert-drop-rate-percent",
}

// applyAlertConfig flattens the nested alert block onto its flags. An unknown
// key is rejected rather than silently ignored, matching the flat behavior.
func applyAlertConfig(flags *flag.FlagSet, value any, explicit map[string]bool) error {
	block, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("config file key %q must be a mapping", "alert")
	}
	for key, setting := range block {
		flagName, known := alertFlagNames[key]
		if !known {
			return fmt.Errorf("config file has unknown alert key %q", key)
		}
		if explicit[flagName] {
			continue
		}
		target := flags.Lookup(flagName)
		if target == nil {
			return fmt.Errorf("alert flag %q is not registered", flagName)
		}
		if err := target.Value.Set(fmt.Sprint(setting)); err != nil {
			return fmt.Errorf("config file alert key %q: %w", key, err)
		}
	}
	return nil
}
