package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestGenerateProductionMaterialCreatesRandomThreeManagerTrust(t *testing.T) {
	specs := productionSpecs()
	first, err := GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", specs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", specs)
	if err != nil {
		t.Fatal(err)
	}

	if first.Manifest.CommitteeParams != (model.CommitteeParams{Size: 3, FaultLimit: 0, QuorumSize: 3}) {
		t.Fatalf("committee params = %+v", first.Manifest.CommitteeParams)
	}
	if len(first.Manifest.Managers) != 3 || len(first.Bundles) != 3 || len(first.ClientTrust.Managers) != 3 {
		t.Fatalf("generated manager counts are not three")
	}
	for index := range first.Bundles {
		if first.Bundles[index].PrivateKey == second.Bundles[index].PrivateKey {
			t.Fatalf("manager %d private key is deterministic", index)
		}
		if len(first.Bundles[index].AdminToken) < productionSecretBytes || len(first.Bundles[index].SessionSecret) < productionSecretBytes {
			t.Fatalf("manager %d shared secret is too short", index)
		}
	}
	if first.Bundles[0].PrivateKey == first.Bundles[1].PrivateKey || first.Bundles[1].PrivateKey == first.Bundles[2].PrivateKey {
		t.Fatal("manager private keys are not unique")
	}
	if first.Bundles[0].AdminToken != first.Bundles[1].AdminToken || first.Bundles[1].AdminToken != first.Bundles[2].AdminToken {
		t.Fatal("admin token is not shared by all managers")
	}
	if first.Bundles[0].SessionSecret != first.Bundles[1].SessionSecret || first.Bundles[1].SessionSecret != first.Bundles[2].SessionSecret {
		t.Fatal("session secret is not shared by all managers")
	}
}

func TestGenerateProductionMaterialRejectsInvalidManagerInput(t *testing.T) {
	if _, err := GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", productionSpecs()[:2]); err == nil {
		t.Fatal("a two-manager committee was accepted")
	}
	tests := []struct {
		name   string
		mutate func(specs []ProductionManagerSpec)
	}{
		{name: "duplicate id", mutate: func(specs []ProductionManagerSpec) { specs[1].ID = specs[0].ID }},
		{name: "private ip", mutate: func(specs []ProductionManagerSpec) { specs[0].PublicIPv4 = "10.0.0.1" }},
		{name: "bad dns", mutate: func(specs []ProductionManagerSpec) { specs[0].DNSName = "not_fqdn" }},
		{name: "bad port", mutate: func(specs []ProductionManagerSpec) { specs[0].Port = 0 }},
		{name: "same transport port", mutate: func(specs []ProductionManagerSpec) { specs[0].WebRTCPort = specs[0].Port }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			specs := productionSpecs()
			test.mutate(specs)
			if _, err := GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", specs); err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}

func TestGenerateProductionMaterialKeepsPublicDocumentsSecretFree(t *testing.T) {
	material, err := GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", productionSpecs())
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(material.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	trustJSON, err := json.Marshal(material.ClientTrust)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{material.Bundles[0].AdminToken, material.Bundles[0].SessionSecret, material.Bundles[0].PrivateKey} {
		if strings.Contains(string(manifestJSON), value) || strings.Contains(string(trustJSON), value) {
			t.Fatal("public document contains private material")
		}
	}
	for _, manager := range material.Manifest.Managers {
		if manager.KeySeed != 0 {
			t.Fatal("manifest contains a deterministic key seed")
		}
	}
	for _, manager := range material.ClientTrust.Managers {
		if manager.KeySeed != 0 {
			t.Fatal("client trust contains a deterministic key seed")
		}
	}
}

func productionSpecs() []ProductionManagerSpec {
	return []ProductionManagerSpec{
		{ID: "fr", DNSName: "fr.netp2p.zhongwwhhhh.cc", PublicIPv4: "193.42.62.111", Port: 4001, WebRTCPort: 4101},
		{ID: "sg", DNSName: "sg.netp2p.zhongwwhhhh.cc", PublicIPv4: "45.127.32.84", Port: 4001, WebRTCPort: 4101},
		{ID: "us-phx", DNSName: "us-phx.netp2p.zhongwwhhhh.cc", PublicIPv4: "129.146.72.228", Port: 4001, WebRTCPort: 4101},
	}
}
