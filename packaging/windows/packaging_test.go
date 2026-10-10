package windows

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/packaging/windows/configcheck"
)

type wixPackage struct {
	XMLName xml.Name `xml:"Wix"`
	Package struct {
		CustomActions []struct {
			ID         string `xml:"Id,attr"`
			FileRef    string `xml:"FileRef,attr"`
			ExeCommand string `xml:"ExeCommand,attr"`
			Return     string `xml:"Return,attr"`
		} `xml:"CustomAction"`
		ServiceInstalls []struct {
			ID    string `xml:"Id,attr"`
			Start string `xml:"Start,attr"`
		} `xml:"ServiceInstall"`
		ServiceControls []struct {
			ID    string `xml:"Id,attr"`
			Start string `xml:"Start,attr"`
		} `xml:"ServiceControl"`
	} `xml:"Package"`
}

func TestWindowsRuntimeTemplateIsFirstRunClient(t *testing.T) {
	path := filepath.Join("..", "windows", "runtime.windows.yaml")
	mode, err := configcheck.Validate(path, true)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if mode != "first-run" {
		t.Fatalf("Validate() mode = %q, want first-run", mode)
	}
	if _, err := configcheck.Validate(path, false); err == nil {
		t.Fatal("Validate() accepted an unprovisioned profile for service start")
	}

	if _, err := configcheck.Validate(filepath.Join("..", "runtime.example.yaml"), true); err == nil {
		t.Fatal("Validate() accepted the Linux runtime template on Windows")
	}
}

func TestConfiguredWindowsProfileStartsService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.yaml")
	config := strings.Join([]string{
		"version: 1",
		"role: client",
		`dataDir: C:\ProgramData\netp2p\data`,
		"manager: /ip4/127.0.0.1/udp/4001/p2p/12D3KooWTest",
		"setupKey: test-key",
		`ipc:`,
		`  path: \\.\pipe\netp2pd`,
	}, "\n")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	mode, err := configcheck.Validate(path, false)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if mode != "configured" {
		t.Fatalf("Validate() mode = %q, want configured", mode)
	}
}

func TestWiXValidatesBeforeServiceInstall(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("netp2p.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed wixPackage
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Package.CustomActions) != 1 || parsed.Package.CustomActions[0].FileRef != "ConfigCheck" ||
		parsed.Package.CustomActions[0].Return != "check" ||
		!strings.Contains(parsed.Package.CustomActions[0].ExeCommand, "--secure") {
		t.Fatalf("missing strict custom action: %+v", parsed.Package.CustomActions)
	}
	for _, service := range parsed.Package.ServiceInstalls {
		if service.ID == "NetP2PService" && service.Start != "auto" {
			t.Fatalf("service start = %q, want auto", service.Start)
		}
	}
	for _, control := range parsed.Package.ServiceControls {
		if control.ID == "NetP2PServiceControl" && control.Start != "install" {
			t.Fatalf("service control must start the idle daemon on install, got %q", control.Start)
		}
	}
	users := map[string]bool{}
	configFile := regexp.MustCompile(`(?s)<File Id="RuntimeConfig".*?</File>`).FindString(string(data))
	for _, user := range []string{"SYSTEM", "Administrators"} {
		users[user] = strings.Contains(configFile, `<Permission User="`+user+`" GenericAll="yes"`)
	}
	if !users["SYSTEM"] || !users["Administrators"] {
		t.Fatalf("config permissions = %v, want SYSTEM and Administrators control", users)
	}
}
