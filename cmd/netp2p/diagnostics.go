package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/tun"
	"github.com/netp2p/netp2p/internal/version"
)

func runPing(args []string) error {
	flags := flag.NewFlagSet("ping", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	source := flags.String("source", "", "overlay source IPv4; defaults to the assigned address")
	packetListen := flags.String("packet-listen", "", "local userspace UDP packet endpoint")
	timeout := flags.Duration("timeout", 3*time.Second, "reply timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: netp2p ping <overlay-ip> [flags]")
	}
	target := net.ParseIP(flags.Arg(0))
	if target == nil {
		return fmt.Errorf("invalid overlay IP %q", flags.Arg(0))
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	if *packetListen != "" {
		cfg.PacketListen = *packetListen
	}
	sourceIP := net.ParseIP(*source)
	if sourceIP == nil {
		client := newIPCClient(cfg.IPC.Path)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var status map[string]any
		if err := client.call(ctx, "GET", "/v1/status", nil, &status); err == nil {
			if clientStatus, ok := status["client"].(map[string]any); ok {
				sourceIP = net.ParseIP(fmt.Sprint(clientStatus["overlayIP"]))
			}
		}
	}
	if sourceIP == nil {
		return fmt.Errorf("source overlay IP is unknown; pass --source")
	}
	connection, err := net.DialTimeout("udp", cfg.PacketListen, time.Second)
	if err != nil {
		return fmt.Errorf("connect packet endpoint: %w", err)
	}
	defer connection.Close()
	request, err := packet.BuildEchoRequest(sourceIP, target, 0x1234, 1, []byte("netp2p-cli"))
	if err != nil {
		return err
	}
	frame, err := packet.EncodeFrame(request)
	if err != nil {
		return err
	}
	started := time.Now()
	if _, err := connection.Write(frame); err != nil {
		return err
	}
	if err := connection.SetReadDeadline(time.Now().Add(*timeout)); err != nil {
		return err
	}
	buffer := make([]byte, 65535)
	read, err := connection.Read(buffer)
	if err != nil {
		return fmt.Errorf("ping %s: %w", target, err)
	}
	reply, err := packet.DecodeFrame(buffer[:read])
	if err != nil {
		return err
	}
	ipPacket := packet.IPv4Packet(reply)
	if err := ipPacket.Validate(); err != nil {
		return err
	}
	if packet.ICMPMessage(reply[ipPacket.HeaderLength():]).Type() != packet.ICMPTypeEchoReply {
		return fmt.Errorf("unexpected reply from %s", target)
	}
	fmt.Printf("64 bytes from %s: time=%s\n", target, time.Since(started).Round(time.Microsecond))
	return nil
}

func runNetcheck(args []string) error {
	flags := flag.NewFlagSet("netcheck", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var status map[string]any
	daemonErr := client.call(ctx, "GET", "/v1/status", nil, &status)
	printCheck("version", version.Version, nil)
	printCheck("daemon", fmt.Sprint(status["state"]), daemonErr)
	if cfg.Manager != "" {
		printCheck("manager", cfg.Manager, nil)
	} else {
		printCheck("manager", "not configured", fmt.Errorf("missing"))
	}
	if conn, err := net.ListenPacket("udp", cfg.PacketListen); err == nil {
		_ = conn.Close()
		printCheck("packet endpoint", cfg.PacketListen, nil)
	} else {
		printCheck("packet endpoint", cfg.PacketListen, err)
	}
	if cfg.NoDNS {
		printCheck("dns", "disabled", nil)
	} else if conn, err := net.ListenPacket("udp", cfg.DNSListen); err == nil {
		_ = conn.Close()
		printCheck("dns", cfg.DNSListen, nil)
	} else {
		printCheck("dns", cfg.DNSListen, err)
	}
	if cfg.NoTun {
		printCheck("tun", "disabled", nil)
	} else if device, err := tun.Open(cfg.TunName, nil); err == nil {
		_ = device.Close()
		printCheck("tun", cfg.TunName, nil)
	} else {
		printCheck("tun", cfg.TunName, err)
	}
	return nil
}

func runDoctor(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var payload struct {
		Version    string `json:"version"`
		State      string `json:"state"`
		NextAction string `json:"nextAction"`
		Checks     []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := client.call(ctx, "GET", "/v1/doctor", nil, &payload); err != nil {
		return err
	}
	fmt.Printf("netp2pd %s\n", payload.Version)
	for _, check := range payload.Checks {
		printCheck(check.Name, check.Detail, nil)
	}
	if payload.NextAction != "" {
		fmt.Printf("next action      %s\n", payload.NextAction)
	}
	return nil
}

func printCheck(name, detail string, err error) {
	if err != nil {
		fmt.Printf("FAIL %-14s %s (%v)\n", name, detail, err)
		return
	}
	fmt.Printf("ok   %-14s %s\n", name, detail)
}

func runDebugBundle(args []string) error {
	flags := flag.NewFlagSet("debug bundle", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	output := flags.String("output", "", "output ZIP path")
	includeProfile := flags.Bool("include-profile", false, "include the recoverable client identity and state files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	cfg.SetupKey = ""
	cfg.AdminToken = ""
	cfg.Alert.WebhookSecret = ""
	cfg.SSOIssuer = ""
	cfg.SSOClientID = ""
	configBody, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	var profile map[string][]byte
	if *includeProfile {
		profile, err = collectClientProfile(cfg.DataDir)
		if err != nil {
			return err
		}
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var status map[string]any
	statusErr := client.call(ctx, "GET", "/v1/status", nil, &status)
	var doctor map[string]any
	doctorErr := client.call(ctx, "GET", "/v1/doctor", nil, &doctor)
	if *output == "" {
		*output = filepath.Join(os.TempDir(), fmt.Sprintf("netp2p-debug-%s.zip", time.Now().Format("20060102-150405")))
	}
	if err := writeDebugBundle(*output, configBody, status, doctor, statusErr, doctorErr, profile); err != nil {
		return err
	}
	fmt.Println(*output)
	return nil
}

func writeDebugBundle(path string, config []byte, status, doctor map[string]any, statusErr, doctorErr error, profile map[string][]byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	archive := zip.NewWriter(file)
	write := func(name string, body []byte) error {
		entry, err := archive.Create(name)
		if err != nil {
			return err
		}
		_, err = entry.Write(body)
		return err
	}
	if err := write("runtime.json", config); err != nil {
		return err
	}
	statusBody, _ := json.MarshalIndent(status, "", "  ")
	if statusErr != nil {
		statusBody = []byte(statusErr.Error())
	}
	if err := write("status.json", statusBody); err != nil {
		return err
	}
	doctorBody, _ := json.MarshalIndent(doctor, "", "  ")
	if doctorErr != nil {
		doctorBody = []byte(doctorErr.Error())
	}
	if err := write("doctor.json", doctorBody); err != nil {
		return err
	}
	if err := write("version.txt", []byte(fmt.Sprintf("netp2p %s\nprotocol %s\n", version.Version, version.ProtocolVersion))); err != nil {
		return err
	}
	for name, body := range profile {
		if err := write("profile/"+name, body); err != nil {
			return err
		}
	}
	if profile != nil {
		manifest, err := json.MarshalIndent(map[string]any{
			"kind": "netp2p-client-profile", "version": 1, "files": profileFileNames(profile),
		}, "", "  ")
		if err != nil {
			return err
		}
		if err := write("profile/manifest.json", manifest); err != nil {
			return err
		}
	}
	return archive.Close()
}

func collectClientProfile(dataDir string) (map[string][]byte, error) {
	directory := filepath.Join(dataDir, "client")
	required := []string{"identity.key", "state.json"}
	profile := make(map[string][]byte, 3)
	for _, name := range append([]string(nil), required...) {
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, fmt.Errorf("read client profile file %s: %w", name, err)
		}
		profile[name] = body
	}
	if body, err := os.ReadFile(filepath.Join(directory, "paths.json")); err == nil {
		profile["paths.json"] = body
	}
	return profile, nil
}

func profileFileNames(profile map[string][]byte) []string {
	names := make([]string, 0, len(profile))
	for name := range profile {
		names = append(names, name)
	}
	return names
}

func runDebugProfileRestore(args []string) error {
	flags := flag.NewFlagSet("debug restore-profile", flag.ContinueOnError)
	archivePath := flags.String("archive", "", "debug bundle ZIP path")
	dataDir := flags.String("data-dir", "", "client data directory")
	overwrite := flags.Bool("overwrite", false, "replace existing profile files; stop the client first")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *archivePath == "" || *dataDir == "" {
		return fmt.Errorf("--archive and --data-dir are required")
	}
	archive, err := zip.OpenReader(*archivePath)
	if err != nil {
		return fmt.Errorf("open debug bundle: %w", err)
	}
	defer archive.Close()
	if err := validateProfileManifest(&archive.Reader); err != nil {
		return err
	}

	targetDir := filepath.Join(*dataDir, "client")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return fmt.Errorf("create client profile directory: %w", err)
	}
	entries := make(map[string]*zip.File)
	for _, entry := range archive.File {
		name := strings.TrimPrefix(entry.Name, "profile/")
		if entry.Name == name || !allowedProfileFile(name) {
			continue
		}
		entries[name] = entry
	}
	if len(entries) == 0 {
		return fmt.Errorf("debug bundle contains no client profile files")
	}
	for name := range entries {
		target := filepath.Join(targetDir, name)
		if _, err := os.Stat(target); err == nil && !*overwrite {
			return fmt.Errorf("target %s already exists; stop the client and pass --overwrite to replace it", target)
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("check profile target: %w", err)
		}
	}
	for name, entry := range entries {
		if err := restoreProfileEntry(entry, filepath.Join(targetDir, name)); err != nil {
			return err
		}
	}
	fmt.Println(targetDir)
	return nil
}

func validateProfileManifest(archive *zip.Reader) error {
	for _, entry := range archive.File {
		if entry.Name != "profile/manifest.json" {
			continue
		}
		source, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open profile manifest: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(source, 1<<20))
		closeErr := source.Close()
		if readErr != nil {
			return fmt.Errorf("read profile manifest: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close profile manifest: %w", closeErr)
		}
		var manifest struct {
			Kind    string `json:"kind"`
			Version int    `json:"version"`
		}
		if err := json.Unmarshal(body, &manifest); err != nil {
			return fmt.Errorf("decode profile manifest: %w", err)
		}
		if manifest.Kind != "netp2p-client-profile" || manifest.Version != 1 {
			return fmt.Errorf("unsupported client profile manifest %q version %d", manifest.Kind, manifest.Version)
		}
		return nil
	}
	return fmt.Errorf("debug bundle has no client profile manifest")
}

func allowedProfileFile(name string) bool {
	switch name {
	case "identity.key", "state.json", "paths.json":
		return true
	default:
		return false
	}
}

func restoreProfileEntry(entry *zip.File, target string) error {
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open profile entry %s: %w", entry.Name, err)
	}
	defer source.Close()
	temp, err := os.CreateTemp(filepath.Dir(target), ".profile-restore-*")
	if err != nil {
		return fmt.Errorf("create profile temporary file: %w", err)
	}
	if _, err := io.Copy(temp, io.LimitReader(source, 64<<20)); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return fmt.Errorf("copy profile entry %s: %w", entry.Name, err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return fmt.Errorf("sync profile entry %s: %w", entry.Name, err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("close profile entry %s: %w", entry.Name, err)
	}
	if err := os.Chmod(temp.Name(), 0o600); err != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("restrict profile entry %s: %w", entry.Name, err)
	}
	_ = os.Remove(target)
	if err := os.Rename(temp.Name(), target); err != nil {
		_ = os.Remove(temp.Name())
		return fmt.Errorf("install profile entry %s: %w", entry.Name, err)
	}
	return nil
}
