package dns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// DefaultResolvConf is the file the stub resolver consults.
const DefaultResolvConf = "/etc/resolv.conf"

// ResolvConf takes over the host's stub resolver configuration and restores the
// original contents when released.
//
// This is inherently invasive, so the original file is preserved verbatim and
// restoration is idempotent: a crash that skips Restore still leaves the backup
// on disk for a human or the next run to recover from.
type ResolvConf struct {
	path     string
	backup   string
	original []byte
	hadFile  bool

	mu       sync.Mutex
	released bool
}

// Takeover points the host resolver at the local DNS listener.
func Takeover(path, listen string, upstreams []string) (*ResolvConf, error) {
	host, port, err := splitListen(listen)
	if err != nil {
		return nil, err
	}
	// resolv.conf cannot express a port, so takeover only makes sense when the
	// resolver owns the standard port.
	if port != "53" {
		return nil, fmt.Errorf("cannot take over %s: the resolver listens on port %s, not 53", path, port)
	}
	backup := path + ".netp2p.bak"
	// If a previous run left a backup behind (for example the container was
	// restarted before Restore ran), that backup is the real original: the live
	// file already points at this resolver, and treating it as the original
	// would make the resolver forward to itself.
	original, hadFile, err := readOriginal(path, backup)
	if err != nil {
		return nil, err
	}
	if hadFile {
		if err := writeFileAtomic(backup, original, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", backup, err)
		}
	}

	var builder strings.Builder
	builder.WriteString("# Managed by NetP2P. Original saved to " + backup + "\n")
	builder.WriteString("nameserver " + host + "\n")
	for _, upstream := range upstreams {
		builder.WriteString("# upstream " + upstream + "\n")
	}

	if err := writeFileAtomic(path, []byte(builder.String()), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return &ResolvConf{path: path, backup: backup, original: original, hadFile: hadFile}, nil
}

// readOriginal prefers a leftover backup over the live file.
func readOriginal(path, backup string) ([]byte, bool, error) {
	data, err := os.ReadFile(backup)
	if err == nil {
		return data, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read %s: %w", backup, err)
	}
	data, err = os.ReadFile(path)
	if err == nil {
		return data, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read %s: %w", path, err)
}

// Restore puts the original configuration back. It is safe to call twice.
func (resolv *ResolvConf) Restore() error {
	resolv.mu.Lock()
	defer resolv.mu.Unlock()
	if resolv.released {
		return nil
	}
	resolv.released = true
	if !resolv.hadFile {
		// There was no file before; remove the one we created rather than
		// leaving a NetP2P-only resolver behind.
		if err := os.Remove(resolv.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := writeFileAtomic(resolv.path, resolv.original, 0o644); err != nil {
		return fmt.Errorf("restore %s: %w", resolv.path, err)
	}
	_ = os.Remove(resolv.backup)
	return nil
}

// BackupPath reports where the original configuration was preserved.
func (resolv *ResolvConf) BackupPath() string { return resolv.backup }

// HostUpstreams returns the nameservers the host used before takeover, in
// resolv.conf order.
func HostUpstreams(path string) []string {
	// Prefer the backup so a restart of an already-taken-over host still sees
	// the real upstreams instead of this resolver itself.
	for _, candidate := range []string{path + ".netp2p.bak", path} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if servers := ParseNameservers(string(data)); len(servers) > 0 {
			return servers
		}
	}
	return nil
}

// ParseNameservers extracts nameserver entries from resolv.conf content.
func ParseNameservers(content string) []string {
	result := make([]string, 0, 4)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		if address := addressWithPort(fields[1]); address != "" {
			result = append(result, address)
		}
	}
	return result
}

func splitListen(listen string) (string, string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", "", fmt.Errorf("invalid dns listen address %q: %w", listen, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port, nil
}

// writeFileAtomic prefers a same-directory rename. Some container runtimes
// bind-mount /etc/resolv.conf and reject replacing that mount with EBUSY; for
// those files an fsync'd in-place write is the only available update, and the
// backup written beside it remains the recovery source.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".netp2p-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	renameErr := os.Rename(tempName, path)
	if renameErr == nil {
		return nil
	}
	if !errors.Is(renameErr, syscall.EBUSY) && !errors.Is(renameErr, syscall.EXDEV) {
		return renameErr
	}
	target, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer target.Close()
	if _, err := target.Write(data); err != nil {
		return err
	}
	return target.Sync()
}
