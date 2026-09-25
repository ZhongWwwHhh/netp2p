package client

import "path/filepath"

// Option customizes the client at construction time.
type Option func(*Client)

// WithStateDir enables path hot-standby persistence, storing the last-known-good
// path and admission conclusions in <dir>/paths.json so a restart resumes from
// the previous decision instead of re-probing from scratch. An empty directory
// disables persistence, which is the default when no option is passed.
func WithStateDir(dir string) Option {
	return func(client *Client) {
		if dir == "" {
			return
		}
		client.pathStore = loadPathStore(filepath.Join(dir, "paths.json"), defaultPathTTL)
	}
}

// Close releases persistence resources, flushing pending state to disk.
func (client *Client) Close() {
	if client.pathStore != nil {
		client.pathStore.close()
	}
}
