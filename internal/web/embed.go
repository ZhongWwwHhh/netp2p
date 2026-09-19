// Package web serves the embedded console and the manager's libp2p HTTP API.
package web

import "embed"

//go:embed all:dist
var assets embed.FS

// Assets returns the Svelte console build embedded in the manager binary.
func Assets() embed.FS { return assets }
