// Package version exposes the build identity reported during peer registration
// and shown in the console.
package version

// Version is the client/manager protocol revision. Override at build time with
// -ldflags "-X github.com/netp2p/netp2p/internal/version.Version=...".
var Version = "0.1.0"
