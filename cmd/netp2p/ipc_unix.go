//go:build !windows

package main

import (
	"context"
	"net"
)

func dialIPC(ctx context.Context, path string) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "unix", path)
}
