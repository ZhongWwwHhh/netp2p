//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

type windowsPipeAddr struct{ path string }

func (addr windowsPipeAddr) Network() string { return "pipe" }
func (addr windowsPipeAddr) String() string  { return addr.path }

type windowsPipeConn struct {
	handle windows.Handle
	path   string
}

func dialIPC(ctx context.Context, path string) (net.Conn, error) {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode pipe path: %w", err)
	}
	handle, err := windows.CreateFile(utf16Path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open named pipe: %w", err)
	}
	return &windowsPipeConn{handle: handle, path: path}, nil
}

func (conn *windowsPipeConn) Read(buffer []byte) (int, error) {
	var read uint32
	err := windows.ReadFile(conn.handle, buffer, &read, nil)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return int(read), io.EOF
	}
	return int(read), err
}
func (conn *windowsPipeConn) Write(buffer []byte) (int, error) {
	var written uint32
	err := windows.WriteFile(conn.handle, buffer, &written, nil)
	return int(written), err
}
func (conn *windowsPipeConn) Close() error                     { return windows.CloseHandle(conn.handle) }
func (conn *windowsPipeConn) LocalAddr() net.Addr              { return windowsPipeAddr{path: conn.path} }
func (conn *windowsPipeConn) RemoteAddr() net.Addr             { return windowsPipeAddr{path: conn.path} }
func (conn *windowsPipeConn) SetDeadline(time.Time) error      { return nil }
func (conn *windowsPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *windowsPipeConn) SetWriteDeadline(time.Time) error { return nil }
