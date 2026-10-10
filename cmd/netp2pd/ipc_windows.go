//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const (
	pipeAccessDuplex       = 0x00000003
	pipeTypeByte           = 0x00000000
	pipeReadmodeByte       = 0x00000000
	pipeWait               = 0x00000000
	pipeUnlimitedInstances = 255
)

type windowsPipeListener struct {
	path   string
	mu     sync.Mutex
	handle windows.Handle
	closed bool
}

type windowsPipeAddr struct{ path string }

func (addr windowsPipeAddr) Network() string { return "pipe" }
func (addr windowsPipeAddr) String() string  { return addr.path }

type windowsPipeConn struct {
	handle windows.Handle
	path   string
}

func listenIPC(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("IPC path is empty")
	}
	listener := &windowsPipeListener{path: path}
	handle, err := createPipeInstance(path)
	if err != nil {
		return nil, err
	}
	listener.handle = handle
	return listener, nil
}

func createPipeInstance(path string) (windows.Handle, error) {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("encode pipe path: %w", err)
	}
	handle, err := windows.CreateNamedPipe(
		utf16Path,
		pipeAccessDuplex,
		pipeTypeByte|pipeReadmodeByte|pipeWait,
		pipeUnlimitedInstances,
		4096,
		4096,
		0,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("create named pipe: %w", err)
	}
	return handle, nil
}

func (listener *windowsPipeListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if listener.closed {
		listener.mu.Unlock()
		return nil, net.ErrClosed
	}
	handle := listener.handle
	listener.mu.Unlock()

	for {
		err := windows.ConnectNamedPipe(handle, nil)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			continue
		}
		return nil, fmt.Errorf("accept named pipe: %w", err)
	}

	next, err := createPipeInstance(listener.path)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	listener.mu.Lock()
	listener.handle = next
	listener.mu.Unlock()
	return &windowsPipeConn{handle: handle, path: listener.path}, nil
}

func (listener *windowsPipeListener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed {
		return nil
	}
	listener.closed = true
	if listener.handle != 0 {
		return windows.CloseHandle(listener.handle)
	}
	return nil
}

func (listener *windowsPipeListener) Addr() net.Addr {
	return windowsPipeAddr{path: listener.path}
}

func (conn *windowsPipeConn) Read(buffer []byte) (int, error) {
	var read uint32
	err := windows.ReadFile(conn.handle, buffer, &read, nil)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return int(read), io.EOF
	}
	if err != nil {
		return int(read), err
	}
	return int(read), nil
}

func (conn *windowsPipeConn) Write(buffer []byte) (int, error) {
	var written uint32
	err := windows.WriteFile(conn.handle, buffer, &written, nil)
	if err != nil {
		return int(written), err
	}
	return int(written), nil
}

func (conn *windowsPipeConn) Close() error {
	_ = windows.DisconnectNamedPipe(conn.handle)
	return windows.CloseHandle(conn.handle)
}

func (conn *windowsPipeConn) LocalAddr() net.Addr              { return windowsPipeAddr{path: conn.path} }
func (conn *windowsPipeConn) RemoteAddr() net.Addr             { return windowsPipeAddr{path: conn.path} }
func (conn *windowsPipeConn) SetDeadline(time.Time) error      { return nil }
func (conn *windowsPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *windowsPipeConn) SetWriteDeadline(time.Time) error { return nil }
