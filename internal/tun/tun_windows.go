//go:build windows

package tun

import (
	"errors"
	"fmt"
	"io"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

var errPacketTooLarge = errors.New("packet exceeds TUN device MTU")

// openDevice attaches to a Wintun adapter through wireguard-go's TUN backend.
// It requires administrator rights and the signed Wintun driver, which
// wireguard-go installs on demand.
func openDevice(name string) (io.ReadWriteCloser, string, error) {
	if name == "" {
		name = "netp2p0"
	}
	device, err := wgtun.CreateTUN(name, DefaultMTU)
	if err != nil {
		return nil, "", fmt.Errorf("create wintun adapter %q (needs administrator): %w", name, err)
	}
	actual, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", fmt.Errorf("read wintun adapter name: %w", err)
	}
	mtu, err := device.MTU()
	if err != nil || mtu <= 0 {
		_ = device.Close()
		return nil, "", fmt.Errorf("read wintun adapter MTU: %w", err)
	}
	return newWireguardDevice(device, mtu), actual, nil
}

// wireguardDevice adapts wireguard-go's batched TUN API to the single-packet
// io.ReadWriteCloser expected by the packet endpoint. Windows devices do not
// expose a *os.File; Wintun owns its ring-buffer handle internally.
type wireguardDevice struct {
	device wgtun.Device
	mtu    int
	batch  int
	bufs   [][]byte
	sizes  []int
}

func newWireguardDevice(device wgtun.Device, mtu int) *wireguardDevice {
	batch := device.BatchSize()
	if batch <= 0 {
		batch = 1
	}
	return &wireguardDevice{
		device: device,
		mtu:    mtu,
		batch:  batch,
		bufs:   make([][]byte, batch),
		sizes:  make([]int, batch),
	}
}

func (adapter *wireguardDevice) Read(p []byte) (int, error) {
	if len(p) < adapter.mtu {
		return 0, io.ErrShortBuffer
	}
	bufs := adapter.bufs
	bufs[0] = p
	for i := 1; i < len(bufs); i++ {
		bufs[i] = nil
	}
	for i := range adapter.sizes {
		adapter.sizes[i] = 0
	}
	count, err := adapter.device.Read(bufs, adapter.sizes, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, io.ErrNoProgress
	}
	return adapter.sizes[0], nil
}

func (adapter *wireguardDevice) Write(p []byte) (int, error) {
	if len(p) > adapter.mtu {
		return 0, errPacketTooLarge
	}
	bufs := adapter.bufs
	bufs[0] = p
	for i := 1; i < len(bufs); i++ {
		bufs[i] = nil
	}
	written, err := adapter.device.Write(bufs, 0)
	if err != nil {
		return written, err
	}
	if written == 0 {
		return 0, io.ErrNoProgress
	}
	return len(p), nil
}

func (adapter *wireguardDevice) Close() error {
	return adapter.device.Close()
}
