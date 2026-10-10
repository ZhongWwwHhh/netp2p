//go:build windows

package tun

import (
	"errors"
	"io"
	"os"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type fakeWintunDevice struct {
	batch      int
	closed     bool
	readBufLen int
	readSize   int
	writeBuf   []byte
	writeCount int
}

func (device *fakeWintunDevice) File() *os.File { return nil }
func (device *fakeWintunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	device.readBufLen = len(bufs[0]) - offset
	sizes[0] = device.readSize
	return 1, nil
}
func (device *fakeWintunDevice) Write(bufs [][]byte, offset int) (int, error) {
	device.writeBuf = bufs[0][offset:]
	device.writeCount++
	return len(bufs), nil
}
func (device *fakeWintunDevice) MTU() (int, error)          { return 1280, nil }
func (device *fakeWintunDevice) Name() (string, error)      { return "netp2p0", nil }
func (device *fakeWintunDevice) Events() <-chan wgtun.Event { return nil }
func (device *fakeWintunDevice) Close() error {
	if device.closed {
		return errors.New("already closed")
	}
	device.closed = true
	return nil
}
func (device *fakeWintunDevice) BatchSize() int { return device.batch }

func TestWireguardDeviceAdapterUsesBatchAPI(t *testing.T) {
	fake := &fakeWintunDevice{batch: 2, readSize: 84}
	adapter := newWireguardDevice(fake, 1280)
	if adapter.batch != 2 {
		t.Fatalf("batch size = %d, want 2", adapter.batch)
	}

	buffer := make([]byte, 1500)
	read, err := adapter.Read(buffer)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if read != 84 || fake.readBufLen != 1500 {
		t.Fatalf("Read = (%d, len %d), want (84, len 1500)", read, fake.readBufLen)
	}

	packet := make([]byte, 1280)
	written, err := adapter.Write(packet)
	if err != nil || written != len(packet) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", written, err, len(packet))
	}
	if len(fake.writeBuf) != len(packet) || fake.writeCount != 1 {
		t.Fatalf("device write = (len %d, count %d), want (len %d, count 1)", len(fake.writeBuf), fake.writeCount, len(packet))
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fake.closed {
		t.Fatal("underlying device was not closed")
	}
}

func TestWireguardDeviceAdapterEnforcesMTU(t *testing.T) {
	fake := &fakeWintunDevice{batch: 1}
	adapter := newWireguardDevice(fake, 1280)

	if _, err := adapter.Read(make([]byte, 1279)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short Read error = %v, want io.ErrShortBuffer", err)
	}
	if _, err := adapter.Write(make([]byte, 1281)); !errors.Is(err, errPacketTooLarge) {
		t.Fatalf("oversized Write error = %v, want errPacketTooLarge", err)
	}
	if fake.writeCount != 0 {
		t.Fatalf("oversized packet reached device %d times", fake.writeCount)
	}
}
