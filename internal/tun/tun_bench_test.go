package tun

import (
	"fmt"
	"io"
	"os"
	"testing"
)

type benchmarkPipe struct {
	reader *os.File
	writer *os.File
}

func (pipe benchmarkPipe) Read(buffer []byte) (int, error) { return pipe.reader.Read(buffer) }
func (pipe benchmarkPipe) Write(buffer []byte) (int, error) {
	return pipe.writer.Write(buffer)
}
func (pipe benchmarkPipe) Close() error {
	readerErr := pipe.reader.Close()
	writerErr := pipe.writer.Close()
	if readerErr != nil {
		return readerErr
	}
	return writerErr
}

func BenchmarkTUNPacketIO(b *testing.B) {
	reader, writer, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}
	device := &Device{
		file: benchmarkPipe{reader: reader, writer: writer}, name: "netp2p-bench",
		routes: make(map[string]struct{}), networks: make(map[string]struct{}),
		pinned: make(map[string]struct{}), hostRoutes: make(map[string]string),
	}
	b.Cleanup(func() { _ = device.Close() })
	payload := make([]byte, 1200)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := device.WritePacket(payload); err != nil {
			b.Fatal(err)
		}
		received, err := device.ReadPacket()
		if err != nil {
			b.Fatal(err)
		}
		if len(received) != len(payload) {
			b.Fatalf("packet length = %d, want %d", len(received), len(payload))
		}
	}
}

func BenchmarkTUNRouteReconcile512Peers(b *testing.B) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(b, runner.run)
	addresses := make([]string, 512)
	for index := range addresses {
		addresses[index] = fmt.Sprintf("100.64.%d.%d", index/250, 1+index%250)
	}
	if err := device.ReconcileRoutes(addresses); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := device.ReconcileRoutes(addresses); err != nil {
			b.Fatal(err)
		}
	}
}

var _ io.ReadWriteCloser = benchmarkPipe{}
