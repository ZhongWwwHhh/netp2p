package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{0x45, 0x00},
		bytes.Repeat([]byte{0xab}, 1400),
		bytes.Repeat([]byte{0xcd}, MaxFrameSize),
	}
	var buffer bytes.Buffer
	for _, payload := range payloads {
		if err := WriteFrame(&buffer, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for index, want := range payloads {
		got, err := ReadFrame(&buffer)
		if err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d mismatch: %d bytes vs %d", index, len(got), len(want))
		}
	}
	if _, err := ReadFrame(&buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing read error = %v, want EOF", err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("expected oversized frame to be rejected")
	}
	if err := WriteFrame(&buffer, nil); err == nil {
		t.Fatal("expected empty frame to be rejected")
	}
}

func TestReadFrameRejectsInvalidLength(t *testing.T) {
	cases := map[string][]byte{
		"zero length":    {0, 0, 0, 0},
		"beyond maximum": {0, 0xff, 0xff, 0xff},
		"truncated body": {0, 0, 0, 10, 1, 2, 3},
		"truncated head": {0, 0},
	}
	for name, data := range cases {
		if _, err := ReadFrame(bytes.NewReader(data)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}
