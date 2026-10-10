package version

import "testing"

func TestProtocolVersionIsV3(t *testing.T) {
	if ProtocolVersion != "3.0.0" {
		t.Fatalf("ProtocolVersion = %q, want 3.0.0", ProtocolVersion)
	}
}
