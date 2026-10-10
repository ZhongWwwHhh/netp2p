//go:build linux

package exitnode

import (
	"fmt"
	"testing"
)

func BenchmarkExitNodeReconcile128Routes(b *testing.B) {
	runner := &recordingRunner{}
	reconciler := New("100.64.0.0/16", runner.run)
	reconciler.forwardingPath = tempForwardingFile(b)
	routes := make([]Route, 128)
	for index := range routes {
		routes[index] = Route{
			ID: fmt.Sprintf("route-%03d", index), Destination: fmt.Sprintf("10.%d.0.0/16", index+1),
			Masquerade: index%2 == 0,
		}
	}
	if err := reconciler.Reconcile(routes); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := reconciler.Reconcile(routes); err != nil {
			b.Fatal(err)
		}
	}
}
