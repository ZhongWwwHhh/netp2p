//go:build !linux

package exitnode

// forwardingState is a no-op on non-Linux platforms; the reconciler is never
// wired up there because exit nodes require TUN, which is Linux-only.
type forwardingState struct{}

func (state *forwardingState) enable(reconciler *Reconciler) error  { return ErrUnsupported }
func (state *forwardingState) disable(reconciler *Reconciler) error { return nil }
