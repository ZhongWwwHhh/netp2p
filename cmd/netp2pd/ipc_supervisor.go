package main

import (
	"context"
	"sync"
)

type clientSupervisor struct {
	parent    context.Context
	start     func(context.Context) error
	onStopped func(error)

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

func newClientSupervisor(parent context.Context, start func(context.Context) error, onStopped func(error)) *clientSupervisor {
	return &clientSupervisor{parent: parent, start: start, onStopped: onStopped}
}

func (supervisor *clientSupervisor) Start() bool {
	supervisor.mu.Lock()
	if supervisor.running {
		supervisor.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithCancel(supervisor.parent)
	done := make(chan struct{})
	supervisor.cancel = cancel
	supervisor.done = done
	supervisor.running = true
	supervisor.mu.Unlock()

	go func() {
		err := supervisor.start(ctx)
		cancel()
		close(done)
		supervisor.mu.Lock()
		supervisor.running = false
		supervisor.cancel = nil
		supervisor.done = nil
		supervisor.mu.Unlock()
		if supervisor.onStopped != nil {
			supervisor.onStopped(err)
		}
	}()
	return true
}

func (supervisor *clientSupervisor) Stop() bool {
	supervisor.mu.Lock()
	if !supervisor.running {
		supervisor.mu.Unlock()
		return false
	}
	cancel := supervisor.cancel
	done := supervisor.done
	supervisor.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return true
}
