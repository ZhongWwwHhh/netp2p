//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func testPipePath(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\netp2p-ipc-test-%s-%d`, name, os.Getpid())
}

func dialTestPipe(t *testing.T, path string) net.Conn {
	t.Helper()
	conn, err := winio.DialPipe(path, nil)
	if err != nil {
		t.Fatalf("open IPC pipe: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestWindowsPipeAcceptsSequentialClients(t *testing.T) {
	listener, err := listenIPC(testPipePath(t, "sequential"))
	if err != nil {
		t.Fatalf("listen IPC: %v", err)
	}
	defer listener.Close()

	accepts := make(chan struct{}, 2)
	go func() {
		for range accepts {
		}
	}()
	go func() {
		for {
			server, err := listener.Accept()
			if err != nil {
				return
			}
			if _, err := server.Write([]byte("ready")); err != nil {
				t.Errorf("write accepted connection: %v", err)
			}
			_ = server.Close()
			accepts <- struct{}{}
		}
	}()

	for i := range 2 {
		client := dialTestPipe(t, listener.Addr().String())
		buffer := make([]byte, 5)
		if _, err := io.ReadFull(client, buffer); err != nil {
			t.Fatalf("client %d: read accepted connection: %v", i, err)
		}
		accepts <- struct{}{}
	}
}

func TestWindowsPipeCloseUnblocksAccept(t *testing.T) {
	listener, err := listenIPC(testPipePath(t, "close"))
	if err != nil {
		t.Fatalf("listen IPC: %v", err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		acceptDone <- err
	}()
	time.Sleep(25 * time.Millisecond)

	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close listener: %v", err)
	}
	select {
	case err := <-acceptDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept was not unblocked by Close")
	}
}

func TestWindowsPipeDeadline(t *testing.T) {
	listener, err := listenIPC(testPipePath(t, "deadline"))
	if err != nil {
		t.Fatalf("listen IPC: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- server
	}()

	dialTestPipe(t, listener.Addr().String())

	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not complete")
	}
	defer server.Close()
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	_, err = server.Read(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestWindowsIPCOverHTTP(t *testing.T) {
	listener, err := listenIPC(testPipePath(t, "http"))
	if err != nil {
		t.Fatalf("listen IPC: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("HTTP server error: %v", err)
		}
	})

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return winio.DialPipeContext(ctx, listener.Addr().String())
			},
		},
		Timeout: 2 * time.Second,
	}
	url := "http://ipc/status"

	for i := 0; i < 25; i++ {
		assertHTTPGet(t, client, url, i)
	}

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			assertHTTPGet(t, client, url, i)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func assertHTTPGet(t *testing.T, client *http.Client, url string, iteration int) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Errorf("request %d: %v", iteration, err)
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Errorf("request %d body: %v", iteration, err)
		return
	}
	if response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("request %d: status %d body %q", iteration, response.StatusCode, body)
	}
}

func TestWindowsPipeSecurityDescriptor(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(ipcPipeSDDL)
	if err != nil {
		t.Fatalf("parse IPC SDDL: %v", err)
	}
	if sd == nil {
		t.Fatal("security descriptor is nil")
	}
}
