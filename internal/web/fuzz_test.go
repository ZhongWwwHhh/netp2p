package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func FuzzDecodeJSONBody(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"email":"user@example.test","password":"secret"}`))
	f.Add([]byte(`{}{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"email":null}`))
	f.Add([]byte("\xff\xfe"))

	f.Fuzz(func(t *testing.T, data []byte) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(data))
		recorder := httptest.NewRecorder()
		var target map[string]any
		_ = decodeJSONBody(recorder, request, 16<<10, &target)
	})
}

func TestDecodeJSONBodyRejectsTrailingAndOversizedInput(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}{}`))
	if server.decodeAuthBody(httptest.NewRecorder(), request, &struct{}{}) {
		t.Fatal("trailing JSON object was accepted")
	}

	request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 16<<10+1)))
	if server.decodeAuthBody(httptest.NewRecorder(), request, &struct{}{}) {
		t.Fatal("oversized JSON body was accepted")
	}
}

func TestBootstrapHTTPStressAndPathTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode skips the local HTTP stress run")
	}
	server := &Server{
		bootstrap: []byte(`{"ok":true}`),
		readinessFunc: func() ReadinessStatus {
			return ReadinessStatus{Status: "ready", LedgerReady: true, QuorumSize: 1, CommitteeOnline: 1}
		},
	}
	httpServer := httptest.NewServer(server.BootstrapHandler())
	defer httpServer.Close()

	paths := []string{"/api/bootstrap", "/healthz", "/readyz", "/assets/../../etc/passwd", "/../../etc/passwd"}
	for _, path := range paths {
		response, err := http.Get(httpServer.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		response.Body.Close()
		if response.StatusCode >= http.StatusInternalServerError {
			t.Fatalf("GET %s status = %d", path, response.StatusCode)
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for iteration := 0; iteration < 16; iteration++ {
				path := paths[(worker+iteration)%len(paths)]
				response, err := client.Get(httpServer.URL + path)
				if err != nil {
					t.Errorf("worker %d GET %s: %v", worker, path, err)
					return
				}
				response.Body.Close()
				if response.StatusCode >= http.StatusInternalServerError {
					t.Errorf("worker %d GET %s status = %d", worker, path, response.StatusCode)
					return
				}
			}
		}(worker)
	}
	workers.Wait()

	if testing.Verbose() {
		fmt.Printf("bootstrap stress completed %d requests\n", len(paths)*16)
	}
}
