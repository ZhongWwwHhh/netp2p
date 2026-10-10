package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type ipcClient struct {
	path string
	http *http.Client
}

func newIPCClient(path string) *ipcClient {
	if path == "" {
		path = defaultIPCPath()
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialIPC(ctx, path)
		},
	}
	return &ipcClient{path: path, http: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

func (client *ipcClient) call(ctx context.Context, method, endpoint string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://netp2pd"+endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(response.Body)
		return fmt.Errorf("IPC %s %s: %s", method, endpoint, bytes.TrimSpace(raw))
	}
	if result == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(result)
}
