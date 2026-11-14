package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestVersionSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &out, &errBuf); err != nil {
		t.Fatalf("conn version failed: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "conn "+Version {
		t.Fatalf("unexpected version output: %q", got)
	}
}

func TestServeRequiresClusterFlagsWhenNotStandalone(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run(context.Background(), []string{"serve"}, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "database-url") {
		t.Fatalf("expected missing database-url error, got %v", err)
	}
}

func TestServeStandaloneEndToEnd(t *testing.T) {
	// Reserve a free ephemeral port first.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out, errBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"serve", "-standalone", "-listen", addr}, &out, &errBuf)
	}()

	baseURL := fmt.Sprintf("http://%s", addr)
	client := &http.Client{Timeout: 2 * time.Second}

	var ready bool
	for i := 0; i < 40; i++ {
		resp, rerr := client.Get(baseURL + "/healthz")
		if rerr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		cancel()
		t.Fatalf("standalone server did not become ready on %s; logs=%s", addr, errBuf.String())
	}

	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Command Portal") {
		t.Fatalf("unexpected standalone portal response: %d", resp.StatusCode)
	}

	cancel()
	if rerr := <-done; rerr != nil {
		t.Fatalf("clean shutdown returned error: %v", rerr)
	}
}
