package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClearedStack/conn/internal/feedhub"
	"github.com/ClearedStack/conn/internal/muster"
	"github.com/ClearedStack/conn/internal/ownership"
	"github.com/ClearedStack/conn/internal/pow"
	"github.com/ClearedStack/conn/internal/pubstore"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type degradedReader struct {
	pubstore.Reader
}

func (d degradedReader) PortalSnapshot(ctx context.Context) (pubstore.PortalData, error) {
	return pubstore.PortalData{
		Degraded:  true,
		ErrorCode: muster.CodeTimeout,
		Health:    map[string]pubstore.ComponentHealth{},
	}, nil
}

func setupTestWebStack(t *testing.T) (*Server, *muster.Standin, *feedhub.Hub, *testClock, func()) {
	t.Helper()

	clk := &testClock{now: time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)}
	owners, err := ownership.Parse([]byte(muster.DefaultStandinOwnershipJSON))
	if err != nil {
		t.Fatalf("ownership.Parse: %v", err)
	}

	standin := muster.NewStandin([]muster.SeedItem{
		{ID: "PA-0001", State: "recorded", Lane: "normal"},
	}, owners)
	standin.SetClock(clk.Now())

	musterSrv := httptest.NewServer(standin)

	client, err := muster.NewClient(musterSrv.URL, muster.StaticTokenSource(standin.TokenFor("conn")), musterSrv.Client())
	if err != nil {
		musterSrv.Close()
		t.Fatalf("muster.NewClient: %v", err)
	}

	hub := feedhub.New(client, feedhub.Config{
		Clock:          clk.Now,
		InitialBackoff: 20 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})

	srv, err := NewServer(Config{
		Store:  pubstore.NewMemoryStore(),
		Muster: client,
		Hub:    hub,
		Owners: owners,
	})
	if err != nil {
		musterSrv.Close()
		t.Fatalf("NewServer: %v", err)
	}

	return srv, standin, hub, clk, func() {
		musterSrv.Close()
	}
}

func assertSecurityHeaders(t *testing.T, path string, h http.Header) {
	t.Helper()
	if got := h.Get("Content-Security-Policy"); got != CSPHeaderValue {
		t.Fatalf("%s: unexpected CSP header: %q", path, got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("%s: unexpected X-Content-Type-Options: %q", path, got)
	}
	if got := h.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("%s: unexpected Referrer-Policy: %q", path, got)
	}
	if cookies := h.Values("Set-Cookie"); len(cookies) > 0 {
		t.Fatalf("%s: unexpected Set-Cookie header: %v", path, cookies)
	}
}

func TestAllReadRoutesAndSecurityHeaders(t *testing.T) {
	srv, _, hub, _, cleanup := setupTestWebStack(t)
	defer cleanup()

	// Seed a fresh depths frame so the portal shows SSE LIVE.
	hub.IngestEvent(muster.FeedEvent{
		Event: "depths",
		Data:  []byte(`{"at":"2026-01-05T09:00:00Z","urgent":1,"normal":2,"backfill":3,"needs_subtool":1}`),
	})

	routes := []struct {
		path       string
		wantStatus int
		wantSubstr string
	}{
		{"/", http.StatusOK, "Command Portal"},
		{"/tools/", http.StatusOK, "Sample Indirect Rate Worksheet Calculator"},
		{"/tools/?status=linked", http.StatusOK, "Sample Boundary Scoping Reference"},
		{"/tools/?q=clause", http.StatusOK, "Sample Solicitation Clause Applicability Matrix"},
		{"/tools/sample-calculator", http.StatusOK, "catalog.sample-calculator.description"},
		{"/tools/sample-scoping-handbook", http.StatusOK, "Linked External Tool"},
		{"/tools/sample-pool-estimator", http.StatusOK, "Consolidated Entry"},
		{"/tools/sample-repealed-notice-helper", http.StatusOK, "Retired Entry"},
		{"/items/", http.StatusOK, "Pipeline Item Explorer"},
		{"/items/?state=needs_subtool", http.StatusOK, "PA-0007"},
		{"/items/PA-0001", http.StatusOK, "contractor-utility-v1"},
		{"/items/PA-0007", http.StatusOK, "E_NEEDS_SUBTOOL"},
		{"/registry/", http.StatusOK, "17-Component Platform Registry"},
		{"/guides/", http.StatusOK, "Clean-Room Specification Boundary"},
		{"/static/style.css", http.StatusOK, "--bg:"},
		{"/static/app.js", http.StatusOK, "muster-pow-v1"},
		{"/static/mark.svg", http.StatusOK, "<svg"},
		{"/healthz", http.StatusOK, `"status":"ok"`},
		{"/does-not-exist", http.StatusNotFound, "404 - Page Not Found"},
		{"/v1/unknown", http.StatusNotFound, `"cause":"no_such_call"`},
	}

	for _, tc := range routes {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != tc.wantStatus {
			t.Fatalf("GET %s: status=%d want=%d body=%s", tc.path, rec.Code, tc.wantStatus, rec.Body.String())
		}
		assertSecurityHeaders(t, tc.path, rec.Header())
		body := rec.Body.String()
		if !strings.Contains(body, tc.wantSubstr) {
			t.Fatalf("GET %s: expected substring %q in body", tc.path, tc.wantSubstr)
		}
		if strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") && strings.Contains(body, `style="`) {
			t.Fatalf("GET %s: HTML contains inline style attribute which violates style-src 'self'", tc.path)
		}
	}
}

func TestPortalAttentionRulesStaleAndDegraded(t *testing.T) {
	srv, _, hub, clk, cleanup := setupTestWebStack(t)
	defer cleanup()

	// Fresh depths -> no stale SSE alert.
	hub.IngestEvent(muster.FeedEvent{
		Event: "depths",
		Data:  []byte(`{"at":"2026-01-05T09:00:00Z","urgent":0,"normal":1,"backfill":0,"needs_subtool":0}`),
	})
	recFresh := httptest.NewRecorder()
	srv.ServeHTTP(recFresh, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(recFresh.Body.String(), "Muster live SSE feed is stale (>15s)") {
		t.Fatal("did not expect stale SSE alert when feed is fresh")
	}

	// Advance past 15s -> P1 stale SSE alert appears!
	clk.Advance(16 * time.Second)
	recStale := httptest.NewRecorder()
	srv.ServeHTTP(recStale, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(recStale.Body.String(), "Muster live SSE feed is stale (&gt;15s)") {
		t.Fatal("expected P1 stale SSE alert when >15s pass since last depths")
	}

	// Degraded Logbook reader -> graceful 200 with P0 E_TIMEOUT alert, zero crash.
	degSrv, err := NewServer(Config{
		Store: degradedReader{Reader: pubstore.NewMemoryStore()},
		Hub:   hub,
	})
	if err != nil {
		t.Fatalf("NewServer degraded: %v", err)
	}
	recDeg := httptest.NewRecorder()
	degSrv.ServeHTTP(recDeg, httptest.NewRequest(http.MethodGet, "/", nil))
	if recDeg.Code != http.StatusOK {
		t.Fatalf("expected graceful 200 on degraded Logbook, got %d", recDeg.Code)
	}
	if !strings.Contains(recDeg.Body.String(), "Logbook public views unreachable") || !strings.Contains(recDeg.Body.String(), "E_TIMEOUT") {
		t.Fatal("expected P0 E_TIMEOUT degraded alert on portal")
	}
}

func TestEditsAndItemsIntakeAndNoVisitorIPLeak(t *testing.T) {
	srv, _, _, _, cleanup := setupTestWebStack(t)
	defer cleanup()

	const visitorRemoteAddr = "198.51.100.77:54321"
	const visitorIP = "198.51.100.77"

	// 1. Accepted 202 edit proposal with 20-bit PoW.
	target := "catalog.sample-calculator.description"
	change := "Clarify synthetic G&A base example note."
	reason := "Synthetic CAS 410-40 alignment"
	powTok, err := pow.Solve("2026-01-05", target, change, reason, pow.DefaultDifficulty)
	if err != nil {
		t.Fatalf("pow.Solve edit: %v", err)
	}

	editPayload, _ := json.Marshal(map[string]string{
		"target":   target,
		"change":   change,
		"reason":   reason,
		"pow":      powTok,
		"honeypot": "",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/edits", bytes.NewReader(editPayload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = visitorRemoteAddr
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/edits: status=%d want=202 body=%s", rec.Code, rec.Body.String())
	}
	assertSecurityHeaders(t, "/v1/edits", rec.Header())
	if strings.Contains(rec.Body.String(), visitorIP) {
		t.Fatal("response body leaked visitor IP")
	}
	var receipt muster.EditReceipt
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("unmarshal EditReceipt: %v", err)
	}
	if receipt.ID != "EP-0001" || receipt.Status != "pending_approval" {
		t.Fatalf("unexpected edit receipt: %+v", receipt)
	}

	// 2. Honeypot non-empty -> 204 No Content.
	hpReq := httptest.NewRequest(http.MethodPost, "/v1/edits", bytes.NewReader([]byte(`{"target":"`+target+`","change":"`+change+`","reason":"`+reason+`","pow":"`+powTok+`","honeypot":"bot-filled"}`)))
	hpReq.Header.Set("Content-Type", "application/json")
	hpReq.RemoteAddr = visitorRemoteAddr
	hpRec := httptest.NewRecorder()
	srv.ServeHTTP(hpRec, hpReq)
	if hpRec.Code != http.StatusNoContent || hpRec.Body.Len() != 0 {
		t.Fatalf("honeypot POST /v1/edits: status=%d len=%d", hpRec.Code, hpRec.Body.Len())
	}

	// 3. Unknown target rejected locally against ownership_map.json -> 400 bad_field.
	badTargetReq := httptest.NewRequest(http.MethodPost, "/v1/edits", bytes.NewReader([]byte(`{"target":"catalog.unknown-tool.description","change":"x","reason":"y","pow":"2026-01-05.0"}`)))
	badTargetReq.Header.Set("Content-Type", "application/json")
	badTargetReq.RemoteAddr = visitorRemoteAddr
	badTargetRec := httptest.NewRecorder()
	srv.ServeHTTP(badTargetRec, badTargetReq)
	if badTargetRec.Code != http.StatusBadRequest || !strings.Contains(badTargetRec.Body.String(), "not in the ownership map") {
		t.Fatalf("unknown target: status=%d body=%s", badTargetRec.Code, badTargetRec.Body.String())
	}

	// 4. Caller attempting to spoof "source" field -> 400 unknown_field.
	spoofReq := httptest.NewRequest(http.MethodPost, "/v1/edits", bytes.NewReader([]byte(`{"target":"`+target+`","change":"x","reason":"y","pow":"2026-01-05.0","source":"203.0.113.1"}`)))
	spoofReq.Header.Set("Content-Type", "application/json")
	spoofReq.RemoteAddr = visitorRemoteAddr
	spoofRec := httptest.NewRecorder()
	srv.ServeHTTP(spoofRec, spoofReq)
	if spoofRec.Code != http.StatusBadRequest || !strings.Contains(spoofRec.Body.String(), `"cause":"unknown_field"`) {
		t.Fatalf("spoofed source: status=%d body=%s", spoofRec.Code, spoofRec.Body.String())
	}

	// 5. >4096 bytes rejected with 413 too_large.
	huge := `{"target":"` + target + `","change":"` + strings.Repeat("a", 4100) + `","reason":"r","pow":"2026-01-05.0"}`
	hugeReq := httptest.NewRequest(http.MethodPost, "/v1/edits", strings.NewReader(huge))
	hugeReq.Header.Set("Content-Type", "application/json")
	hugeReq.RemoteAddr = visitorRemoteAddr
	hugeRec := httptest.NewRecorder()
	srv.ServeHTTP(hugeRec, hugeReq)
	if hugeRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for >4KiB edit body, got %d", hugeRec.Code)
	}

	// 6. Anonymous site-form POST /v1/items -> 201 Created, then 200 Duplicate.
	itemTitle := "Sample Contractor Overtime Threshold Checker"
	itemAddr := "https://example.gov/made-up/overtime-rule"
	itemPow, err := pow.Solve("2026-01-05", muster.SourceSiteForm, itemTitle, itemAddr, pow.DefaultDifficulty)
	if err != nil {
		t.Fatalf("pow.Solve item: %v", err)
	}
	itemBody, _ := json.Marshal(map[string]string{
		"source":  "site-form",
		"title":   itemTitle,
		"address": itemAddr,
		"pow":     itemPow,
	})

	itemReq1 := httptest.NewRequest(http.MethodPost, "/v1/items", bytes.NewReader(itemBody))
	itemReq1.Header.Set("Content-Type", "application/json")
	itemReq1.RemoteAddr = visitorRemoteAddr
	itemRec1 := httptest.NewRecorder()
	srv.ServeHTTP(itemRec1, itemReq1)
	if itemRec1.Code != http.StatusCreated {
		t.Fatalf("POST /v1/items first: status=%d body=%s", itemRec1.Code, itemRec1.Body.String())
	}
	if strings.Contains(itemRec1.Body.String(), visitorIP) {
		t.Fatal("POST /v1/items response leaked visitor IP")
	}

	itemReq2 := httptest.NewRequest(http.MethodPost, "/v1/items", bytes.NewReader(itemBody))
	itemReq2.Header.Set("Content-Type", "application/json")
	itemReq2.RemoteAddr = visitorRemoteAddr
	itemRec2 := httptest.NewRecorder()
	srv.ServeHTTP(itemRec2, itemReq2)
	if itemRec2.Code != http.StatusOK || !strings.Contains(itemRec2.Body.String(), `"duplicate":true`) {
		t.Fatalf("POST /v1/items duplicate: status=%d body=%s", itemRec2.Code, itemRec2.Body.String())
	}
}

func TestPublicSSEFeedStreamsProposalLifecycle(t *testing.T) {
	srv, standin, hub, _, cleanup := setupTestWebStack(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpSrv.URL+"/v1/feed", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := httpSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /v1/feed: %v", err)
	}
	defer resp.Body.Close()

	assertSecurityHeaders(t, "/v1/feed", resp.Header)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected feed content-type: %q", resp.Header.Get("Content-Type"))
	}

	// Emit edit proposal transitions from Muster standin and verify browser SSE receives them.
	go func() {
		time.Sleep(80 * time.Millisecond)
		standin.EmitEditStatus("EP-0001", "approved")
		time.Sleep(30 * time.Millisecond)
		standin.EmitEditStatus("EP-0001", "building")
		time.Sleep(30 * time.Millisecond)
		standin.EmitEditStatus("EP-0001", "live")
	}()

	scanner := bufio.NewScanner(resp.Body)
	seenLive := false
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, `"id":"EP-0001"`) && strings.Contains(line, `"status":"live"`) {
				seenLive = true
				return
			}
		}
	}()

	select {
	case <-doneCh:
		if !seenLive {
			t.Fatal("stream closed before receiving live edit status")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for EP-0001 live event on public /v1/feed")
	}
}
