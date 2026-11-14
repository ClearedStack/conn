package feedhub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClearedStack/conn/internal/muster"
)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestStalenessAfter15Seconds(t *testing.T) {
	clk := &manualClock{now: time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)}
	hub := New(nil, Config{Clock: clk.Now})

	if !hub.Snapshot().Stale {
		t.Fatal("expected hub to start stale before first depths event")
	}

	ok := hub.IngestEvent(muster.FeedEvent{
		Event: "depths",
		Data:  []byte(`{"at":"2026-01-05T09:00:00Z","urgent":1,"normal":4,"backfill":2,"needs_subtool":0}`),
	})
	if !ok {
		t.Fatal("expected valid depths event to be accepted")
	}

	snap := hub.Snapshot()
	if snap.Stale {
		t.Fatal("expected hub to be fresh right after depths event")
	}
	if snap.Depths.Normal != 4 || snap.Depths.Urgent != 1 {
		t.Fatalf("unexpected cached depths: %+v", snap.Depths)
	}

	clk.Advance(15 * time.Second)
	if hub.Snapshot().Stale {
		t.Fatal("expected hub to remain fresh at exact 15s boundary")
	}

	clk.Advance(1 * time.Millisecond)
	if !hub.Snapshot().Stale {
		t.Fatal("expected hub to become stale once >15s pass without depths")
	}

	// Health event alone must not reset depths staleness.
	hub.IngestEvent(muster.FeedEvent{
		Event: "health",
		Data:  []byte(`{"at":"2026-01-05T09:00:16Z","component":"sextant","state":"healthy"}`),
	})
	if !hub.Snapshot().Stale {
		t.Fatal("expected health event alone not to clear depths staleness")
	}

	// Next depths tick clears staleness immediately.
	hub.IngestEvent(muster.FeedEvent{
		Event: "depths",
		Data:  []byte(`{"at":"2026-01-05T09:00:17Z","urgent":0,"normal":3,"backfill":2,"needs_subtool":0}`),
	})
	if hub.Snapshot().Stale {
		t.Fatal("expected fresh depths event to clear staleness")
	}
}

func TestSanitizationRejectsUnsafeEvents(t *testing.T) {
	hub := New(nil, Config{})

	badCases := []muster.FeedEvent{
		{Event: "unknown", Data: []byte(`{"at":"2026-01-05T09:00:00Z"}`)},
		{Event: "depths", Data: []byte(`{"at":"2026-01-05T09:00:00Z","urgent":-1,"normal":0,"backfill":0,"needs_subtool":0}`)},
		{Event: "depths", Data: []byte(`{"at":"2026-01-05T09:00:00Z","urgent":0,"normal":0,"backfill":0,"needs_subtool":0,"visitor":"203.0.113.9"}`)},
		{Event: "health", Data: []byte(`{"at":"2026-01-05T09:00:00Z","component":"not-a-component","state":"healthy"}`)},
		{Event: "health", Data: []byte(`{"at":"2026-01-05T09:00:00Z","component":"sextant","state":"degraded","code":"SECRET_STACKTRACE"}`)},
		{Event: "edit", Data: []byte(`{"at":"2026-01-05T09:00:00Z","id":"BAD-1","status":"approved"}`)},
		{Event: "edit", Data: []byte(`{"at":"2026-01-05T09:00:00Z","id":"EP-0001","status":"approved","source":"203.0.113.9"}`)},
	}

	for i, tc := range badCases {
		if hub.IngestEvent(tc) {
			t.Fatalf("case %d (%s) was unexpectedly accepted", i, tc.Event)
		}
	}

	if !hub.IngestEvent(muster.FeedEvent{
		Event: "health",
		Data:  []byte(`{"at":"2026-01-05T09:00:00Z","component":"sextant","state":"degraded","code":"E_TIMEOUT"}`),
	}) {
		t.Fatal("expected valid degraded E_TIMEOUT health event to be accepted")
	}

	if !hub.IngestEvent(muster.FeedEvent{
		Event: "edit",
		Data:  []byte(`{"at":"2026-01-05T09:00:00Z","id":"EP-0001","status":"approved"}`),
	}) {
		t.Fatal("expected valid edit status event to be accepted")
	}

	snap := hub.Snapshot()
	if snap.Health["sextant"].Code != muster.CodeTimeout {
		t.Fatalf("unexpected health snapshot: %+v", snap.Health["sextant"])
	}
	if snap.Edits["EP-0001"].Status != "approved" {
		t.Fatalf("unexpected edit snapshot: %+v", snap.Edits["EP-0001"])
	}
}

func TestSubscriberCapAndSlowEviction(t *testing.T) {
	hub := New(nil, Config{MaxSubscribers: MaxSubscribers})

	subs := make([]*Subscriber, 0, MaxSubscribers)
	for i := 0; i < MaxSubscribers; i++ {
		sub, err := hub.Subscribe()
		if err != nil {
			t.Fatalf("subscribe %d failed: %v", i, err)
		}
		subs = append(subs, sub)
	}

	if _, err := hub.Subscribe(); !errors.Is(err, ErrTooManySubscribers) {
		t.Fatalf("expected ErrTooManySubscribers at 65th subscriber, got %v", err)
	}

	// Unsubscribing one frees a slot.
	subs[0].Unsubscribe()
	replacement, err := hub.Subscribe()
	if err != nil {
		t.Fatalf("expected subscribe after unsubscribe to succeed: %v", err)
	}
	subs[0] = replacement

	// Keep draining subs[0], leave subs[1] unread so its buffer overflows.
	var received int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range subs[0].C {
			atomic.AddInt32(&received, 1)
		}
	}()

	for i := 0; i < SubscriberBuffer+10; i++ {
		hub.IngestEvent(muster.FeedEvent{
			Event: "depths",
			Data:  []byte(`{"at":"2026-01-05T09:00:00Z","urgent":0,"normal":1,"backfill":0,"needs_subtool":0}`),
		})
	}

	// Drain subs[1] until closed to confirm slow subscriber eviction closed its channel.
	drained := 0
	for range subs[1].C {
		drained++
	}
	if drained != SubscriberBuffer {
		t.Fatalf("expected slow subscriber to buffer %d frames before eviction, got %d", SubscriberBuffer, drained)
	}

	subs[0].Unsubscribe()
	<-done
	if atomic.LoadInt32(&received) < int32(SubscriberBuffer+5) {
		t.Fatalf("expected healthy subscriber to keep receiving frames, got %d", received)
	}

	for _, s := range subs[2:] {
		s.Unsubscribe()
	}
}

func TestRunReconnectsToStandinFeed(t *testing.T) {
	standin := muster.NewStandin([]muster.SeedItem{
		{ID: "PA-0001", State: "recorded", Lane: "normal"},
	}, nil)

	var dropNext atomic.Bool
	var connCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == muster.PathFeed {
			n := connCount.Add(1)
			if n == 1 && dropNext.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"E_TIMEOUT","cause":"busy","reason":"too busy; try again"}`))
				return
			}
		}
		standin.ServeHTTP(w, r)
	}))
	defer srv.Close()

	dropNext.Store(true)

	client, err := muster.NewClient(srv.URL, muster.StaticTokenSource(standin.TokenFor("conn")), srv.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	hub := New(client, Config{
		InitialBackoff: 20 * time.Millisecond,
		MaxBackoff:     60 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	sub, err := hub.Subscribe()
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Wait until hub reconnects after initial 503 and receives initial depths snapshot.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case frame := <-sub.C:
			if strings.Contains(string(frame), "event: depths") {
				standin.EmitEditStatus("EP-0001", "building")
				goto waitEdit
			}
		case <-deadline:
			t.Fatal("timed out waiting for depths frame after reconnect")
		}
	}

waitEdit:
	for {
		select {
		case frame := <-sub.C:
			if strings.Contains(string(frame), "event: edit") && strings.Contains(string(frame), `"status":"building"`) {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for live edit status frame")
		}
	}
}
