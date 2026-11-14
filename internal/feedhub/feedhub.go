// Package feedhub subscribes to Muster's Contract v1 GET /v1/feed stream,
// caches sanitized live state, detects >15s feed staleness (P1 attention),
// and fans out Server-Sent Events to up to 64 concurrent browser subscribers.
package feedhub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ClearedStack/conn/internal/muster"
	"github.com/ClearedStack/conn/internal/pubstore"
)

const (
	// MaxSubscribers caps concurrent public GET /v1/feed browser streams.
	MaxSubscribers = 64

	// SubscriberBuffer bounds queued SSE frames per browser subscriber before slow-drop.
	SubscriberBuffer = 32

	// DefaultStaleAfter triggers a P1 attention alert when exceeded since the last depths tick.
	DefaultStaleAfter = 15 * time.Second

	// MaxCachedEdits bounds in-memory proposal status tracking so memory stays flat.
	MaxCachedEdits = 256

	defaultInitialBackoff = 200 * time.Millisecond
	defaultMaxBackoff     = 5 * time.Second
)

// ErrTooManySubscribers is returned when all 64 public SSE slots are occupied.
var ErrTooManySubscribers = errors.New("feedhub: maximum subscriber capacity reached")

var (
	proposalIDPattern = regexp.MustCompile(`^EP-([0-9]{4}|[1-9][0-9]{4,8})$`)

	allowedHealthStates = map[string]bool{
		"healthy":  true,
		"idle":     true,
		"degraded": true,
		"paused":   true,
	}
	allowedPublicCodes = map[string]bool{
		"":                      true,
		muster.CodeTimeout:      true,
		muster.CodeParse:        true,
		muster.CodeNeedsSubtool: true,
	}
	allowedEditStatuses = map[string]bool{
		"pending_approval": true,
		"approved":         true,
		"building":         true,
		"live":             true,
		"rejected":         true,
	}
)

// FeedOpener is satisfied by *muster.Client and test doubles.
type FeedOpener interface {
	OpenFeed(ctx context.Context) (*muster.FeedStream, error)
}

// Config configures a Hub instance.
type Config struct {
	Clock          func() time.Time
	StaleAfter     time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxSubscribers int
}

// Snapshot represents a point-in-time read of cached live feed state.
type Snapshot struct {
	Connected       bool
	HasDepths       bool
	Stale           bool
	LastDepthsAt    time.Time
	Depths          muster.DepthsData
	Health          map[string]muster.HealthData
	Edits           map[string]muster.EditData
	SubscriberCount int
}

// Subscriber receives formatted SSE frames on C until Unsubscribe is called
// or the hub drops and closes C because the subscriber fell behind.
type Subscriber struct {
	C      <-chan []byte
	ch     chan []byte
	hub    *Hub
	closed bool
}

// Unsubscribe removes the subscriber from the hub and closes its channel if still open.
func (s *Subscriber) Unsubscribe() {
	if s == nil || s.hub == nil {
		return
	}
	s.hub.unsubscribe(s)
}

// Hub maintains Muster SSE upstream state and fans out sanitized frames to browsers.
type Hub struct {
	opener         FeedOpener
	clock          func() time.Time
	staleAfter     time.Duration
	initialBackoff time.Duration
	maxBackoff     time.Duration
	maxSubs        int

	mu           sync.RWMutex
	connected    bool
	hasDepths    bool
	lastDepthsAt time.Time
	depths       muster.DepthsData
	health       map[string]muster.HealthData
	edits        map[string]muster.EditData
	editOrder    []string
	nextSeq      uint64
	subs         map[*Subscriber]struct{}
}

// New constructs a Hub backed by opener (which may be nil in unit tests using IngestEvent).
func New(opener FeedOpener, cfg Config) *Hub {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	staleAfter := cfg.StaleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	initBackoff := cfg.InitialBackoff
	if initBackoff <= 0 {
		initBackoff = defaultInitialBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff < initBackoff {
		maxBackoff = defaultMaxBackoff
	}
	maxSubs := cfg.MaxSubscribers
	if maxSubs <= 0 {
		maxSubs = MaxSubscribers
	}

	return &Hub{
		opener:         opener,
		clock:          clock,
		staleAfter:     staleAfter,
		initialBackoff: initBackoff,
		maxBackoff:     maxBackoff,
		maxSubs:        maxSubs,
		health:         make(map[string]muster.HealthData),
		edits:          make(map[string]muster.EditData),
		subs:           make(map[*Subscriber]struct{}),
	}
}

// Run continuously subscribes to Muster's GET /v1/feed endpoint and reconnects
// with bounded exponential backoff until ctx is canceled.
func (h *Hub) Run(ctx context.Context) {
	if h.opener == nil {
		<-ctx.Done()
		h.closeAllSubscribers()
		return
	}

	backoff := h.initialBackoff
	for {
		if ctx.Err() != nil {
			h.closeAllSubscribers()
			return
		}

		stream, err := h.opener.OpenFeed(ctx)
		if err != nil {
			h.setConnected(false)
			if !sleepContext(ctx, backoff) {
				h.closeAllSubscribers()
				return
			}
			backoff = nextBackoff(backoff, h.maxBackoff)
			continue
		}

		h.setConnected(true)
		backoff = h.initialBackoff

		readDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = stream.Close()
			case <-readDone:
			}
		}()

		for {
			ev, rerr := stream.Next()
			if rerr != nil {
				break
			}
			h.IngestEvent(ev)
		}

		close(readDone)
		_ = stream.Close()
		h.setConnected(false)

		if !sleepContext(ctx, backoff) {
			h.closeAllSubscribers()
			return
		}
		backoff = nextBackoff(backoff, h.maxBackoff)
	}
}

// IngestEvent validates, sanitizes, caches, and broadcasts one upstream SSE frame.
// Returns true if the event matched the Contract v1 feed schema and was accepted.
func (h *Hub) IngestEvent(ev muster.FeedEvent) bool {
	now := h.clock().UTC()

	switch ev.Event {
	case "depths":
		var d muster.DepthsData
		if err := decodeStrict(ev.Data, &d); err != nil {
			return false
		}
		if d.Urgent < 0 || d.Normal < 0 || d.Backfill < 0 || d.NeedsSubtool < 0 {
			return false
		}
		if !validRFC3339(d.At) {
			d.At = now.Format(time.RFC3339)
		}

		h.mu.Lock()
		h.depths = d
		h.hasDepths = true
		h.lastDepthsAt = now
		frame := h.formatFrameLocked("depths", d)
		h.broadcastLocked(frame)
		h.mu.Unlock()
		return true

	case "health":
		var hd muster.HealthData
		if err := decodeStrict(ev.Data, &hd); err != nil {
			return false
		}
		if _, ok := pubstore.LookupRegistryComponent(hd.Component); !ok {
			return false
		}
		if !allowedHealthStates[hd.State] {
			return false
		}
		if !allowedPublicCodes[hd.Code] {
			return false
		}
		if hd.State == "healthy" || hd.State == "idle" {
			hd.Code = ""
		}
		if !validRFC3339(hd.At) {
			hd.At = now.Format(time.RFC3339)
		}

		h.mu.Lock()
		h.health[hd.Component] = hd
		frame := h.formatFrameLocked("health", hd)
		h.broadcastLocked(frame)
		h.mu.Unlock()
		return true

	case "edit":
		var ed muster.EditData
		if err := decodeStrict(ev.Data, &ed); err != nil {
			return false
		}
		if !proposalIDPattern.MatchString(ed.ID) || !allowedEditStatuses[ed.Status] {
			return false
		}
		if !validRFC3339(ed.At) {
			ed.At = now.Format(time.RFC3339)
		}

		h.mu.Lock()
		if _, exists := h.edits[ed.ID]; !exists {
			if len(h.editOrder) >= MaxCachedEdits {
				oldest := h.editOrder[0]
				h.editOrder = h.editOrder[1:]
				delete(h.edits, oldest)
			}
			h.editOrder = append(h.editOrder, ed.ID)
		}
		h.edits[ed.ID] = ed
		frame := h.formatFrameLocked("edit", ed)
		h.broadcastLocked(frame)
		h.mu.Unlock()
		return true

	default:
		return false
	}
}

// Snapshot returns a thread-safe copy of cached feed data and current staleness.
func (h *Hub) Snapshot() Snapshot {
	now := h.clock().UTC()

	h.mu.RLock()
	defer h.mu.RUnlock()

	stale := !h.hasDepths || now.Sub(h.lastDepthsAt) > h.staleAfter

	healthCopy := make(map[string]muster.HealthData, len(h.health))
	for k, v := range h.health {
		healthCopy[k] = v
	}
	editsCopy := make(map[string]muster.EditData, len(h.edits))
	for k, v := range h.edits {
		editsCopy[k] = v
	}

	return Snapshot{
		Connected:       h.connected,
		HasDepths:       h.hasDepths,
		Stale:           stale,
		LastDepthsAt:    h.lastDepthsAt,
		Depths:          h.depths,
		Health:          healthCopy,
		Edits:           editsCopy,
		SubscriberCount: len(h.subs),
	}
}

// Subscribe registers a new browser SSE subscriber up to MaxSubscribers and
// enqueues initial cached frames without blocking.
func (h *Hub) Subscribe() (*Subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.subs) >= h.maxSubs {
		return nil, ErrTooManySubscribers
	}

	ch := make(chan []byte, SubscriberBuffer)
	sub := &Subscriber{
		C:   ch,
		ch:  ch,
		hub: h,
	}

	initial := h.initialFramesLocked()
	for _, frame := range initial {
		select {
		case ch <- frame:
		default:
		}
	}

	h.subs[sub] = struct{}{}
	return sub, nil
}

func (h *Hub) initialFramesLocked() [][]byte {
	var frames [][]byte
	if h.hasDepths {
		frames = append(frames, formatStatelessFrame(h.nextSeq, "depths", h.depths))
	}

	if len(h.health) > 0 {
		keys := make([]string, 0, len(h.health))
		for k := range h.health {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(frames) >= SubscriberBuffer/2 {
				break
			}
			frames = append(frames, formatStatelessFrame(h.nextSeq, "health", h.health[k]))
		}
	}

	if len(h.editOrder) > 0 {
		start := 0
		if len(h.editOrder) > 8 {
			start = len(h.editOrder) - 8
		}
		for _, id := range h.editOrder[start:] {
			if ed, ok := h.edits[id]; ok {
				frames = append(frames, formatStatelessFrame(h.nextSeq, "edit", ed))
			}
		}
	}
	return frames
}

func (h *Hub) formatFrameLocked(event string, payload any) []byte {
	h.nextSeq++
	return formatStatelessFrame(h.nextSeq, event, payload)
}

func formatStatelessFrame(seq uint64, event string, payload any) []byte {
	var dataBuf bytes.Buffer
	enc := json.NewEncoder(&dataBuf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
	compact := bytes.TrimSuffix(dataBuf.Bytes(), []byte("\n"))

	var frame bytes.Buffer
	if seq > 0 {
		frame.WriteString("id: ")
		frame.WriteString(strconv.FormatUint(seq, 10))
		frame.WriteByte('\n')
	}
	frame.WriteString("event: ")
	frame.WriteString(event)
	frame.WriteString("\ndata: ")
	frame.Write(compact)
	frame.WriteString("\n\n")
	return frame.Bytes()
}

func (h *Hub) broadcastLocked(frame []byte) {
	for sub := range h.subs {
		select {
		case sub.ch <- frame:
		default:
			// Slow subscriber: drop cleanly so upstream feed processing never stalls.
			delete(h.subs, sub)
			if !sub.closed {
				sub.closed = true
				close(sub.ch)
			}
		}
	}
}

func (h *Hub) unsubscribe(sub *Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, sub)
	if !sub.closed {
		sub.closed = true
		close(sub.ch)
	}
}

func (h *Hub) closeAllSubscribers() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connected = false
	for sub := range h.subs {
		delete(h.subs, sub)
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
	}
}

func (h *Hub) setConnected(v bool) {
	h.mu.Lock()
	h.connected = v
	h.mu.Unlock()
}

func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing tokens")
	}
	return nil
}

func validRFC3339(s string) bool {
	if s == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		return max
	}
	return next
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
