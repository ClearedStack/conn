package muster

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const contractExamplesDir = "../../testdata/contract/v1/examples"

type savedExample struct {
	About   string       `json:"about"`
	Given   *savedGiven  `json:"given,omitempty"`
	Request savedRequest `json:"request"`
	Expect  savedExpect  `json:"expect"`
}

type savedGiven struct {
	Items     []SeedItem     `json:"items,omitempty"`
	Calls     []savedRequest `json:"calls,omitempty"`
	Wait      string         `json:"wait,omitempty"`
	Condition string         `json:"condition,omitempty"`
}

type savedRequest struct {
	As          string          `json:"as,omitempty"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	ContentType *string         `json:"content_type,omitempty"`
	Body        json.RawMessage `json:"body,omitempty"`
	Raw         *string         `json:"raw,omitempty"`
}

type savedExpect struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
	Stream *string         `json:"stream,omitempty"`
}

// TestReplayAll56ContractExamples replays all 56 saved Muster Contract v1 JSON
// examples from testdata/contract/v1/examples/ with zero skips, verifying both
// Standin fidelity across all 56 files and Client behavior on Conn calls,
// healthz, SSE streams, and every refusal code.
func TestReplayAll56ContractExamples(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(contractExamplesDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 56 {
		t.Fatalf("found %d contract examples in %s, want exactly 56", len(paths), contractExamplesDir)
	}

	replayed := 0
	connClientCalls := 0
	refusalsDecoded := 0

	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var ex savedExample
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&ex); err != nil {
				t.Fatalf("invalid contract example %s: %v", name, err)
			}
			if ex.About == "" {
				t.Fatalf("%s: missing about field", name)
			}

			// 1. Replay the full scenario (given + request) against Standin.
			var seed []SeedItem
			if ex.Given != nil {
				seed = ex.Given.Items
			}
			standin := NewStandin(seed, nil)
			if ex.Given != nil {
				for i, gc := range ex.Given.Calls {
					rec := execSavedRequest(t, standin, gc)
					if rec.Code < 200 || rec.Code > 299 {
						t.Fatalf("given call %d (%s %s as %s) failed: %d %s",
							i+1, gc.Method, gc.Path, gc.As, rec.Code, rec.Body.String())
					}
				}
				if ex.Given.Wait != "" {
					dur, werr := time.ParseDuration(ex.Given.Wait)
					if werr != nil {
						t.Fatal(werr)
					}
					standin.Advance(dur)
				}
				if ex.Given.Condition != "" {
					standin.SetCondition(ex.Given.Condition)
				}
			}

			if ex.Expect.Stream != nil {
				verifyFeedExample(t, standin, ex)
				connClientCalls++
			} else {
				rec := execSavedRequest(t, standin, ex.Request)
				if rec.Code != ex.Expect.Status {
					t.Fatalf("Standin status = %d, want %d\ngot body:  %s\nwant body: %s",
						rec.Code, ex.Expect.Status, rec.Body.String(), string(ex.Expect.Body))
				}
				if len(ex.Expect.Body) == 0 {
					if rec.Body.Len() != 0 {
						t.Fatalf("expected empty body on %d, got %q", rec.Code, rec.Body.String())
					}
				} else {
					assertEqualJSON(t, rec.Body.Bytes(), ex.Expect.Body)
				}
			}

			// 2. Additionally exercise Client directly for Conn-authored requests, healthz, and refusals.
			if isConnEmittableRequest(ex.Request) {
				verifyThroughConnClient(t, ex)
				connClientCalls++
			}
			if ex.Request.Path == PathHealthz && ex.Request.Method == http.MethodGet {
				srv := httptest.NewServer(standin)
				defer srv.Close()
				c, cerr := NewClient(srv.URL, StaticTokenSource("tok-conn"), srv.Client())
				if cerr != nil {
					t.Fatal(cerr)
				}
				if herr := c.Healthz(context.Background()); herr != nil {
					t.Fatalf("Client.Healthz failed: %v", herr)
				}
				connClientCalls++
			}
			if ex.Expect.Status >= 400 {
				verifyClientRefusalDecoding(t, ex.Expect)
				refusalsDecoded++
			}
		})
		replayed++
	}

	if replayed != 56 {
		t.Fatalf("replayed %d examples, want 56", replayed)
	}
	if connClientCalls < 8 {
		t.Fatalf("expected at least 8 Conn Client calls exercised, got %d", connClientCalls)
	}
	if refusalsDecoded < 25 {
		t.Fatalf("expected all refusal examples decoded by Client, got %d", refusalsDecoded)
	}
}

func execSavedRequest(t *testing.T, h http.Handler, sr savedRequest) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if sr.Raw != nil {
		body = []byte(*sr.Raw)
	} else if len(sr.Body) > 0 {
		body = sr.Body
	}
	req := httptest.NewRequest(sr.Method, sr.Path, bytes.NewReader(body))
	if sr.As != "" {
		req.Header.Set("Authorization", "Bearer tok-"+sr.As)
	}
	if sr.ContentType != nil {
		if *sr.ContentType != "" {
			req.Header.Set("Content-Type", *sr.ContentType)
		}
	} else if sr.Method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func verifyFeedExample(t *testing.T, standin *Standin, ex savedExample) {
	t.Helper()
	srv := httptest.NewServer(standin)
	defer srv.Close()

	// Verify exact wire stream first.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, ex.Request.Method, srv.URL+ex.Request.Path, nil)
	if ex.Request.As != "" {
		req.Header.Set("Authorization", "Bearer "+standin.TokenFor(ex.Request.As))
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != ex.Expect.Status {
		t.Fatalf("feed status = %d, want %d", resp.StatusCode, ex.Expect.Status)
	}
	wantEvents := strings.Count(*ex.Expect.Stream, "\n\n")
	var gotBuf bytes.Buffer
	br := bufio.NewReader(resp.Body)
	for seen := 0; seen < wantEvents; {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			t.Fatalf("feed ended early: %v", lerr)
		}
		gotBuf.WriteString(line)
		if line == "\n" {
			seen++
		}
	}
	if gotBuf.String() != *ex.Expect.Stream {
		t.Fatalf("SSE stream mismatch\ngot:\n%s\nwant:\n%s", gotBuf.String(), *ex.Expect.Stream)
	}

	// Also verify Client.OpenFeed parses all initial SSE frames cleanly.
	c, err := NewClient(srv.URL, StaticTokenSource(standin.TokenFor("conn")), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	fs, err := c.OpenFeed(streamCtx)
	if err != nil {
		t.Fatalf("Client.OpenFeed failed: %v", err)
	}
	defer fs.Close()

	for i := 0; i < wantEvents; i++ {
		ev, nerr := fs.Next()
		if nerr != nil {
			t.Fatalf("fs.Next() %d failed: %v", i, nerr)
		}
		if ev.Event == "" || len(ev.Data) == 0 {
			t.Fatalf("empty SSE event parsed: %+v", ev)
		}
	}
}

func isConnEmittableRequest(sr savedRequest) bool {
	if sr.As != "conn" || sr.Method != http.MethodPost || sr.ContentType != nil || sr.Raw != nil {
		return false
	}
	return sr.Path == PathEdits || sr.Path == PathItems
}

func verifyThroughConnClient(t *testing.T, ex savedExample) {
	t.Helper()
	var seed []SeedItem
	if ex.Given != nil {
		seed = ex.Given.Items
	}
	standin := NewStandin(seed, nil)
	if ex.Given != nil {
		for _, gc := range ex.Given.Calls {
			rec := execSavedRequest(t, standin, gc)
			if rec.Code < 200 || rec.Code > 299 {
				t.Fatalf("setup call failed: %d", rec.Code)
			}
		}
		if ex.Given.Wait != "" {
			dur, _ := time.ParseDuration(ex.Given.Wait)
			standin.Advance(dur)
		}
		if ex.Given.Condition != "" {
			standin.SetCondition(ex.Given.Condition)
		}
	}

	srv := httptest.NewServer(standin)
	defer srv.Close()

	var tokenReads atomic.Int32
	tokSrc := func() (string, error) {
		tokenReads.Add(1)
		return standin.TokenFor("conn"), nil
	}
	c, err := NewClient(srv.URL, tokSrc, srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	switch ex.Request.Path {
	case PathEdits:
		var body wireEditRequest
		if json.Unmarshal(ex.Request.Body, &body) != nil || body.Contract != ContractVersion {
			return
		}
		got, callErr := c.SubmitEdit(context.Background(), EditRequest{
			Target:   body.Target,
			Change:   body.Change,
			Reason:   body.Reason,
			Pow:      body.Pow,
			Honeypot: body.Honeypot,
			Source:   body.Source,
		})
		// Note: for >4096-byte edits, Client enforces the 4 KiB cap before hitting the wire.
		if len(ex.Request.Body) <= MaxEditBodyBytes && tokenReads.Load() != 1 {
			t.Fatalf("expected fresh token read per call, got %d", tokenReads.Load())
		}
		checkClientOutcome(t, got, callErr, ex.Expect)

	case PathItems:
		var body wireItemRequest
		if json.Unmarshal(ex.Request.Body, &body) != nil || body.Contract != ContractVersion {
			return
		}
		got, callErr := c.SubmitItem(context.Background(), ItemRequest{
			Source:  body.Source,
			Title:   body.Title,
			Address: body.Address,
			Result:  body.Result,
			Pow:     body.Pow,
			Visitor: body.Visitor,
		})
		if tokenReads.Load() != 1 {
			t.Fatalf("expected fresh token read per call, got %d", tokenReads.Load())
		}
		checkClientOutcome(t, got, callErr, ex.Expect)
	}
}

func checkClientOutcome(t *testing.T, got any, callErr error, exp savedExpect) {
	t.Helper()
	if exp.Status == http.StatusNoContent {
		if callErr != nil {
			t.Fatalf("expected nil error on 204, got %v", callErr)
		}
		if r, ok := got.(*EditReceipt); !ok || r != nil {
			t.Fatalf("expected nil *EditReceipt on 204, got %#v", got)
		}
		return
	}
	if exp.Status >= 400 {
		assertRefusalMatches(t, callErr, exp)
		return
	}
	if callErr != nil {
		t.Fatalf("unexpected Client error on %d: %v", exp.Status, callErr)
	}
	gotBytes, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	assertEqualJSON(t, gotBytes, exp.ExpectBody())
}

func (e savedExpect) ExpectBody() []byte { return e.Body }

func verifyClientRefusalDecoding(t *testing.T, exp savedExpect) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(exp.Status)
		_, _ = w.Write(exp.Body)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, StaticTokenSource("tok-conn"), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, callErr := c.SubmitEdit(context.Background(), EditRequest{
		Target: "catalog.sample-calculator.description",
		Change: "sample change",
		Pow:    "2026-01-05.208bd",
		Source: "203.0.113.7",
	})
	assertRefusalMatches(t, callErr, exp)
}

func assertRefusalMatches(t *testing.T, callErr error, exp savedExpect) {
	t.Helper()
	re, ok := UnwrapRefusal(callErr)
	if !ok {
		t.Fatalf("expected *RefusalError for HTTP %d, got %T (%v)", exp.Status, callErr, callErr)
	}
	var want Refusal
	if err := json.Unmarshal(exp.Body, &want); err != nil {
		t.Fatal(err)
	}
	if re.Status != exp.Status || re.Refusal.Error != want.Error || re.Cause != want.Cause || re.Reason != want.Reason {
		t.Fatalf("refusal mismatch: got %+v, want status=%d %+v", re, exp.Status, want)
	}
	wantRetry := exp.Status == http.StatusTooManyRequests || exp.Status == http.StatusServiceUnavailable
	if IsRetryable(callErr) != wantRetry {
		t.Fatalf("IsRetryable = %v, want %v", IsRetryable(callErr), wantRetry)
	}
}

func assertEqualJSON(t *testing.T, gotRaw, wantRaw []byte) {
	t.Helper()
	var gotVal, wantVal any
	if err := json.Unmarshal(gotRaw, &gotVal); err != nil {
		t.Fatalf("got invalid JSON %q: %v", gotRaw, err)
	}
	if err := json.Unmarshal(wantRaw, &wantVal); err != nil {
		t.Fatalf("want invalid JSON %q: %v", wantRaw, err)
	}
	if !reflect.DeepEqual(gotVal, wantVal) {
		t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", bytes.TrimSpace(gotRaw), bytes.TrimSpace(wantRaw))
	}
}

func TestClientTokenRotationCapsAndRedirectRefusal(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokPath, []byte("tok-conn\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var seenAuths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuths = append(seenAuths, r.Header.Get("Authorization"))
		writeJSONResp(w, http.StatusAccepted, EditReceipt{ID: "EP-0001", Status: "pending_approval"})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, FileTokenSource(tokPath), srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.SubmitEdit(context.Background(), EditRequest{
		Target: "catalog.sample-calculator.description", Change: "first", Pow: "2026-01-05.208bd", Source: "203.0.113.7",
	}); err != nil {
		t.Fatal(err)
	}
	// Rotate token file on disk and ensure next call picks up the new token immediately.
	if err := os.WriteFile(tokPath, []byte("tok-conn-rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitEdit(context.Background(), EditRequest{
		Target: "catalog.sample-calculator.description", Change: "second", Pow: "2026-01-05.208bd", Source: "203.0.113.7",
	}); err != nil {
		t.Fatal(err)
	}
	if len(seenAuths) != 2 || seenAuths[0] != "Bearer tok-conn" || seenAuths[1] != "Bearer tok-conn-rotated" {
		t.Fatalf("expected rotated bearer tokens, got %v", seenAuths)
	}

	// Verify 64 KiB cap on /v1/items.
	_, err = c.SubmitItem(context.Background(), ItemRequest{
		Source:  SourceSiteForm,
		Title:   "Oversized item",
		Address: "https://example.org/" + strings.Repeat("a", MaxItemBodyBytes),
		Pow:     "2026-01-05.70b6f",
		Visitor: "203.0.113.7",
	})
	if re, ok := UnwrapRefusal(err); !ok || re.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 refusal on >64 KiB item request, got %v", err)
	}

	// Verify HTTP redirects are refused so bearer tokens never follow redirects.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+PathEdits, http.StatusFound)
	}))
	defer redir.Close()
	rc, err := NewClient(redir.URL, FileTokenSource(tokPath), redir.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.SubmitEdit(context.Background(), EditRequest{
		Target: "catalog.sample-calculator.description", Change: "x", Pow: "2026-01-05.208bd", Source: "203.0.113.7",
	}); err == nil {
		t.Fatal("expected redirect to be refused")
	}
}
