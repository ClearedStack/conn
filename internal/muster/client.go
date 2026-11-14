// Package muster implements Conn's Contract v1 HTTP/SSE client and an
// in-memory Muster stand-in for standalone operation and contract tests.
package muster

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Contract v1 constants, paths, and byte limits.
const (
	ContractVersion = "v1"

	PathEdits        = "/v1/edits"
	PathItems        = "/v1/items"
	PathFeed         = "/v1/feed"
	PathHealth       = "/v1/health"
	PathRelease      = "/v1/release"
	PathLease        = "/v1/lease"
	PathHeartbeat    = "/v1/heartbeat"
	PathComplete     = "/v1/complete"
	PathFail         = "/v1/fail"
	PathNeedsSubtool = "/v1/needs_subtool"
	PathHealthz      = "/healthz"

	MaxEditBodyBytes    = 4096
	MaxItemBodyBytes    = 64 << 10
	MaxWaybillBodyBytes = 256 << 10
	MaxResponseBytes    = 64 << 10
	MaxSSELineBytes     = 64 << 10

	CodeTimeout      = "E_TIMEOUT"
	CodeParse        = "E_PARSE"
	CodeNeedsSubtool = "E_NEEDS_SUBTOOL"

	SourceSiteForm = "site-form"
)

// TokenSource reads a fresh Kubernetes ServiceAccount bearer token on each call.
type TokenSource func() (string, error)

// FileTokenSource reads and trims a bearer token from path on every call so
// projected Kubernetes ServiceAccount token rotations take effect immediately.
func FileTokenSource(path string) TokenSource {
	return func() (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("muster: unable to read serviceaccount token")
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", errors.New("muster: empty serviceaccount token")
		}
		return tok, nil
	}
}

// StaticTokenSource returns a fixed bearer token (used in standalone mode and tests).
func StaticTokenSource(token string) TokenSource {
	return func() (string, error) {
		if strings.TrimSpace(token) == "" {
			return "", errors.New("muster: empty token")
		}
		return strings.TrimSpace(token), nil
	}
}

// Refusal is the fixed three-field error payload returned by Muster on >= 400.
type Refusal struct {
	Error  string `json:"error"`
	Cause  string `json:"cause"`
	Reason string `json:"reason"`
}

// RefusalError wraps an HTTP status and a Contract v1 Refusal.
type RefusalError struct {
	Status int
	Refusal
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("muster %d %s (%s): %s", e.Status, e.Refusal.Error, e.Cause, e.Reason)
}

// UnwrapRefusal extracts a *RefusalError from err if present.
func UnwrapRefusal(err error) (*RefusalError, bool) {
	var re *RefusalError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// IsRetryable reports whether err is a transient 429/503 refusal.
func IsRetryable(err error) bool {
	re, ok := UnwrapRefusal(err)
	if !ok {
		return false
	}
	return re.Status == http.StatusTooManyRequests || re.Status == http.StatusServiceUnavailable
}

// ClientError represents a sanitized client-side validation or transport error.
type ClientError struct {
	Code    string
	Message string
}

func (e *ClientError) Error() string {
	return e.Code + ": " + e.Message
}

// EditRequest carries the fields Conn forwards to POST /v1/edits.
type EditRequest struct {
	Target   string
	Change   string
	Reason   string
	Pow      string
	Honeypot string
	Source   string
}

type wireEditRequest struct {
	Contract string `json:"contract"`
	Target   string `json:"target"`
	Change   string `json:"change"`
	Reason   string `json:"reason"`
	Pow      string `json:"pow"`
	Honeypot string `json:"honeypot"`
	Source   string `json:"source"`
}

// EditReceipt is Muster's 202 response to an accepted edit proposal.
type EditReceipt struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// ItemRequest carries the fields Conn forwards to POST /v1/items.
type ItemRequest struct {
	Source  string
	Title   string
	Address string
	Result  json.RawMessage
	Pow     string
	Visitor string
}

type wireItemRequest struct {
	Contract string          `json:"contract"`
	Source   string          `json:"source"`
	Title    string          `json:"title"`
	Address  string          `json:"address"`
	Result   json.RawMessage `json:"result,omitempty"`
	Pow      string          `json:"pow,omitempty"`
	Visitor  string          `json:"visitor,omitempty"`
}

// ItemReceipt is Muster's 201 (new) or 200 (duplicate) response to POST /v1/items.
type ItemReceipt struct {
	StatusCode int    `json:"-"`
	ID         string `json:"id"`
	State      string `json:"state"`
	Next       string `json:"next,omitempty"`
	Duplicate  bool   `json:"duplicate,omitempty"`
}

// FeedEvent is one Server-Sent Event frame read from GET /v1/feed.
type FeedEvent struct {
	ID    string
	Event string
	Data  []byte
}

// DepthsData is the JSON payload of a "depths" SSE event.
type DepthsData struct {
	At           string `json:"at"`
	Urgent       int    `json:"urgent"`
	Normal       int    `json:"normal"`
	Backfill     int    `json:"backfill"`
	NeedsSubtool int    `json:"needs_subtool"`
}

// HealthData is the JSON payload of a "health" SSE event.
type HealthData struct {
	At        string `json:"at"`
	Component string `json:"component"`
	State     string `json:"state"`
	Code      string `json:"code,omitempty"`
}

// EditData is the JSON payload of an "edit" SSE event.
type EditData struct {
	At     string `json:"at"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// FeedStream reads Server-Sent Events from Muster's GET /v1/feed endpoint.
type FeedStream struct {
	body io.ReadCloser
	br   *bufio.Reader
}

// Close closes the underlying HTTP response body.
func (fs *FeedStream) Close() error {
	if fs == nil || fs.body == nil {
		return nil
	}
	return fs.body.Close()
}

// Next reads the next complete SSE event frame from the stream.
func (fs *FeedStream) Next() (FeedEvent, error) {
	var ev FeedEvent
	var dataBuf bytes.Buffer
	hasFields := false

	for {
		line, err := readBoundedLine(fs.br, MaxSSELineBytes)
		if err != nil {
			if errors.Is(err, io.EOF) && hasFields {
				ev.Data = bytes.TrimSuffix(dataBuf.Bytes(), []byte("\n"))
				return ev, nil
			}
			return FeedEvent{}, err
		}

		line = strings.TrimSuffix(line, "\r\n")
		line = strings.TrimSuffix(line, "\n")

		if line == "" {
			if !hasFields {
				continue
			}
			ev.Data = bytes.TrimSuffix(dataBuf.Bytes(), []byte("\n"))
			return ev, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}

		field, val, hasColon := strings.Cut(line, ":")
		if hasColon && strings.HasPrefix(val, " ") {
			val = val[1:]
		}
		switch field {
		case "id":
			ev.ID = val
			hasFields = true
		case "event":
			ev.Event = val
			hasFields = true
		case "data":
			dataBuf.WriteString(val)
			dataBuf.WriteByte('\n')
			hasFields = true
		}
	}
}

func readBoundedLine(r *bufio.Reader, maxBytes int) (string, error) {
	var out bytes.Buffer
	for {
		frag, isPrefix, err := r.ReadLine()
		out.Write(frag)
		if out.Len() > maxBytes {
			return "", &ClientError{Code: CodeParse, Message: "sse line exceeded maximum byte limit"}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && out.Len() > 0 {
				return out.String(), nil
			}
			return "", err
		}
		if !isPrefix {
			out.WriteByte('\n')
			return out.String(), nil
		}
	}
}

// Client calls Muster's Contract v1 endpoints on behalf of Conn.
type Client struct {
	baseURL    string
	tokenSrc   TokenSource
	httpClient *http.Client
	streamHTTP *http.Client
}

// NewClient constructs a hardened Contract v1 client that never follows HTTP redirects.
func NewClient(baseURL string, tokenSrc TokenSource, customHTTP *http.Client) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, &ClientError{Code: CodeParse, Message: "invalid muster base url"}
	}
	if tokenSrc == nil {
		return nil, &ClientError{Code: CodeParse, Message: "missing muster token source"}
	}

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return errors.New("redirects refused")
	}

	var shortClient http.Client
	var longClient http.Client
	if customHTTP != nil {
		shortClient = *customHTTP
		longClient = *customHTTP
	}
	shortClient.CheckRedirect = noRedirect
	if shortClient.Timeout == 0 {
		shortClient.Timeout = 10 * time.Second
	}
	longClient.CheckRedirect = noRedirect
	longClient.Timeout = 0 // SSE stream uses context cancellation instead of a fixed response timeout.

	return &Client{
		baseURL:    trimmed,
		tokenSrc:   tokenSrc,
		httpClient: &shortClient,
		streamHTTP: &longClient,
	}, nil
}

// SubmitEdit sends an anonymous edit proposal to Muster POST /v1/edits.
// Returns (nil, nil) when Muster responds 204 (honeypot silent drop).
func (c *Client) SubmitEdit(ctx context.Context, req EditRequest) (*EditReceipt, error) {
	wire := wireEditRequest{
		Contract: ContractVersion,
		Target:   req.Target,
		Change:   req.Change,
		Reason:   req.Reason,
		Pow:      req.Pow,
		Honeypot: req.Honeypot,
		Source:   req.Source,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wire); err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "failed encoding edit request"}
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(payload) > MaxEditBodyBytes {
		return nil, &RefusalError{
			Status: http.StatusRequestEntityTooLarge,
			Refusal: Refusal{
				Error:  CodeParse,
				Cause:  "too_large",
				Reason: "the request is too large",
			},
		}
	}

	status, body, err := c.doJSON(ctx, http.MethodPost, PathEdits, payload, true)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	if status != http.StatusAccepted {
		return nil, &ClientError{Code: CodeParse, Message: "unexpected status from muster edits endpoint"}
	}
	var receipt EditReceipt
	if err := decodeStrictJSON(body, &receipt); err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "malformed receipt from muster edits endpoint"}
	}
	return &receipt, nil
}

// SubmitItem sends a candidate item (such as source "site-form") to Muster POST /v1/items.
func (c *Client) SubmitItem(ctx context.Context, req ItemRequest) (*ItemReceipt, error) {
	if req.Source == "" {
		req.Source = SourceSiteForm
	}
	if req.Source == SourceSiteForm && (req.Pow == "" || req.Visitor == "") {
		return nil, &ClientError{Code: CodeParse, Message: "site-form submission requires pow and visitor"}
	}
	wire := wireItemRequest{
		Contract: ContractVersion,
		Source:   req.Source,
		Title:    req.Title,
		Address:  req.Address,
		Result:   req.Result,
		Pow:      req.Pow,
		Visitor:  req.Visitor,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wire); err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "failed encoding item request"}
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(payload) > MaxItemBodyBytes {
		return nil, &RefusalError{
			Status: http.StatusRequestEntityTooLarge,
			Refusal: Refusal{
				Error:  CodeParse,
				Cause:  "too_large",
				Reason: "the request is too large",
			},
		}
	}

	status, body, err := c.doJSON(ctx, http.MethodPost, PathItems, payload, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, &ClientError{Code: CodeParse, Message: "unexpected status from muster items endpoint"}
	}
	var receipt ItemReceipt
	if err := decodeStrictJSON(body, &receipt); err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "malformed receipt from muster items endpoint"}
	}
	receipt.StatusCode = status
	return &receipt, nil
}

// OpenFeed opens Muster's GET /v1/feed SSE stream with a fresh bearer token.
func (c *Client) OpenFeed(ctx context.Context) (*FeedStream, error) {
	tok, err := c.tokenSrc()
	if err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "unable to load bearer token"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+PathFeed, nil)
	if err != nil {
		return nil, &ClientError{Code: CodeParse, Message: "unable to construct feed request"}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.streamHTTP.Do(req)
	if err != nil {
		return nil, &ClientError{Code: CodeTimeout, Message: "unable to reach muster feed"}
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
		return nil, decodeRefusalOrError(resp.StatusCode, raw)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &ClientError{Code: CodeParse, Message: "unexpected feed response status"}
	}
	return &FeedStream{
		body: resp.Body,
		br:   bufio.NewReaderSize(resp.Body, 16*1024),
	}, nil
}

// Healthz checks Muster's unauthenticated GET /healthz endpoint.
func (c *Client) Healthz(ctx context.Context) error {
	status, body, err := c.doJSON(ctx, http.MethodGet, PathHealthz, nil, false)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &ClientError{Code: CodeTimeout, Message: "muster healthz non-200"}
	}
	var hz struct {
		Status string `json:"status"`
	}
	if err := decodeStrictJSON(body, &hz); err != nil || hz.Status != "ok" {
		return &ClientError{Code: CodeParse, Message: "malformed muster healthz body"}
	}
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload []byte, withAuth bool) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, &ClientError{Code: CodeParse, Message: "failed constructing request"}
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withAuth {
		tok, terr := c.tokenSrc()
		if terr != nil {
			return 0, nil, &ClientError{Code: CodeParse, Message: "unable to load bearer token"}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, &ClientError{Code: CodeTimeout, Message: "muster request failed or timed out"}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, nil, &ClientError{Code: CodeTimeout, Message: "failed reading muster response"}
	}
	if len(raw) > MaxResponseBytes {
		return 0, nil, &ClientError{Code: CodeParse, Message: "muster response exceeded size limit"}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, nil, decodeRefusalOrError(resp.StatusCode, raw)
	}
	return resp.StatusCode, raw, nil
}

func decodeRefusalOrError(status int, raw []byte) error {
	var ref Refusal
	if err := decodeStrictJSON(raw, &ref); err == nil && ref.Error != "" && ref.Cause != "" && ref.Reason != "" {
		return &RefusalError{Status: status, Refusal: ref}
	}
	code := CodeParse
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
		code = CodeTimeout
	}
	return &ClientError{Code: code, Message: "muster returned non-contract error response"}
}

func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing tokens")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected extra JSON value")
	}
	return nil
}
