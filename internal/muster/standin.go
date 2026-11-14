package muster

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ClearedStack/conn/internal/ownership"
	"github.com/ClearedStack/conn/internal/pow"
	"github.com/ClearedStack/conn/internal/pubstore"
)

const (
	defaultLeaseDuration = 60 * time.Second
	defaultDailyCap      = 5
	sevenDays            = 7 * 24 * time.Hour
	defaultStandinSalt   = "made-up-salt-secret-for-tests-only-0123456789abcdef"
)

// DefaultStandinOwnershipJSON matches the targets used in Muster Contract v1 examples
// as well as Conn's standalone seed catalog entries.
const DefaultStandinOwnershipJSON = `{
  "elements": {
    "catalog.sample-calculator.description": {
      "repository": "clearedstack.com",
      "file": "src/data/sample-catalog.json",
      "kind": "DATA"
    },
    "catalog.sample-clause-matrix.description": {
      "repository": "conn",
      "file": "internal/pubstore/memory.go",
      "kind": "DATA"
    },
    "catalog.sample-scoping-handbook.description": {
      "repository": "conn",
      "file": "internal/pubstore/memory.go",
      "kind": "DATA"
    },
    "catalog.sample-pool-estimator.description": {
      "repository": "conn",
      "file": "internal/pubstore/memory.go",
      "kind": "DATA"
    },
    "catalog.sample-repealed-notice-helper.description": {
      "repository": "conn",
      "file": "internal/pubstore/memory.go",
      "kind": "DATA"
    },
    "sextant.sample-portal.options": {
      "repository": "sextant",
      "file": "tools/sample-portal/options.json",
      "kind": "CONFIG"
    },
    "assay.sample-profile.report": {
      "repository": "assay",
      "file": "tools/sample-profile/README.md",
      "kind": "ISSUE"
    }
  }
}`

var (
	workerSet = map[string]bool{
		"trawl": true, "sextant": true, "assay": true, "countersign": true, "waybill": true,
		"moldloft": true, "shakedown": true, "chartroom": true, "tidegauge": true, "bellbuoy": true,
	}
	knownCallers = map[string]bool{
		"trawl": true, "sextant": true, "assay": true, "countersign": true, "waybill": true,
		"moldloft": true, "shakedown": true, "chartroom": true, "tidegauge": true, "bellbuoy": true,
		"conn": true, "shipkeeper": true,
	}
	healthStates = map[string]bool{
		"healthy": true, "idle": true, "degraded": true, "paused": true,
	}
	publicCodes = map[string]bool{
		CodeTimeout: true, CodeParse: true, CodeNeedsSubtool: true,
	}
	itemSources = map[string]string{
		"sam-gov":       "normal",
		"github-issues": "normal",
		"web-sweep":     "backfill",
		"site-form":     "normal",
	}
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	itemIDRegex   = regexp.MustCompile(`^PA-([0-9]{4}|[1-9][0-9]{4,8})$`)
)

// Fixed Contract v1 refusals.
var (
	refNotJSON           = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "not_json", "the request is not one json value"}}
	refUnknownField      = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "unknown_field", "the request has a field this call does not define"}}
	refMissingField      = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "missing_field", "a required field is missing"}}
	refBadField          = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "a field does not have the form this call requires"}}
	refUseNeedsSubtool   = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "report a missing rule with the needs_subtool call"}}
	refBadProof          = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "the proof of work is not valid"}}
	refUnknownTarget     = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "the target is not in the ownership map"}}
	refNothingLeft       = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "nothing is left of the text once markup is removed"}}
	refLogbookRefused    = &RefusalError{http.StatusBadRequest, Refusal{CodeParse, "bad_field", "the record store refused a field"}}
	refNoCredential      = &RefusalError{http.StatusUnauthorized, Refusal{CodeParse, "no_credential", "no valid credential was presented"}}
	refNotYourCall       = &RefusalError{http.StatusForbidden, Refusal{CodeParse, "not_your_call", "this caller may not make this call"}}
	refNoSuchCall        = &RefusalError{http.StatusNotFound, Refusal{CodeParse, "no_such_call", "no such call"}}
	refWrongMethod       = &RefusalError{http.StatusMethodNotAllowed, Refusal{CodeParse, "wrong_method", "this call does not accept that method"}}
	refTooLarge          = &RefusalError{http.StatusRequestEntityTooLarge, Refusal{CodeParse, "too_large", "the request is too large"}}
	refWrongType         = &RefusalError{http.StatusUnsupportedMediaType, Refusal{CodeParse, "wrong_type", "the content type must be application/json"}}
	refLeaseNotHeld      = &RefusalError{http.StatusConflict, Refusal{CodeParse, "lease_not_held", "the lease is not held"}}
	refMoveNotAllowed    = &RefusalError{http.StatusConflict, Refusal{CodeParse, "move_not_allowed", "that move is not allowed"}}
	refDuplicate         = &RefusalError{http.StatusConflict, Refusal{CodeParse, "duplicate", "the same component is reported twice in one batch"}}
	refUnknownContract   = &RefusalError{http.StatusUnprocessableEntity, Refusal{CodeNeedsSubtool, "unknown_contract", "this contract version is not known"}}
	refUnknownHealth     = &RefusalError{http.StatusUnprocessableEntity, Refusal{CodeNeedsSubtool, "unknown_value", "this health state is not known"}}
	refUnknownSource     = &RefusalError{http.StatusUnprocessableEntity, Refusal{CodeNeedsSubtool, "unknown_value", "this source is not known"}}
	refLogbookUnfamiliar = &RefusalError{http.StatusUnprocessableEntity, Refusal{CodeNeedsSubtool, "unknown_value", "the record store has no rule for a value"}}
	refRateLimited       = &RefusalError{http.StatusTooManyRequests, Refusal{CodeTimeout, "rate_limited", "too many submissions from this visitor today; try again tomorrow"}}
	refStoreSlow         = &RefusalError{http.StatusServiceUnavailable, Refusal{CodeTimeout, "store_slow", "the record store took too long"}}
	refBusy              = &RefusalError{http.StatusServiceUnavailable, Refusal{CodeTimeout, "busy", "too busy; try again"}}
	refIdentitySlow      = &RefusalError{http.StatusServiceUnavailable, Refusal{CodeTimeout, "busy", "the identity check took too long; try again"}}
	refBadRecord         = &RefusalError{http.StatusInternalServerError, Refusal{CodeParse, "bad_record", "a stored record was not consistent and has been set aside"}}
	refUnexpected        = &RefusalError{http.StatusInternalServerError, Refusal{CodeParse, "unexpected", "an unexpected condition; the request was refused"}}
)

// AllContractRefusals returns all 28 fixed Contract v1 refusal definitions.
func AllContractRefusals() []*RefusalError {
	return []*RefusalError{
		refNotJSON, refUnknownField, refMissingField, refBadField, refUseNeedsSubtool,
		refBadProof, refUnknownTarget, refNothingLeft, refLogbookRefused,
		refNoCredential, refNotYourCall, refNoSuchCall, refWrongMethod, refTooLarge, refWrongType,
		refLeaseNotHeld, refMoveNotAllowed, refDuplicate,
		refUnknownContract, refUnknownHealth, refUnknownSource, refLogbookUnfamiliar,
		refRateLimited, refStoreSlow, refBusy, refIdentitySlow, refBadRecord, refUnexpected,
	}
}

// SeedItem represents an initial item record in Standin.
type SeedItem struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Lane  string `json:"lane"`
	Next  string `json:"next,omitempty"`
}

type standinItem struct {
	ID         string
	State      string
	Lane       string
	Source     string
	Title      string
	Address    string
	Results    map[string]json.RawMessage
	PausedFrom string
	PausedBy   string
	PausedSeq  int
}

type standinProposal struct {
	ID         string
	Target     string
	Repository string
	File       string
	EditKind   string
	Change     string
	Reason     string
	Status     string
	Results    map[string]json.RawMessage
}

type standinEntry struct {
	Key        string
	Arrival    int
	Subject    string
	Kind       string // "item", "proposal", "incident"
	Worker     string
	Lane       string
	NotBefore  time.Time
	Attempt    int
	LeaseName  string
	LeaseOwner string
	LeasedTill time.Time
	Held       bool
	Incident   *standinIncident
}

type standinIncident struct {
	ID     string `json:"id"`
	Worker string `json:"worker"`
	Code   string `json:"code"`
	State  string `json:"state"`
}

type standinHealth struct {
	Component string
	State     string
	Code      string
	Digest    string
	At        time.Time
}

// Standin is a self-contained in-memory Muster Contract v1 HTTP server.
type Standin struct {
	mu          sync.Mutex
	now         time.Time
	owners      *ownership.Map
	saltSecret  []byte
	difficulty  int
	dailyCap    int
	condition   string
	nextItemNum int
	nextPropNum int
	nextArrival int
	nextPauseSq int
	nextSSEID   uint64

	items       map[string]*standinItem
	addrToItem  map[string]string
	proposals   map[string]*standinProposal
	entries     []*standinEntry
	health      map[string]standinHealth
	submissions map[string]int
	subs        map[chan []byte]struct{}
}

// NewStandin creates a new Muster Contract v1 stand-in starting at 2026-01-05T09:00:00Z.
func NewStandin(seed []SeedItem, customOwners *ownership.Map) *Standin {
	owners := customOwners
	if owners == nil {
		owners, _ = ownership.Parse([]byte(DefaultStandinOwnershipJSON))
	}
	s := &Standin{
		now:         time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC),
		owners:      owners,
		saltSecret:  []byte(defaultStandinSalt),
		difficulty:  pow.DefaultDifficulty,
		dailyCap:    defaultDailyCap,
		items:       make(map[string]*standinItem),
		addrToItem:  make(map[string]string),
		proposals:   make(map[string]*standinProposal),
		health:      make(map[string]standinHealth),
		submissions: make(map[string]int),
		subs:        make(map[chan []byte]struct{}),
	}
	for _, si := range seed {
		s.AddSeedItem(si)
	}
	return s
}

// TokenFor returns the bearer token Standin accepts for caller slug.
func (s *Standin) TokenFor(caller string) string {
	if caller == "" {
		return ""
	}
	return "tok-" + caller
}

// SetClock sets Standin's current UTC timestamp.
func (s *Standin) SetClock(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = t.UTC()
}

// Advance moves Standin's clock forward by d.
func (s *Standin) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

// SetCondition configures a synthetic fault condition from Contract v1 examples.
func (s *Standin) SetCondition(cond string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.condition = cond
	if cond == "the queue says sextant is next for an item that is live" {
		s.items["PA-0001"] = &standinItem{
			ID:      "PA-0001",
			State:   "live",
			Lane:    "normal",
			Title:   "Made-up item PA-0001",
			Results: map[string]json.RawMessage{},
		}
		s.nextArrival++
		s.entries = append(s.entries, &standinEntry{
			Key:     "PA-0001",
			Arrival: s.nextArrival,
			Subject: "PA-0001",
			Kind:    "item",
			Worker:  "sextant",
			Lane:    "normal",
		})
	}
}

// AddSeedItem inserts an item and optional queue step into Standin.
func (s *Standin) AddSeedItem(si SeedItem) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if num, err := strconv.Atoi(strings.TrimPrefix(si.ID, "PA-")); err == nil && num > s.nextItemNum {
		s.nextItemNum = num
	}
	lane := si.Lane
	if lane == "" {
		lane = "normal"
	}
	s.items[si.ID] = &standinItem{
		ID:      si.ID,
		State:   si.State,
		Lane:    lane,
		Title:   "Made-up item " + si.ID,
		Results: map[string]json.RawMessage{},
	}
	nextWorker := si.Next
	if nextWorker == "" {
		nextWorker = defaultWorkerForSeedState(si.State)
	}
	if nextWorker != "" {
		s.nextArrival++
		s.entries = append(s.entries, &standinEntry{
			Key:     si.ID,
			Arrival: s.nextArrival,
			Subject: si.ID,
			Kind:    "item",
			Worker:  nextWorker,
			Lane:    lane,
		})
	}
}

func defaultWorkerForSeedState(state string) string {
	switch state {
	case "discovered":
		return "trawl"
	case "recorded":
		return "sextant"
	case "observed":
		return "assay"
	case "scored", "screened_out":
		return "countersign"
	case "approved":
		return "waybill"
	case "live":
		return "tidegauge"
	default:
		return ""
	}
}

// BroadcastTick emits a periodic depths SSE frame to all connected subscribers.
func (s *Standin) BroadcastTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	frame := s.makeFrameLocked("depths", s.depthsPayloadLocked())
	s.fanOutLocked(frame)
}

// EmitEditStatus updates a proposal's status and pushes an edit SSE event.
func (s *Standin) EmitEditStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.proposals[id]; ok {
		p.Status = status
	}
	depths := s.makeFrameLocked("depths", s.depthsPayloadLocked())
	edit := s.makeFrameLocked("edit", EditData{
		At:     s.now.UTC().Format(time.RFC3339),
		ID:     id,
		Status: status,
	})
	s.fanOutLocked(depths, edit)
}

// ServeHTTP implements Muster's Contract v1 HTTP endpoints.
func (s *Standin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == PathHealthz {
		if r.Method != http.MethodGet {
			writeRefusal(w, refWrongMethod)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	knownPath, wantMethod := contractPathMethod(r.URL.Path)
	if !knownPath {
		// Authenticate before 404 or check 404? Check refused-404-no_such_call.json: caller is authenticated.
		writeRefusal(w, refNoSuchCall)
		return
	}
	if r.Method != wantMethod {
		writeRefusal(w, refWrongMethod)
		return
	}

	s.mu.Lock()
	cond := s.condition
	s.mu.Unlock()

	if cond == "every place for a call in flight is taken" {
		writeRefusal(w, refBusy)
		return
	}
	if cond == "the cluster does not answer the identity check in time" {
		writeRefusal(w, refIdentitySlow)
		return
	}

	caller, ok := authenticateToken(r.Header.Get("Authorization"))
	if !ok {
		writeRefusal(w, refNoCredential)
		return
	}
	if !authorizedForPath(caller, r.URL.Path) {
		writeRefusal(w, refNotYourCall)
		return
	}

	if r.URL.Path == PathFeed {
		s.handleFeed(w, r, cond)
		return
	}

	ct := r.Header.Get("Content-Type")
	mediaType, _, _ := strings.Cut(ct, ";")
	if strings.TrimSpace(strings.ToLower(mediaType)) != "application/json" {
		writeRefusal(w, refWrongType)
		return
	}

	maxBody := MaxItemBodyBytes
	if r.URL.Path == PathComplete && caller == "waybill" {
		maxBody = MaxWaybillBodyBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBody)+1))
	if err != nil {
		writeRefusal(w, refNotJSON)
		return
	}
	if len(raw) > maxBody {
		writeRefusal(w, refTooLarge)
		return
	}

	// Check JSON syntax and contract field first.
	var env map[string]json.RawMessage
	if err := decodeSingleObject(raw, &env); err != nil {
		writeRefusal(w, refNotJSON)
		return
	}

	switch r.URL.Path {
	case PathLease:
		s.handleLease(w, caller, raw, cond)
	case PathHeartbeat:
		s.handleHeartbeat(w, caller, raw, cond)
	case PathComplete:
		s.handleComplete(w, caller, raw, cond)
	case PathFail:
		s.handleFail(w, caller, raw, cond)
	case PathNeedsSubtool:
		s.handleNeedsSubtool(w, caller, raw, cond)
	case PathRelease:
		s.handleRelease(w, raw, cond)
	case PathItems:
		s.handleItems(w, caller, raw, cond)
	case PathHealth:
		s.handleHealth(w, raw, cond)
	case PathEdits:
		s.handleEdits(w, raw, cond)
	}
}

func contractPathMethod(path string) (bool, string) {
	switch path {
	case PathFeed:
		return true, http.MethodGet
	case PathLease, PathHeartbeat, PathComplete, PathFail, PathNeedsSubtool,
		PathItems, PathRelease, PathHealth, PathEdits:
		return true, http.MethodPost
	default:
		return false, ""
	}
}

func authenticateToken(hdr string) (string, bool) {
	if !strings.HasPrefix(hdr, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	if !strings.HasPrefix(tok, "tok-") {
		return "", false
	}
	caller := strings.TrimPrefix(tok, "tok-")
	if !knownCallers[caller] {
		return "", false
	}
	return caller, true
}

func authorizedForPath(caller, path string) bool {
	switch path {
	case PathLease, PathHeartbeat, PathComplete, PathFail, PathNeedsSubtool:
		return workerSet[caller]
	case PathItems:
		return caller == "trawl" || caller == "conn"
	case PathRelease:
		return caller == "countersign"
	case PathHealth:
		return caller == "shipkeeper"
	case PathEdits, PathFeed:
		return caller == "conn"
	default:
		return false
	}
}

func checkStoreCondition(cond string) *RefusalError {
	switch cond {
	case "logbook takes too long":
		return refStoreSlow
	case "logbook fails in a way nothing provides for":
		return refUnexpected
	case "logbook refuses a field":
		return refLogbookRefused
	case "logbook has no rule for a value":
		return refLogbookUnfamiliar
	default:
		return nil
	}
}

func decodeSingleObject(raw []byte, dst *map[string]json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return io.ErrUnexpectedEOF
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return io.ErrUnexpectedEOF
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func decodeStrictFields(raw []byte, dst any) *RefusalError {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.Contains(err.Error(), "json: unknown field ") {
			return refUnknownField
		}
		return refBadField
	}
	return nil
}

func checkContractField(contract string) *RefusalError {
	if contract == "" {
		return refMissingField
	}
	if contract != ContractVersion {
		return refUnknownContract
	}
	return nil
}

func (s *Standin) handleLease(w http.ResponseWriter, worker string, raw []byte, cond string) {
	var req struct {
		Contract string `json:"contract"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bestIdx := -1
	bestRank := 99
	for i, e := range s.entries {
		if e.Worker != worker || e.Held || e.NotBefore.After(s.now) {
			continue
		}
		if e.LeaseName != "" && e.LeasedTill.After(s.now) {
			continue
		}
		rank := laneRank(e.Lane)
		if rank < bestRank || (rank == bestRank && (bestIdx == -1 || e.Arrival < s.entries[bestIdx].Arrival)) {
			bestIdx = i
			bestRank = rank
		}
	}
	if bestIdx < 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	entry := s.entries[bestIdx]
	if entry.Kind == "item" {
		it := s.items[entry.Subject]
		if it == nil || !workerCanHoldItemState(worker, it.State) {
			entry.Held = true
			s.addIncidentLocked(entry.Subject, worker, CodeParse, safeItemState(it))
			writeRefusal(w, refBadRecord)
			return
		}
	}

	entry.Attempt++
	prefix := entry.Subject
	if entry.Kind == "incident" {
		prefix = "incident:" + entry.Subject
	}
	entry.LeaseName = fmt.Sprintf("%s.%d.%d", prefix, entry.Arrival, entry.Attempt)
	entry.LeaseOwner = worker
	entry.LeasedTill = s.now.Add(defaultLeaseDuration)

	type foundPayload struct {
		Source  string `json:"source"`
		Title   string `json:"title"`
		Address string `json:"address"`
	}
	type propPayload struct {
		Target     string `json:"target"`
		Repository string `json:"repository"`
		File       string `json:"file"`
		EditKind   string `json:"edit_kind"`
		Change     string `json:"change"`
		Reason     string `json:"reason"`
	}
	type grantResp struct {
		Lease    string                     `json:"lease"`
		Kind     string                     `json:"kind"`
		ID       string                     `json:"id"`
		State    string                     `json:"state"`
		Lane     string                     `json:"lane"`
		Attempt  int                        `json:"attempt"`
		Expires  string                     `json:"expires"`
		Found    *foundPayload              `json:"found,omitempty"`
		Results  map[string]json.RawMessage `json:"results,omitempty"`
		Proposal *propPayload               `json:"proposal,omitempty"`
		Incident *standinIncident           `json:"incident,omitempty"`
	}

	resp := grantResp{
		Lease:   entry.LeaseName,
		Kind:    entry.Kind,
		ID:      entry.Subject,
		Lane:    entry.Lane,
		Attempt: entry.Attempt,
		Expires: entry.LeasedTill.UTC().Format(time.RFC3339),
	}

	switch entry.Kind {
	case "item":
		it := s.items[entry.Subject]
		resp.State = it.State
		if it.Source != "" && it.Address != "" {
			resp.Found = &foundPayload{Source: it.Source, Title: it.Title, Address: it.Address}
		}
		if len(it.Results) > 0 {
			resp.Results = copyRawMap(it.Results)
		}
	case "proposal":
		pr := s.proposals[entry.Subject]
		resp.State = pr.Status
		if len(pr.Results) > 0 {
			resp.Results = copyRawMap(pr.Results)
		}
		resp.Proposal = &propPayload{
			Target:     pr.Target,
			Repository: pr.Repository,
			File:       pr.File,
			EditKind:   pr.EditKind,
			Change:     pr.Change,
			Reason:     pr.Reason,
		}
	case "incident":
		resp.State = entry.Incident.State
		cp := *entry.Incident
		resp.Incident = &cp
	}

	writeJSONResp(w, http.StatusOK, resp)
}

func (s *Standin) handleHeartbeat(w http.ResponseWriter, worker string, raw []byte, cond string) {
	var req struct {
		Contract string `json:"contract"`
		Lease    string `json:"lease"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if req.Lease == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.findHeldLeaseLocked(worker, req.Lease, false)
	if entry == nil {
		writeRefusal(w, refLeaseNotHeld)
		return
	}
	entry.LeasedTill = s.now.Add(defaultLeaseDuration)
	writeJSONResp(w, http.StatusOK, struct {
		Lease   string `json:"lease"`
		Expires string `json:"expires"`
	}{
		Lease:   entry.LeaseName,
		Expires: entry.LeasedTill.UTC().Format(time.RFC3339),
	})
}

func (s *Standin) handleComplete(w http.ResponseWriter, worker string, raw []byte, cond string) {
	var req struct {
		Contract string          `json:"contract"`
		Lease    string          `json:"lease"`
		State    string          `json:"state"`
		Result   json.RawMessage `json:"result,omitempty"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if req.Lease == "" || req.State == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if len(req.Result) > 0 {
		trimmed := bytes.TrimSpace(req.Result)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			writeRefusal(w, refBadField)
			return
		}
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) != nil {
			writeRefusal(w, refBadField)
			return
		}
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.findHeldLeaseLocked(worker, req.Lease, true)
	if entry == nil {
		writeRefusal(w, refLeaseNotHeld)
		return
	}

	switch entry.Kind {
	case "incident":
		if len(req.Result) > 0 || req.State != entry.Incident.State {
			writeRefusal(w, refMoveNotAllowed)
			return
		}
		s.removeEntryLocked(entry)
		writeJSONResp(w, http.StatusOK, struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}{ID: entry.Subject, State: req.State})

	case "proposal":
		pr := s.proposals[entry.Subject]
		nextWorker, nextLane, ok := nextProposalStep(worker, pr.Status, req.State)
		if !ok {
			writeRefusal(w, refMoveNotAllowed)
			return
		}
		pr.Status = req.State
		if len(req.Result) > 0 {
			pr.Results[worker] = append(json.RawMessage(nil), req.Result...)
		}
		s.removeEntryLocked(entry)
		if nextWorker != "" {
			s.nextArrival++
			s.entries = append(s.entries, &standinEntry{
				Key:     pr.ID,
				Arrival: s.nextArrival,
				Subject: pr.ID,
				Kind:    "proposal",
				Worker:  nextWorker,
				Lane:    nextLane,
			})
		}
		writeJSONResp(w, http.StatusOK, ackResponse{ID: pr.ID, State: pr.Status, Next: nextWorker})

	case "item":
		it := s.items[entry.Subject]
		if !knownItemOrProposalState(req.State) {
			writeRefusal(w, refBadField)
			return
		}
		nextWorker, nextLane, delay, ok := nextItemStep(worker, it.State, req.State, entry.Lane)
		if !ok {
			writeRefusal(w, refMoveNotAllowed)
			return
		}
		it.State = req.State
		if len(req.Result) > 0 {
			it.Results[worker] = append(json.RawMessage(nil), req.Result...)
		}
		s.removeEntryLocked(entry)
		if nextWorker != "" {
			s.nextArrival++
			s.entries = append(s.entries, &standinEntry{
				Key:       it.ID,
				Arrival:   s.nextArrival,
				Subject:   it.ID,
				Kind:      "item",
				Worker:    nextWorker,
				Lane:      nextLane,
				NotBefore: s.now.Add(delay),
			})
		}
		writeJSONResp(w, http.StatusOK, ackResponse{ID: it.ID, State: it.State, Next: nextWorker})
	}
}

type ackResponse struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Next  string `json:"next,omitempty"`
	Held  bool   `json:"held,omitempty"`
}

func (s *Standin) handleFail(w http.ResponseWriter, worker string, raw []byte, cond string) {
	var req struct {
		Contract string `json:"contract"`
		Lease    string `json:"lease"`
		Code     string `json:"code"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if req.Lease == "" || req.Code == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if req.Code == CodeNeedsSubtool {
		writeRefusal(w, refUseNeedsSubtool)
		return
	}
	if req.Code != CodeTimeout && req.Code != CodeParse {
		writeRefusal(w, refBadField)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.findHeldLeaseLocked(worker, req.Lease, true)
	if entry == nil {
		writeRefusal(w, refLeaseNotHeld)
		return
	}
	curState := s.subjectStateLocked(entry)
	entry.LeaseName = ""
	entry.LeaseOwner = ""
	entry.LeasedTill = time.Time{}

	if req.Code == CodeTimeout {
		writeJSONResp(w, http.StatusOK, ackResponse{ID: entry.Subject, State: curState, Next: entry.Worker})
		return
	}

	entry.Held = true
	if entry.Kind == "item" {
		s.addIncidentLocked(entry.Subject, worker, CodeParse, curState)
	}
	writeJSONResp(w, http.StatusOK, ackResponse{ID: entry.Subject, State: curState, Held: true})
}

func (s *Standin) handleNeedsSubtool(w http.ResponseWriter, worker string, raw []byte, cond string) {
	var req struct {
		Contract string `json:"contract"`
		Lease    string `json:"lease"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if req.Lease == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.findHeldLeaseLocked(worker, req.Lease, true)
	if entry == nil {
		writeRefusal(w, refLeaseNotHeld)
		return
	}
	if entry.Kind != "item" {
		writeRefusal(w, refMoveNotAllowed)
		return
	}
	it := s.items[entry.Subject]
	if !itemStateCanPause(it.State) {
		writeRefusal(w, refMoveNotAllowed)
		return
	}
	pausedFrom := it.State
	it.State = "needs_subtool"
	it.PausedFrom = pausedFrom
	it.PausedBy = worker
	s.nextPauseSq++
	it.PausedSeq = s.nextPauseSq
	s.removeEntryLocked(entry)
	s.addIncidentLocked(it.ID, worker, CodeNeedsSubtool, pausedFrom)

	writeJSONResp(w, http.StatusOK, ackResponse{ID: it.ID, State: "needs_subtool"})
}

func (s *Standin) handleRelease(w http.ResponseWriter, raw []byte, cond string) {
	var req struct {
		Contract string `json:"contract"`
		ID       string `json:"id"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if req.ID == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if !itemIDRegex.MatchString(req.ID) {
		writeRefusal(w, refBadField)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range s.entries {
		if e.Kind == "item" && e.Subject == req.ID && e.Held {
			e.Held = false
			e.Lane = "urgent"
			s.nextArrival++
			e.Arrival = s.nextArrival
			it := s.items[req.ID]
			writeJSONResp(w, http.StatusOK, ackResponse{ID: req.ID, State: it.State, Next: e.Worker})
			return
		}
	}
	writeRefusal(w, refMoveNotAllowed)
}

func (s *Standin) handleItems(w http.ResponseWriter, caller string, raw []byte, cond string) {
	var req struct {
		Contract string          `json:"contract"`
		Source   string          `json:"source"`
		Title    string          `json:"title"`
		Address  string          `json:"address"`
		Result   json.RawMessage `json:"result,omitempty"`
		Pow      string          `json:"pow,omitempty"`
		Visitor  string          `json:"visitor,omitempty"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	for _, f := range []string{req.Source, req.Title, req.Address, req.Pow, req.Visitor} {
		if !validUTF8NoNul(f) {
			writeRefusal(w, refBadField)
			return
		}
	}
	if req.Source == "" || req.Title == "" || req.Address == "" {
		writeRefusal(w, refMissingField)
		return
	}
	if !validSlugForm(req.Source) || len(req.Title) > 200 || !plainNoControl(req.Title) || len(req.Address) > 2000 || !noSpaceOrControl(req.Address) {
		writeRefusal(w, refBadField)
		return
	}
	if len(req.Result) > 0 {
		trimmed := bytes.TrimSpace(req.Result)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			writeRefusal(w, refBadField)
			return
		}
	}
	lane, knownSrc := itemSources[req.Source]
	if !knownSrc {
		writeRefusal(w, refUnknownSource)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fromForm := req.Source == SourceSiteForm
	var visitorAddr netip.Addr
	if fromForm {
		if req.Pow == "" || req.Visitor == "" {
			writeRefusal(w, refMissingField)
			return
		}
		var ok bool
		if visitorAddr, ok = parseVisitorAddr(req.Visitor); !ok {
			writeRefusal(w, refBadField)
			return
		}
		if !pow.Verify(req.Pow, req.Source, req.Title, req.Address, s.difficulty, s.now) {
			writeRefusal(w, refBadProof)
			return
		}
	} else if req.Pow != "" || req.Visitor != "" {
		writeRefusal(w, refBadField)
		return
	}

	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	if fromForm && !s.admitVisitorLocked(visitorAddr) {
		writeRefusal(w, refRateLimited)
		return
	}
	cleanTitle := StripMarkup(req.Title)
	if cleanTitle == "" {
		writeRefusal(w, refNothingLeft)
		return
	}

	if existingID, dup := s.addrToItem[req.Address]; dup {
		it := s.items[existingID]
		writeJSONResp(w, http.StatusOK, ItemReceipt{
			ID:        it.ID,
			State:     it.State,
			Duplicate: true,
		})
		return
	}

	s.nextItemNum++
	id := formatItemID(s.nextItemNum)
	results := map[string]json.RawMessage{}
	if len(req.Result) > 0 {
		results[caller] = append(json.RawMessage(nil), req.Result...)
	}
	s.items[id] = &standinItem{
		ID:      id,
		State:   "discovered",
		Lane:    lane,
		Source:  req.Source,
		Title:   cleanTitle,
		Address: req.Address,
		Results: results,
	}
	s.addrToItem[req.Address] = id
	s.nextArrival++
	s.entries = append(s.entries, &standinEntry{
		Key:     id,
		Arrival: s.nextArrival,
		Subject: id,
		Kind:    "item",
		Worker:  "trawl",
		Lane:    lane,
	})

	writeJSONResp(w, http.StatusCreated, ItemReceipt{
		ID:    id,
		State: "discovered",
		Next:  "trawl",
	})
}

func (s *Standin) handleHealth(w http.ResponseWriter, raw []byte, cond string) {
	type report struct {
		Component string `json:"component"`
		State     string `json:"state"`
		Code      string `json:"code,omitempty"`
		Digest    string `json:"digest,omitempty"`
	}
	var req struct {
		Contract string   `json:"contract"`
		Reports  []report `json:"reports"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if len(req.Reports) == 0 {
		writeRefusal(w, refMissingField)
		return
	}
	if len(req.Reports) > 64 {
		writeRefusal(w, refBadField)
		return
	}

	seen := map[string]bool{}
	for _, rep := range req.Reports {
		if rep.Component == "" || rep.State == "" {
			writeRefusal(w, refMissingField)
			return
		}
		comp, knownComp := pubstore.LookupRegistryComponent(rep.Component)
		_ = comp
		if !knownComp {
			writeRefusal(w, refBadField)
			return
		}
		if !validSlugForm(rep.State) {
			writeRefusal(w, refBadField)
			return
		}
		if !healthStates[rep.State] {
			writeRefusal(w, refUnknownHealth)
			return
		}
		if rep.Code != "" && !publicCodes[rep.Code] {
			writeRefusal(w, refBadField)
			return
		}
		if rep.Digest != "" && !digestPattern.MatchString(rep.Digest) {
			writeRefusal(w, refBadField)
			return
		}
		if seen[rep.Component] {
			writeRefusal(w, refDuplicate)
			return
		}
		seen[rep.Component] = true
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	replayed := 0
	liveCount := 0

	for _, rep := range req.Reports {
		prev, hadPrev := s.health[rep.Component]
		digestToKeep := prev.Digest
		if rep.Digest != "" {
			digestToKeep = rep.Digest
		}
		s.health[rep.Component] = standinHealth{
			Component: rep.Component,
			State:     rep.State,
			Code:      rep.Code,
			Digest:    digestToKeep,
			At:        s.now,
		}

		if rep.Digest != "" && hadPrev && prev.Digest != "" && prev.Digest != rep.Digest {
			if workerSet[rep.Component] {
				var paused []*standinItem
				for _, it := range s.items {
					if it.State == "needs_subtool" && it.PausedBy == rep.Component {
						paused = append(paused, it)
					}
				}
				sort.Slice(paused, func(i, j int) bool { return paused[i].PausedSeq < paused[j].PausedSeq })
				for _, it := range paused {
					it.State = it.PausedFrom
					it.PausedFrom = ""
					it.PausedBy = ""
					s.nextArrival++
					s.entries = append(s.entries, &standinEntry{
						Key:     it.ID,
						Arrival: s.nextArrival,
						Subject: it.ID,
						Kind:    "item",
						Worker:  rep.Component,
						Lane:    "urgent",
					})
					replayed++
				}
			}

			comp, _ := pubstore.LookupRegistryComponent(rep.Component)
			for _, pr := range s.proposals {
				if pr.Status == "building" && repoMatchesComponent(pr.Repository, comp) {
					pr.Status = "live"
					liveCount++
				}
			}
		}
	}

	writeJSONResp(w, http.StatusOK, struct {
		Received int `json:"received"`
		Replayed int `json:"replayed"`
		Live     int `json:"live"`
	}{
		Received: len(req.Reports),
		Replayed: replayed,
		Live:     liveCount,
	})
}

func repoMatchesComponent(repo string, comp pubstore.RegistryComponent) bool {
	if repo == comp.Repository {
		return true
	}
	if comp.Slug == "conn" && repo == "clearedstack.com" {
		return true
	}
	return false
}

func (s *Standin) handleEdits(w http.ResponseWriter, raw []byte, cond string) {
	var req struct {
		Contract string  `json:"contract"`
		Target   string  `json:"target"`
		Change   string  `json:"change"`
		Reason   *string `json:"reason"`
		Pow      string  `json:"pow"`
		Honeypot *string `json:"honeypot"`
		Source   string  `json:"source"`
	}
	if ref := decodeStrictFields(raw, &req); ref != nil {
		writeRefusal(w, ref)
		return
	}
	if ref := checkContractField(req.Contract); ref != nil {
		writeRefusal(w, ref)
		return
	}
	reasonStr := ""
	if req.Reason != nil {
		reasonStr = *req.Reason
	}
	honeypotStr := ""
	if req.Honeypot != nil {
		honeypotStr = *req.Honeypot
	}
	for _, f := range []string{req.Target, req.Change, reasonStr, req.Pow, honeypotStr, req.Source} {
		if !validUTF8NoNul(f) {
			writeRefusal(w, refBadField)
			return
		}
	}
	if req.Target == "" || req.Change == "" || req.Pow == "" || req.Source == "" {
		writeRefusal(w, refMissingField)
		return
	}
	addr, ok := parseVisitorAddr(req.Source)
	if !ok {
		writeRefusal(w, refBadField)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !pow.Verify(req.Pow, req.Target, req.Change, reasonStr, s.difficulty, s.now) {
		writeRefusal(w, refBadProof)
		return
	}
	if honeypotStr != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}

	ownerEntry, knownTarget := s.owners.Lookup(req.Target)
	cleanChange := StripMarkup(req.Change)
	cleanReason := StripMarkup(reasonStr)

	var shapeVerdict *RefusalError
	switch {
	case len(raw) > MaxEditBodyBytes:
		shapeVerdict = refTooLarge
	case !knownTarget:
		shapeVerdict = refUnknownTarget
	case cleanChange == "":
		shapeVerdict = refNothingLeft
	}

	if !s.admitVisitorLocked(addr) {
		writeRefusal(w, refRateLimited)
		return
	}
	if shapeVerdict != nil {
		writeRefusal(w, shapeVerdict)
		return
	}

	s.nextPropNum++
	id := pubstore.FormatProposalID(int64(s.nextPropNum))
	s.proposals[id] = &standinProposal{
		ID:         id,
		Target:     req.Target,
		Repository: ownerEntry.Repository,
		File:       ownerEntry.File,
		EditKind:   ownerEntry.Kind,
		Change:     cleanChange,
		Reason:     cleanReason,
		Status:     "pending_approval",
		Results:    map[string]json.RawMessage{},
	}
	s.nextArrival++
	s.entries = append(s.entries, &standinEntry{
		Key:     id,
		Arrival: s.nextArrival,
		Subject: id,
		Kind:    "proposal",
		Worker:  "countersign",
		Lane:    "normal",
	})

	editFrame := s.makeFrameLocked("edit", EditData{
		At:     s.now.UTC().Format(time.RFC3339),
		ID:     id,
		Status: "pending_approval",
	})
	depthsFrame := s.makeFrameLocked("depths", s.depthsPayloadLocked())
	s.fanOutLocked(depthsFrame, editFrame)

	writeJSONResp(w, http.StatusAccepted, EditReceipt{
		ID:     id,
		Status: "pending_approval",
	})
}

func (s *Standin) handleFeed(w http.ResponseWriter, r *http.Request, cond string) {
	if ref := checkStoreCondition(cond); ref != nil {
		writeRefusal(w, ref)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeRefusal(w, refUnexpected)
		return
	}

	s.mu.Lock()
	if len(s.subs) >= 8 {
		s.mu.Unlock()
		writeRefusal(w, refBusy)
		return
	}
	ch := make(chan []byte, 64)
	ch <- s.makeFrameLocked("depths", s.depthsPayloadLocked())

	names := make([]string, 0, len(s.health))
	for name := range s.health {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h := s.health[name]
		ch <- s.makeFrameLocked("health", HealthData{
			At:        h.At.UTC().Format(time.RFC3339),
			Component: h.Component,
			State:     h.State,
			Code:      h.Code,
		})
	}
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if _, exists := s.subs[ch]; exists {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Drain initial queued snapshot immediately before waiting.
	for len(ch) > 0 {
		frame := <-ch
		_, _ = w.Write(frame)
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case frame, open := <-ch:
			if !open {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Standin) depthsPayloadLocked() DepthsData {
	d := DepthsData{At: s.now.UTC().Format(time.RFC3339)}
	for _, e := range s.entries {
		if e.Held || e.NotBefore.After(s.now) {
			continue
		}
		if e.LeaseName != "" && e.LeasedTill.After(s.now) {
			continue
		}
		switch e.Lane {
		case "urgent":
			d.Urgent++
		case "normal":
			d.Normal++
		case "backfill":
			d.Backfill++
		}
	}
	for _, it := range s.items {
		if it.State == "needs_subtool" {
			d.NeedsSubtool++
		}
	}
	return d
}

func (s *Standin) makeFrameLocked(event string, data any) []byte {
	s.nextSSEID++
	raw, _ := json.Marshal(data)
	var out bytes.Buffer
	out.WriteString("id: ")
	out.WriteString(strconv.FormatUint(s.nextSSEID, 10))
	out.WriteString("\nevent: ")
	out.WriteString(event)
	out.WriteString("\ndata: ")
	out.Write(raw)
	out.WriteString("\n\n")
	return out.Bytes()
}

func (s *Standin) fanOutLocked(frames ...[]byte) {
	for ch := range s.subs {
		if cap(ch)-len(ch) < len(frames) {
			delete(s.subs, ch)
			close(ch)
			continue
		}
		for _, f := range frames {
			ch <- f
		}
	}
}

func (s *Standin) findHeldLeaseLocked(worker, lease string, allowExpiredUnclaimed bool) *standinEntry {
	for _, e := range s.entries {
		if e.LeaseName == lease && e.LeaseOwner == worker && !e.Held {
			if allowExpiredUnclaimed || e.LeasedTill.After(s.now) {
				return e
			}
		}
	}
	return nil
}

func (s *Standin) removeEntryLocked(target *standinEntry) {
	for i, e := range s.entries {
		if e == target {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return
		}
	}
}

func (s *Standin) addIncidentLocked(itemID, worker, code, state string) {
	inc := &standinIncident{ID: itemID, Worker: worker, Code: code, State: state}
	for _, e := range s.entries {
		if e.Kind == "incident" && e.Subject == itemID {
			e.Incident = inc
			e.LeaseName = ""
			e.LeaseOwner = ""
			e.LeasedTill = time.Time{}
			return
		}
	}
	s.nextArrival++
	s.entries = append(s.entries, &standinEntry{
		Key:      "incident:" + itemID,
		Arrival:  s.nextArrival,
		Subject:  itemID,
		Kind:     "incident",
		Worker:   "bellbuoy",
		Lane:     "normal",
		Incident: inc,
	})
}

func (s *Standin) subjectStateLocked(e *standinEntry) string {
	switch e.Kind {
	case "item":
		if it := s.items[e.Subject]; it != nil {
			return it.State
		}
	case "proposal":
		if pr := s.proposals[e.Subject]; pr != nil {
			return pr.Status
		}
	case "incident":
		return e.Incident.State
	}
	return ""
}

func (s *Standin) admitVisitorLocked(addr netip.Addr) bool {
	day := s.now.UTC().Format(pow.DayLayout)
	saltMac := hmac.New(sha256.New, s.saltSecret)
	saltMac.Write([]byte("muster-salt-v1\n" + day))
	visMac := hmac.New(sha256.New, saltMac.Sum(nil))
	visMac.Write([]byte(addr.Unmap().String()))
	key := day + ":" + hex.EncodeToString(visMac.Sum(nil))
	s.submissions[key]++
	return s.submissions[key] <= s.dailyCap
}

func laneRank(lane string) int {
	switch lane {
	case "urgent":
		return 1
	case "normal":
		return 2
	case "backfill":
		return 3
	default:
		return 4
	}
}

func itemStateCanPause(state string) bool {
	switch state {
	case "recorded", "observed", "approved", "building", "live", "parked", "linked", "merged", "retired":
		return true
	default:
		return false
	}
}

func workerCanHoldItemState(worker, state string) bool {
	switch worker {
	case "trawl":
		return state == "discovered"
	case "sextant":
		return state == "recorded"
	case "assay":
		return state == "observed"
	case "countersign":
		return state == "scored" || state == "screened_out"
	case "waybill":
		return state == "approved" || state == "building"
	case "moldloft":
		return state == "approved" || state == "building"
	case "shakedown":
		return state == "building"
	case "chartroom":
		return state == "building" || state == "linked" || state == "merged" || state == "retired"
	case "tidegauge":
		return state == "live" || state == "linked" || state == "parked"
	default:
		return false
	}
}

func nextProposalStep(worker, fromStatus, toStatus string) (nextWorker, nextLane string, ok bool) {
	switch {
	case worker == "countersign" && fromStatus == "pending_approval" && toStatus == "approved":
		return "bellbuoy", "urgent", true
	case worker == "countersign" && fromStatus == "pending_approval" && toStatus == "declined":
		return "", "", true
	case worker == "bellbuoy" && fromStatus == "approved" && toStatus == "building":
		return "", "", true
	default:
		return "", "", false
	}
}

func nextItemStep(worker, fromState, toState, curLane string) (nextWorker, nextLane string, delay time.Duration, ok bool) {
	switch {
	case worker == "trawl" && fromState == "discovered" && toState == "recorded":
		return "sextant", curLane, 0, true
	case worker == "trawl" && fromState == "discovered" && toState == "rejected":
		return "", "", 0, true
	case worker == "sextant" && fromState == "recorded" && toState == "observed":
		return "assay", curLane, 0, true
	case worker == "assay" && fromState == "observed" && (toState == "scored" || toState == "screened_out"):
		return "countersign", curLane, 0, true
	case worker == "countersign" && fromState == "scored" && toState == "approved":
		return "waybill", curLane, 0, true
	case worker == "countersign" && fromState == "scored" && toState == "parked":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "countersign" && fromState == "scored" && toState == "rejected":
		return "", "", 0, true
	case worker == "countersign" && fromState == "scored" && (toState == "linked" || toState == "merged"):
		return "chartroom", curLane, 0, true
	case worker == "countersign" && fromState == "screened_out" && toState == "observed":
		return "assay", curLane, 0, true
	case worker == "waybill" && fromState == "approved" && toState == "approved":
		return "moldloft", curLane, 0, true
	case worker == "waybill" && fromState == "building" && toState == "building":
		return "moldloft", curLane, 0, true
	case worker == "moldloft" && (fromState == "approved" || fromState == "building") && toState == "building":
		return "shakedown", curLane, 0, true
	case worker == "shakedown" && fromState == "building" && toState == "building":
		return "chartroom", curLane, 0, true
	case worker == "shakedown" && fromState == "building" && toState == "parked":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "chartroom" && fromState == "building" && toState == "live":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "chartroom" && fromState == "linked" && toState == "linked":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "chartroom" && ((fromState == "merged" && toState == "merged") || (fromState == "retired" && toState == "retired")):
		return "", "", 0, true
	case worker == "tidegauge" && fromState == "live" && toState == "live":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "tidegauge" && fromState == "live" && toState == "retired":
		return "chartroom", "urgent", 0, true
	case worker == "tidegauge" && fromState == "live" && toState == "building":
		return "waybill", "urgent", 0, true
	case worker == "tidegauge" && fromState == "linked" && toState == "linked":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "tidegauge" && fromState == "linked" && toState == "observed":
		return "assay", "urgent", 0, true
	case worker == "tidegauge" && fromState == "parked" && toState == "parked":
		return "tidegauge", "backfill", sevenDays, true
	case worker == "tidegauge" && fromState == "parked" && toState == "observed":
		return "assay", "urgent", 0, true
	default:
		return "", "", 0, false
	}
}

func knownItemOrProposalState(s string) bool {
	if pubstore.ValidState(s) {
		return true
	}
	return s == "pending_approval" || s == "declined"
}

func safeItemState(it *standinItem) string {
	if it == nil {
		return ""
	}
	return it.State
}

func copyRawMap(m map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

func formatItemID(n int) string {
	if n < 10000 {
		return fmt.Sprintf("PA-%04d", n)
	}
	return fmt.Sprintf("PA-%d", n)
}

func validUTF8NoNul(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

func plainNoControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func noSpaceOrControl(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validSlugForm(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func parseVisitorAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

// StripMarkup removes HTML comments, script/style blocks, and tag-shaped markup
// iteratively until fixed point, matching Muster Contract v1 intake rules.
func StripMarkup(s string) string {
	for {
		next := stripMarkupPass(s)
		if next == s {
			return strings.TrimSpace(next)
		}
		s = next
	}
}

func stripMarkupPass(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '<' {
			out.WriteByte(s[i])
			i++
			continue
		}
		rest := s[i:]
		if strings.HasPrefix(rest, "<!--") {
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				return out.String()
			}
			i += 4 + end + 3
			continue
		}
		if len(rest) < 2 || !isTagStarter(rest[1]) {
			out.WriteByte(s[i])
			i++
			continue
		}
		end := findTagClose(rest)
		if end < 0 {
			return out.String()
		}
		tName := extractTagName(rest)
		i += end + 1
		if rest[1] != '/' && (tName == "script" || tName == "style") {
			closeOffset := findElementClosingTag(s[i:], tName)
			if closeOffset < 0 {
				return out.String()
			}
			i += closeOffset
		}
	}
	return out.String()
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isTagStarter(b byte) bool {
	return isASCIILetter(b) || b == '/' || b == '!' || b == '?'
}

func findTagClose(s string) int {
	var quote byte
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
	}
	return -1
}

func extractTagName(s string) string {
	i := 1
	if i < len(s) && s[i] == '/' {
		i++
	}
	j := i
	for j < len(s) && (isASCIILetter(s[j]) || (s[j] >= '0' && s[j] <= '9')) {
		j++
	}
	return strings.ToLower(s[i:j])
}

func findElementClosingTag(s, tagName string) int {
	lower := strings.ToLower(s)
	needle := "</" + tagName
	pos := 0
	for {
		idx := strings.Index(lower[pos:], needle)
		if idx < 0 {
			return -1
		}
		idx += pos
		after := idx + len(needle)
		if after < len(s) && (isASCIILetter(s[after]) || (s[after] >= '0' && s[after] <= '9')) {
			pos = after
			continue
		}
		gt := strings.IndexByte(s[after:], '>')
		if gt < 0 {
			return -1
		}
		return after + gt + 1
	}
}

func writeRefusal(w http.ResponseWriter, ref *RefusalError) {
	writeJSONResp(w, ref.Status, ref.Refusal)
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	_, _ = w.Write(buf.Bytes())
}
