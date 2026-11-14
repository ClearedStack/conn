// Package web implements Conn's public HTTP portal, contractor tool catalog,
// pipeline item explorer, 17-component registry, sanitized SSE stream, and
// anonymous Proof-of-Work edit/item intake endpoints.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ClearedStack/conn/internal/feedhub"
	"github.com/ClearedStack/conn/internal/muster"
	"github.com/ClearedStack/conn/internal/ownership"
	"github.com/ClearedStack/conn/internal/pubstore"
)

// Strict security header values applied to every HTTP response.
const (
	CSPHeaderValue = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"

	sseKeepAliveInterval = 15 * time.Second
	maxSearchQueryBytes  = 200
)

//go:embed static/*
var staticFS embed.FS

// IntakeClient is satisfied by *muster.Client and test doubles.
type IntakeClient interface {
	SubmitEdit(ctx context.Context, req muster.EditRequest) (*muster.EditReceipt, error)
	SubmitItem(ctx context.Context, req muster.ItemRequest) (*muster.ItemReceipt, error)
}

// Config bundles dependencies for Server.
type Config struct {
	Store  pubstore.Reader
	Muster IntakeClient
	Hub    *feedhub.Hub
	Owners *ownership.Map
}

// Server serves Conn's HTTP routes with strict CSP and zero cookies.
type Server struct {
	store  pubstore.Reader
	muster IntakeClient
	hub    *feedhub.Hub
	owners *ownership.Map
	tmpl   *template.Template
}

// NewServer constructs a ready-to-serve Conn HTTP handler.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("web: Store is required")
	}
	if cfg.Hub == nil {
		cfg.Hub = feedhub.New(nil, feedhub.Config{})
	}
	if cfg.Owners == nil {
		m, err := ownership.Parse([]byte(muster.DefaultStandinOwnershipJSON))
		if err != nil {
			return nil, err
		}
		cfg.Owners = m
	}
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{
		store:  cfg.Store,
		muster: cfg.Muster,
		hub:    cfg.Hub,
		owners: cfg.Owners,
		tmpl:   tmpl,
	}, nil
}

// ServeHTTP sets strict security headers on every response and dispatches routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())

	path := r.URL.Path
	switch {
	case path == "/healthz":
		s.handleHealthz(w, r)
	case path == "/":
		s.handlePortal(w, r)
	case path == "/tools" || path == "/tools/":
		s.handleToolsList(w, r)
	case strings.HasPrefix(path, "/tools/"):
		s.handleToolDetail(w, r, strings.TrimPrefix(path, "/tools/"))
	case path == "/items" || path == "/items/":
		s.handleItemsList(w, r)
	case strings.HasPrefix(path, "/items/"):
		s.handleItemDetail(w, r, strings.TrimPrefix(path, "/items/"))
	case path == "/registry" || path == "/registry/":
		s.handleRegistry(w, r)
	case path == "/guides" || path == "/guides/":
		s.handleGuides(w, r)
	case path == "/v1/feed":
		s.handleFeed(w, r)
	case path == "/v1/edits":
		s.handleEdits(w, r)
	case path == "/v1/items":
		s.handleItemsIntake(w, r)
	case strings.HasPrefix(path, "/static/"):
		s.handleStatic(w, r, strings.TrimPrefix(path, "/static/"))
	default:
		if strings.HasPrefix(path, "/v1/") {
			writeContractRefusal(w, http.StatusNotFound, muster.CodeParse, "no_such_call", "no such call")
			return
		}
		s.renderNotFound(w, r, "The requested page does not exist on Conn.")
	}
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", CSPHeaderValue)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Del("Set-Cookie")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeContractRefusal(w, http.StatusMethodNotAllowed, muster.CodeParse, "wrong_method", "this call does not accept that method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var contentType string
	switch name {
	case "style.css":
		contentType = "text/css; charset=utf-8"
	case "app.js":
		contentType = "application/javascript; charset=utf-8"
	case "mark.svg":
		contentType = "image/svg+xml"
	default:
		http.NotFound(w, r)
		return
	}
	raw, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(raw)
	}
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	if !allowPageMethod(w, r) {
		return
	}

	portal, _ := s.store.PortalSnapshot(r.Context())
	feedSnap := s.hub.Snapshot()

	lanes := portal.Lanes
	if feedSnap.HasDepths {
		lanes.Urgent = feedSnap.Depths.Urgent
		lanes.Normal = feedSnap.Depths.Normal
		lanes.Backfill = feedSnap.Depths.Backfill
		lanes.NeedsSubtool = feedSnap.Depths.NeedsSubtool
	}

	components := mergeComponentViews(portal.Health, feedSnap.Health)
	alerts := buildPortalAlerts(portal, lanes, components, feedSnap)

	recent := portal.RecentItems
	if len(recent) > 10 {
		recent = recent[:10]
	}

	data := struct {
		Meta         layoutMeta
		Alerts       []AttentionAlert
		Lanes        pubstore.LaneSummary
		Components   []ComponentView
		LatestDrill  *pubstore.RestoreDrill
		RecentItems  []pubstore.Item
		CatalogCount int
	}{
		Meta: layoutMeta{
			Title:     "Command Portal",
			Nav:       "portal",
			FeedStale: feedSnap.Stale,
		},
		Alerts:       alerts,
		Lanes:        lanes,
		Components:   components,
		LatestDrill:  portal.LatestDrill,
		RecentItems:  recent,
		CatalogCount: portal.CatalogCount,
	}
	s.renderHTML(w, r, http.StatusOK, "portal", data)
}

func buildPortalAlerts(
	portal pubstore.PortalData,
	lanes pubstore.LaneSummary,
	components []ComponentView,
	feedSnap feedhub.Snapshot,
) []AttentionAlert {
	var p0, p1, p2 []AttentionAlert

	if portal.Degraded {
		code := portal.ErrorCode
		if code == "" {
			code = muster.CodeTimeout
		}
		p0 = append(p0, AttentionAlert{
			Severity: "P0",
			Code:     code,
			Summary:  "Logbook public views unreachable",
			Detail:   "Conn could not complete its read-only pub.* query within budget; rendering degraded portal view.",
		})
	}

	for _, c := range components {
		if c.State == "degraded" {
			p0 = append(p0, AttentionAlert{
				Severity: "P0",
				Code:     c.ErrorCode,
				Summary:  fmt.Sprintf("Component %s is degraded", c.Name),
				Detail:   fmt.Sprintf("Workload %s/%s reported degraded health.", c.Namespace, c.Slug),
			})
		}
	}

	if portal.LatestDrill != nil && !portal.LatestDrill.Passed {
		p0 = append(p0, AttentionAlert{
			Severity: "P0",
			Summary:  "Latest backup restore drill failed",
			Detail:   fmt.Sprintf("Restore drill at %s did not pass all subsystem checks.", portal.LatestDrill.RanAt),
		})
	}

	if feedSnap.Stale {
		p1 = append(p1, AttentionAlert{
			Severity: "P1",
			Code:     muster.CodeTimeout,
			Summary:  "Muster live SSE feed is stale (>15s)",
			Detail:   "More than 15 seconds have elapsed since the last depths tick on /v1/feed.",
		})
	}

	for _, c := range components {
		if c.State == "paused" {
			p1 = append(p1, AttentionAlert{
				Severity: "P1",
				Code:     c.ErrorCode,
				Summary:  fmt.Sprintf("Worker %s is paused", c.Name),
				Detail:   fmt.Sprintf("Workload %s/%s is paused awaiting sub-tool build or replay.", c.Namespace, c.Slug),
			})
		}
	}

	pauseCount := len(portal.OpenPauses)
	if lanes.NeedsSubtool > pauseCount {
		pauseCount = lanes.NeedsSubtool
	}
	if pauseCount > 0 {
		p1 = append(p1, AttentionAlert{
			Severity: "P1",
			Code:     muster.CodeNeedsSubtool,
			Summary:  fmt.Sprintf("%d item(s) paused in needs_subtool", pauseCount),
			Detail:   "Bellbuoy and Countersign track missing sub-tools before automatic digest replay.",
		})
	}

	waitingTotal := lanes.Urgent + lanes.Normal + lanes.Backfill
	if waitingTotal > 0 {
		p2 = append(p2, AttentionAlert{
			Severity: "P2",
			Summary:  fmt.Sprintf("%d item(s) queued across pipeline lanes", waitingTotal),
			Detail:   fmt.Sprintf("Urgent: %d | Normal: %d | Backfill: %d.", lanes.Urgent, lanes.Normal, lanes.Backfill),
		})
	}

	pendingProposals := countPendingProposals(portal.Proposals, feedSnap.Edits)
	if pendingProposals > 0 {
		p2 = append(p2, AttentionAlert{
			Severity: "P2",
			Summary:  fmt.Sprintf("%d edit proposal(s) awaiting Countersign review", pendingProposals),
			Detail:   "Anonymous proof-of-work proposals are queued in pending_approval.",
		})
	}

	out := make([]AttentionAlert, 0, len(p0)+len(p1)+len(p2))
	out = append(out, p0...)
	out = append(out, p1...)
	out = append(out, p2...)
	return out
}

func countPendingProposals(stored []pubstore.EditProposal, live map[string]muster.EditData) int {
	seen := make(map[string]string, len(stored)+len(live))
	for _, p := range stored {
		seen[p.ProposalID] = p.Status
	}
	for id, ed := range live {
		seen[id] = ed.Status
	}
	n := 0
	for _, st := range seen {
		if st == "pending_approval" {
			n++
		}
	}
	return n
}

func mergeComponentViews(
	stored map[string]pubstore.ComponentHealth,
	live map[string]muster.HealthData,
) []ComponentView {
	reg := pubstore.AllRegistryComponents()
	out := make([]ComponentView, 0, len(reg))
	for _, rc := range reg {
		cv := ComponentView{
			Slug:           rc.Slug,
			Name:           rc.Name,
			Kind:           rc.Kind,
			Stage:          rc.Stage,
			Namespace:      rc.Namespace,
			Repository:     rc.Repository,
			Responsibility: rc.Responsibility,
			State:          "idle",
		}
		if sh, ok := stored[rc.Slug]; ok && sh.State != "" {
			cv.State = sh.State
			cv.ErrorCode = sh.ErrorCode
			cv.ReportedAt = sh.ReportedAt
		}
		if lh, ok := live[rc.Slug]; ok && lh.State != "" {
			cv.State = lh.State
			cv.ErrorCode = lh.Code
			cv.ReportedAt = lh.At
		}
		out = append(out, cv)
	}
	return out
}

type filterCount struct {
	Name  string
	Count int
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request) {
	if !allowPageMethod(w, r) {
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > maxSearchQueryBytes {
		q = q[:maxSearchQueryBytes]
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !pubstore.ValidCatalogStatus(status) {
		http.Error(w, "invalid catalog status filter", http.StatusBadRequest)
		return
	}

	res, _ := s.store.ListCatalog(r.Context(), q, status)
	feedSnap := s.hub.Snapshot()

	var statuses []filterCount
	total := 0
	for _, st := range pubstore.CatalogStatuses {
		c := res.CountsByStatus[st]
		total += c
		statuses = append(statuses, filterCount{Name: st, Count: c})
	}

	data := struct {
		Meta         layoutMeta
		Query        string
		StatusFilter string
		TotalCount   int
		Statuses     []filterCount
		Result       pubstore.CatalogListResult
	}{
		Meta: layoutMeta{
			Title:     "Contractor Tool Catalog",
			Nav:       "tools",
			FeedStale: feedSnap.Stale,
		},
		Query:        q,
		StatusFilter: status,
		TotalCount:   total,
		Statuses:     statuses,
		Result:       res,
	}
	s.renderHTML(w, r, http.StatusOK, "tools_list", data)
}

func (s *Server) handleToolDetail(w http.ResponseWriter, r *http.Request, slug string) {
	if !allowPageMethod(w, r) {
		return
	}
	slug = strings.TrimSuffix(slug, "/")
	if slug == "" || strings.Contains(slug, "/") {
		s.renderNotFound(w, r, "Unknown catalog entry slug.")
		return
	}

	detail, _ := s.store.GetCatalogEntry(r.Context(), slug)
	if !detail.Found {
		if detail.Degraded {
			s.renderNotFoundStatus(w, r, http.StatusServiceUnavailable, "Catalog store temporarily unavailable ("+detail.ErrorCode+").")
			return
		}
		s.renderNotFound(w, r, "No catalog entry matches slug "+slug+".")
		return
	}

	feedSnap := s.hub.Snapshot()

	editTarget := detail.Entry.EditTarget
	if editTarget == "" {
		editTarget = "catalog." + detail.Entry.Slug + ".description"
	}
	ownerEntry, editable := s.owners.Lookup(editTarget)

	proposals := make([]pubstore.EditProposal, len(detail.Proposals))
	copy(proposals, detail.Proposals)
	for i := range proposals {
		if liveEd, ok := feedSnap.Edits[proposals[i].ProposalID]; ok {
			proposals[i].Status = liveEd.Status
		}
	}

	data := struct {
		Meta       layoutMeta
		Entry      pubstore.CatalogEntry
		EditTarget string
		Editable   bool
		OwnerEntry ownership.Entry
		Proposals  []pubstore.EditProposal
	}{
		Meta: layoutMeta{
			Title:     detail.Entry.Title,
			Nav:       "tools",
			FeedStale: feedSnap.Stale,
		},
		Entry:      detail.Entry,
		EditTarget: editTarget,
		Editable:   editable,
		OwnerEntry: ownerEntry,
		Proposals:  proposals,
	}
	s.renderHTML(w, r, http.StatusOK, "tool_detail", data)
}

func (s *Server) handleItemsList(w http.ResponseWriter, r *http.Request) {
	if !allowPageMethod(w, r) {
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state != "" && !pubstore.ValidState(state) {
		http.Error(w, "invalid item lifecycle state filter", http.StatusBadRequest)
		return
	}

	res, _ := s.store.ListItems(r.Context(), state)
	feedSnap := s.hub.Snapshot()

	states := make([]filterCount, 0, len(pubstore.AllStates))
	total := 0
	for _, st := range pubstore.AllStates {
		c := res.CountsByState[st]
		total += c
		states = append(states, filterCount{Name: st, Count: c})
	}

	data := struct {
		Meta        layoutMeta
		StateFilter string
		TotalCount  int
		States      []filterCount
		Result      pubstore.ItemListResult
	}{
		Meta: layoutMeta{
			Title:     "Pipeline Items",
			Nav:       "items",
			FeedStale: feedSnap.Stale,
		},
		StateFilter: state,
		TotalCount:  total,
		States:      states,
		Result:      res,
	}
	s.renderHTML(w, r, http.StatusOK, "items_list", data)
}

func (s *Server) handleItemDetail(w http.ResponseWriter, r *http.Request, itemID string) {
	if !allowPageMethod(w, r) {
		return
	}
	itemID = strings.TrimSuffix(itemID, "/")
	if itemID == "" || strings.Contains(itemID, "/") {
		s.renderNotFound(w, r, "Unknown pipeline item ID.")
		return
	}

	detail, _ := s.store.GetItemDetail(r.Context(), itemID)
	if !detail.Found {
		if detail.Degraded {
			s.renderNotFoundStatus(w, r, http.StatusServiceUnavailable, "Item store temporarily unavailable ("+detail.ErrorCode+").")
			return
		}
		s.renderNotFound(w, r, "No pipeline item matches ID "+itemID+".")
		return
	}

	feedSnap := s.hub.Snapshot()
	data := struct {
		Meta   layoutMeta
		Detail pubstore.ItemDetail
	}{
		Meta: layoutMeta{
			Title:     detail.Item.ItemID + " " + detail.Item.Title,
			Nav:       "items",
			FeedStale: feedSnap.Stale,
		},
		Detail: detail,
	}
	s.renderHTML(w, r, http.StatusOK, "item_detail", data)
}

func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if !allowPageMethod(w, r) {
		return
	}
	storedList, degraded, errCode := s.store.ListComponentHealth(r.Context())
	storedMap := make(map[string]pubstore.ComponentHealth, len(storedList))
	for _, h := range storedList {
		storedMap[h.Component] = h
	}
	feedSnap := s.hub.Snapshot()
	all := mergeComponentViews(storedMap, feedSnap.Health)

	var cp, workers []ComponentView
	for _, c := range all {
		if c.Kind == "control-plane" {
			cp = append(cp, c)
		} else {
			workers = append(workers, c)
		}
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Stage < workers[j].Stage })

	data := struct {
		Meta         layoutMeta
		Degraded     bool
		ErrorCode    string
		ControlPlane []ComponentView
		Workers      []ComponentView
	}{
		Meta: layoutMeta{
			Title:     "17-Component Registry",
			Nav:       "registry",
			FeedStale: feedSnap.Stale,
		},
		Degraded:     degraded,
		ErrorCode:    errCode,
		ControlPlane: cp,
		Workers:      workers,
	}
	s.renderHTML(w, r, http.StatusOK, "registry", data)
}

func (s *Server) handleGuides(w http.ResponseWriter, r *http.Request) {
	if !allowPageMethod(w, r) {
		return
	}
	feedSnap := s.hub.Snapshot()
	data := struct {
		Meta layoutMeta
	}{
		Meta: layoutMeta{
			Title:     "Operational & Governance Guides",
			Nav:       "guides",
			FeedStale: feedSnap.Stale,
		},
	}
	s.renderHTML(w, r, http.StatusOK, "guides", data)
}

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeContractRefusal(w, http.StatusMethodNotAllowed, muster.CodeParse, "wrong_method", "this call does not accept that method")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeContractRefusal(w, http.StatusInternalServerError, muster.CodeParse, "unexpected", "an unexpected condition; the request was refused")
		return
	}

	sub, err := s.hub.Subscribe()
	if err != nil {
		if errors.Is(err, feedhub.ErrTooManySubscribers) {
			writeContractRefusal(w, http.StatusServiceUnavailable, muster.CodeTimeout, "busy", "too busy; try again")
			return
		}
		writeContractRefusal(w, http.StatusInternalServerError, muster.CodeParse, "unexpected", "an unexpected condition; the request was refused")
		return
	}
	defer sub.Unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(sseKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case frame, open := <-sub.C:
			if !open {
				return
			}
			if _, werr := w.Write(frame); werr != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, werr := w.Write([]byte(": keepalive\n\n")); werr != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleEdits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeContractRefusal(w, http.StatusMethodNotAllowed, muster.CodeParse, "wrong_method", "this call does not accept that method")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeContractRefusal(w, http.StatusUnsupportedMediaType, muster.CodeParse, "wrong_type", "the content type must be application/json")
		return
	}

	raw, tooLarge, err := readBoundedBody(r.Body, muster.MaxEditBodyBytes)
	if err != nil {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "not_json", "the request is not one json value")
		return
	}
	if tooLarge {
		writeContractRefusal(w, http.StatusRequestEntityTooLarge, muster.CodeParse, "too_large", "the request is too large")
		return
	}

	var in struct {
		Contract *string `json:"contract"`
		Target   *string `json:"target"`
		Change   *string `json:"change"`
		Reason   *string `json:"reason"`
		Pow      *string `json:"pow"`
		Honeypot *string `json:"honeypot"`
	}
	if ref := decodePublicJSON(raw, &in); ref != nil {
		writeRefusalErr(w, ref)
		return
	}
	if in.Contract != nil {
		if *in.Contract == "" {
			writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "bad_field", "a field does not have the form this call requires")
			return
		}
		if *in.Contract != muster.ContractVersion {
			writeContractRefusal(w, http.StatusUnprocessableEntity, muster.CodeNeedsSubtool, "unknown_contract", "this contract version is not known")
			return
		}
	}
	if in.Target == nil || in.Change == nil || in.Pow == nil || *in.Target == "" || *in.Change == "" || *in.Pow == "" {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "missing_field", "a required field is missing")
		return
	}

	reason := ""
	if in.Reason != nil {
		reason = *in.Reason
	}
	honeypot := ""
	if in.Honeypot != nil {
		honeypot = *in.Honeypot
	}

	// Enforce ownership_map.json locally before forwarding to Muster when not a honeypot trap.
	if honeypot == "" {
		if _, ok := s.owners.Lookup(*in.Target); !ok {
			writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "bad_field", "the target is not in the ownership map")
			return
		}
	}

	if s.muster == nil {
		writeContractRefusal(w, http.StatusServiceUnavailable, muster.CodeTimeout, "busy", "too busy; try again")
		return
	}

	// Extract visitor IP from RemoteAddr strictly in local stack memory.
	// Never log, store, or echo this value.
	visitorIP, ok := extractVisitorIP(r.RemoteAddr)
	if !ok {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "bad_field", "a field does not have the form this call requires")
		return
	}

	receipt, subErr := s.muster.SubmitEdit(r.Context(), muster.EditRequest{
		Target:   *in.Target,
		Change:   *in.Change,
		Reason:   reason,
		Pow:      *in.Pow,
		Honeypot: honeypot,
		Source:   visitorIP,
	})
	if subErr != nil {
		if ref, isRef := muster.UnwrapRefusal(subErr); isRef {
			writeRefusalErr(w, ref)
			return
		}
		writeContractRefusal(w, http.StatusServiceUnavailable, muster.CodeTimeout, "busy", "too busy; try again")
		return
	}
	if receipt == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusAccepted, receipt)
}

func (s *Server) handleItemsIntake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeContractRefusal(w, http.StatusMethodNotAllowed, muster.CodeParse, "wrong_method", "this call does not accept that method")
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeContractRefusal(w, http.StatusUnsupportedMediaType, muster.CodeParse, "wrong_type", "the content type must be application/json")
		return
	}

	raw, tooLarge, err := readBoundedBody(r.Body, muster.MaxItemBodyBytes)
	if err != nil {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "not_json", "the request is not one json value")
		return
	}
	if tooLarge {
		writeContractRefusal(w, http.StatusRequestEntityTooLarge, muster.CodeParse, "too_large", "the request is too large")
		return
	}

	var in struct {
		Contract *string `json:"contract"`
		Source   *string `json:"source"`
		Title    *string `json:"title"`
		Address  *string `json:"address"`
		Pow      *string `json:"pow"`
		Honeypot *string `json:"honeypot"`
	}
	if ref := decodePublicJSON(raw, &in); ref != nil {
		writeRefusalErr(w, ref)
		return
	}
	if in.Contract != nil {
		if *in.Contract == "" {
			writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "bad_field", "a field does not have the form this call requires")
			return
		}
		if *in.Contract != muster.ContractVersion {
			writeContractRefusal(w, http.StatusUnprocessableEntity, muster.CodeNeedsSubtool, "unknown_contract", "this contract version is not known")
			return
		}
	}

	source := muster.SourceSiteForm
	if in.Source != nil && *in.Source != "" {
		source = *in.Source
	}
	if source != muster.SourceSiteForm {
		writeContractRefusal(w, http.StatusForbidden, muster.CodeParse, "not_your_call", "this caller may not make this call")
		return
	}

	if in.Title == nil || in.Address == nil || in.Pow == nil || *in.Title == "" || *in.Address == "" || *in.Pow == "" {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "missing_field", "a required field is missing")
		return
	}

	if in.Honeypot != nil && *in.Honeypot != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if s.muster == nil {
		writeContractRefusal(w, http.StatusServiceUnavailable, muster.CodeTimeout, "busy", "too busy; try again")
		return
	}

	// Extract visitor IP from RemoteAddr strictly in local stack memory.
	// Never log, store, or echo this value.
	visitorIP, ok := extractVisitorIP(r.RemoteAddr)
	if !ok {
		writeContractRefusal(w, http.StatusBadRequest, muster.CodeParse, "bad_field", "a field does not have the form this call requires")
		return
	}

	receipt, subErr := s.muster.SubmitItem(r.Context(), muster.ItemRequest{
		Source:  muster.SourceSiteForm,
		Title:   *in.Title,
		Address: *in.Address,
		Pow:     *in.Pow,
		Visitor: visitorIP,
	})
	if subErr != nil {
		if ref, isRef := muster.UnwrapRefusal(subErr); isRef {
			writeRefusalErr(w, ref)
			return
		}
		writeContractRefusal(w, http.StatusServiceUnavailable, muster.CodeTimeout, "busy", "too busy; try again")
		return
	}

	status := receipt.StatusCode
	if status != http.StatusCreated && status != http.StatusOK {
		status = http.StatusCreated
	}
	writeJSON(w, status, receipt)
}

func allowPageMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (s *Server) renderNotFound(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderNotFoundStatus(w, r, http.StatusNotFound, msg)
}

func (s *Server) renderNotFoundStatus(w http.ResponseWriter, r *http.Request, status int, msg string) {
	feedSnap := s.hub.Snapshot()
	data := struct {
		Meta    layoutMeta
		Message string
	}{
		Meta: layoutMeta{
			Title:     "Not Found",
			FeedStale: feedSnap.Stale,
		},
		Message: msg,
	}
	s.renderHTML(w, r, status, "not_found", data)
}

func (s *Server) renderHTML(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template rendering error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeContractRefusal(w http.ResponseWriter, status int, code, cause, reason string) {
	writeJSON(w, status, muster.Refusal{
		Error:  code,
		Cause:  cause,
		Reason: reason,
	})
}

func writeRefusalErr(w http.ResponseWriter, ref *muster.RefusalError) {
	writeContractRefusal(w, ref.Status, ref.Refusal.Error, ref.Cause, ref.Reason)
}

func isJSONContentType(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

func readBoundedBody(body io.ReadCloser, maxBytes int) ([]byte, bool, error) {
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
	if err != nil {
		return nil, false, err
	}
	if len(raw) > maxBytes {
		return nil, true, nil
	}
	return raw, false, nil
}

func decodePublicJSON(raw []byte, dst any) *muster.RefusalError {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return &muster.RefusalError{
			Status: http.StatusBadRequest,
			Refusal: muster.Refusal{
				Error:  muster.CodeParse,
				Cause:  "not_json",
				Reason: "the request is not one json value",
			},
		}
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return &muster.RefusalError{
				Status: http.StatusBadRequest,
				Refusal: muster.Refusal{
					Error:  muster.CodeParse,
					Cause:  "unknown_field",
					Reason: "the request has a field this call does not define",
				},
			}
		}
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return &muster.RefusalError{
				Status: http.StatusBadRequest,
				Refusal: muster.Refusal{
					Error:  muster.CodeParse,
					Cause:  "bad_field",
					Reason: "a field does not have the form this call requires",
				},
			}
		}
		return &muster.RefusalError{
			Status: http.StatusBadRequest,
			Refusal: muster.Refusal{
				Error:  muster.CodeParse,
				Cause:  "not_json",
				Reason: "the request is not one json value",
			},
		}
	}
	if dec.More() {
		return &muster.RefusalError{
			Status: http.StatusBadRequest,
			Refusal: muster.Refusal{
				Error:  muster.CodeParse,
				Cause:  "not_json",
				Reason: "the request is not one json value",
			},
		}
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return &muster.RefusalError{
			Status: http.StatusBadRequest,
			Refusal: muster.Refusal{
				Error:  muster.CodeParse,
				Cause:  "not_json",
				Reason: "the request is not one json value",
			},
		}
	}
	return nil
}

// extractVisitorIP parses the TCP peer IP from RemoteAddr strictly in memory.
func extractVisitorIP(remoteAddr string) (string, bool) {
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return "", false
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if zoneIdx := strings.IndexByte(host, '%'); zoneIdx >= 0 {
		host = host[:zoneIdx]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}
