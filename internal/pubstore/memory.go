package pubstore

import (
	"context"
	"sync"
)

// MemoryStore is a deterministic in-memory Reader populated with synthetic
// made-up data for "-standalone" mode and unit tests.
type MemoryStore struct {
	mu          sync.RWMutex
	catalog     []CatalogEntry
	items       []Item
	evaluations map[string][]Evaluation
	decisions   map[string][]Decision
	history     map[string][]HistoryEntry
	pauses      []Pause
	queueRows   []QueueDepthRow
	proposals   []EditProposal
	latestDrill *RestoreDrill
	health      map[string]ComponentHealth
}

// NewMemoryStore constructs a deterministic MemoryStore covering all 4 catalog
// statuses, all 14 item states, evaluations, decisions, history, pauses,
// restore drill checks, and all 17 ClearedStack components.
func NewMemoryStore() *MemoryStore {
	score88 := 88
	score92 := 92
	score41 := 41

	catalog := []CatalogEntry{
		{
			ItemID:      "PA-0001",
			Slug:        "sample-calculator",
			Status:      "live",
			Title:       "Sample Indirect Rate Worksheet Calculator",
			Summary:     "Deterministic worksheet computing synthetic fringe, overhead, and G&A rate pools from made-up example inputs with full step-by-step trace.",
			Repository:  "conn",
			PublishedAt: "2026-01-05T08:40:00Z",
			EditTarget:  "catalog.sample-calculator.description",
			Provenance: Provenance{
				Credit:        "Clean-room specification compiled by Waybill from synthetic rule notes.",
				License:       "MIT",
				CleanRoomNote: "Generated strictly from Waybill structured specification; zero external page markup passed to Moldloft.",
				OptOutSLA:     "Attribution updates or opt-out requests submitted via inline Edit are reviewed within 2 business days.",
				Citations: []Citation{
					{Authority: "Synthetic FAR", Section: "31.203", Title: "Indirect costs allocation example"},
					{Authority: "Synthetic CAS", Section: "410-40", Title: "Allocation of business unit G&A expenses"},
				},
			},
		},
		{
			ItemID:      "PA-0002",
			Slug:        "sample-clause-matrix",
			Status:      "live",
			Title:       "Sample Solicitation Clause Applicability Matrix",
			Summary:     "Filterable offline reference matrix cross-walking synthetic contract types and thresholds against made-up clause triggers.",
			Repository:  "conn",
			PublishedAt: "2026-01-05T08:30:00Z",
			EditTarget:  "catalog.sample-clause-matrix.description",
			Provenance: Provenance{
				Credit:        "Clean-room build verified by Shakedown and listed by Chartroom.",
				License:       "MIT",
				CleanRoomNote: "Deterministic table rules verified against synthetic test fixtures.",
				OptOutSLA:     "Attribution updates or opt-out requests submitted via inline Edit are reviewed within 2 business days.",
				Citations: []Citation{
					{Authority: "Synthetic FAR", Section: "52.301", Title: "Solicitation provisions and contract clauses matrix"},
				},
			},
		},
		{
			ItemID:      "PA-0003",
			Slug:        "sample-scoping-handbook",
			Status:      "linked",
			Title:       "Sample Boundary Scoping Reference",
			Summary:     "Linked external public guide maintained by a synthetic standards body; listed as a direct link rather than duplicated.",
			Repository:  "conn",
			PublishedAt: "2026-01-04T16:15:00Z",
			EditTarget:  "catalog.sample-scoping-handbook.description",
			Link: &CatalogLink{
				URL:       "https://example.org/made-up/scoping-handbook",
				Label:     "Open Synthetic Standards Portal",
				Publisher: "Example Public Standards Group",
			},
			Provenance: Provenance{
				Credit:        "Credited directly to Example Public Standards Group via linked listing.",
				License:       "Public Domain Reference",
				CleanRoomNote: "Countersign chose linked outcome so readers go straight to the authoritative maintainer.",
				OptOutSLA:     "Link removal or update requests via inline Edit are processed within 2 business days.",
				Citations: []Citation{
					{Authority: "Synthetic Publication", Section: "SP-800-EX", Title: "Sample System Boundary Guide"},
				},
			},
		},
		{
			ItemID:      "PA-0004",
			Slug:        "sample-pool-estimator",
			Status:      "merged",
			Title:       "Sample Overhead Pool Estimator",
			Summary:     "Folded into the unified Sample Indirect Rate Worksheet Calculator so contractors use one maintained worksheet.",
			Repository:  "conn",
			PublishedAt: "2026-01-03T14:00:00Z",
			EditTarget:  "catalog.sample-pool-estimator.description",
			Merge: &CatalogMerge{
				IntoSlug:  "sample-calculator",
				IntoTitle: "Sample Indirect Rate Worksheet Calculator",
				Note:      "Combined fringe and overhead pool checks into sample-calculator.",
			},
			Provenance: Provenance{
				Credit:        "Merged by Chartroom following Countersign consolidation decision.",
				License:       "MIT",
				CleanRoomNote: "No external third-party code used.",
				OptOutSLA:     "Reviewed within 2 business days via inline Edit.",
				Citations: []Citation{
					{Authority: "Synthetic FAR", Section: "31.201-4", Title: "Determining allocability"},
				},
			},
		},
		{
			ItemID:      "PA-0005",
			Slug:        "sample-repealed-notice-helper",
			Status:      "retired",
			Title:       "Sample Repealed Reporting Checklist",
			Summary:     "Retired after Tidegauge detected that the underlying synthetic reporting rule was repealed.",
			Repository:  "conn",
			PublishedAt: "2025-12-20T10:00:00Z",
			EditTarget:  "catalog.sample-repealed-notice-helper.description",
			Retirement: &CatalogRetirement{
				Reason:     "Underlying synthetic rule was repealed during scheduled seven-day Tidegauge check.",
				ReplacedBy: "sample-clause-matrix",
				RetiredAt:  "2026-01-02T09:00:00Z",
			},
			Provenance: Provenance{
				Credit:        "Archived in catalog for audit trail transparency.",
				License:       "MIT",
				CleanRoomNote: "Retained read-only retirement notice.",
				OptOutSLA:     "Reviewed within 2 business days via inline Edit.",
				Citations: []Citation{
					{Authority: "Synthetic Register", Section: "Vol. 91 No. 2", Title: "Repeal of sample interim reporting rule"},
				},
			},
		},
	}

	items := []Item{
		{ItemID: "PA-0014", State: "discovered", Title: "Sample Subcontract Flowdown Checklist", RecordedAt: "2026-01-05T08:55:00Z", ChangedAt: "2026-01-05T08:55:00Z"},
		{ItemID: "PA-0013", State: "recorded", Title: "Sample Small Business Size Standard Lookup", RecordedAt: "2026-01-05T08:50:00Z", ChangedAt: "2026-01-05T08:51:00Z"},
		{ItemID: "PA-0012", State: "observed", Title: "Sample Labor Category Mapping Worksheet", RecordedAt: "2026-01-05T08:42:00Z", ChangedAt: "2026-01-05T08:45:00Z"},
		{ItemID: "PA-0011", State: "screened_out", Title: "Sample Proprietary Cloud Connector", RecordedAt: "2026-01-05T08:20:00Z", ChangedAt: "2026-01-05T08:25:00Z"},
		{ItemID: "PA-0010", State: "scored", Title: "Sample Deliverable Schedule Date Checker", RecordedAt: "2026-01-05T08:10:00Z", ChangedAt: "2026-01-05T08:18:00Z"},
		{ItemID: "PA-0009", State: "approved", Title: "Sample Security Control Traceability Table", RecordedAt: "2026-01-05T07:50:00Z", ChangedAt: "2026-01-05T08:05:00Z"},
		{ItemID: "PA-0008", State: "building", Title: "Sample Travel Per Diem Cap Validator", RecordedAt: "2026-01-05T07:30:00Z", ChangedAt: "2026-01-05T08:00:00Z"},
		{ItemID: "PA-0007", State: "needs_subtool", Title: "Sample Archive Tariff Bulletin Parser", RecordedAt: "2026-01-05T07:10:00Z", ChangedAt: "2026-01-05T07:15:00Z"},
		{ItemID: "PA-0006", State: "parked", Title: "Sample Multi-Year Escalation Scratchpad", RecordedAt: "2026-01-04T19:00:00Z", ChangedAt: "2026-01-04T19:40:00Z"},
		{ItemID: "PA-0005", State: "retired", Title: "Sample Repealed Reporting Checklist", RecordedAt: "2025-12-18T11:00:00Z", ChangedAt: "2026-01-02T09:00:00Z"},
		{ItemID: "PA-0004", State: "merged", Title: "Sample Overhead Pool Estimator", RecordedAt: "2026-01-03T12:00:00Z", ChangedAt: "2026-01-03T14:00:00Z"},
		{ItemID: "PA-0003", State: "linked", Title: "Sample Boundary Scoping Reference", RecordedAt: "2026-01-04T15:00:00Z", ChangedAt: "2026-01-04T16:15:00Z"},
		{ItemID: "PA-0002", State: "live", Title: "Sample Solicitation Clause Applicability Matrix", RecordedAt: "2026-01-05T06:00:00Z", ChangedAt: "2026-01-05T08:30:00Z"},
		{ItemID: "PA-0001", State: "live", Title: "Sample Indirect Rate Worksheet Calculator", RecordedAt: "2026-01-05T05:30:00Z", ChangedAt: "2026-01-05T08:40:00Z"},
		{ItemID: "PA-0015", State: "rejected", Title: "Sample Out-of-Scope Consumer Coupon Finder", RecordedAt: "2026-01-04T10:00:00Z", ChangedAt: "2026-01-04T10:05:00Z"},
	}

	evaluations := map[string][]Evaluation{
		"PA-0001": {
			{
				EvaluationID:   101,
				ItemID:         "PA-0001",
				Profile:        "contractor-utility-v1",
				GatesPassed:    true,
				Score:          &score92,
				Recommendation: "approve",
				SplitFlag:      false,
				EvaluatedAt:    "2026-01-05T06:10:00Z",
				Gates: []EvaluationGate{
					{EvaluationID: 101, ItemID: "PA-0001", Gate: "clean-room-feasible", Passed: true},
					{EvaluationID: 101, ItemID: "PA-0001", Gate: "offline-deterministic", Passed: true},
					{EvaluationID: 101, ItemID: "PA-0001", Gate: "public-rule-grounded", Passed: true},
				},
				Factors: []EvaluationFactor{
					{EvaluationID: 101, ItemID: "PA-0001", Factor: "contractor-time-saved", Rating: 5, Weight: 8, Points: 40},
					{EvaluationID: 101, ItemID: "PA-0001", Factor: "rule-clarity", Rating: 5, Weight: 6, Points: 30},
					{EvaluationID: 101, ItemID: "PA-0001", Factor: "maintenance-simplicity", Rating: 4, Weight: 5, Points: 20},
					{EvaluationID: 101, ItemID: "PA-0001", Factor: "standalone-fit", Rating: 2, Weight: 1, Points: 2},
				},
			},
		},
		"PA-0010": {
			{
				EvaluationID:   102,
				ItemID:         "PA-0010",
				Profile:        "contractor-utility-v1",
				GatesPassed:    true,
				Score:          &score88,
				Recommendation: "approve",
				SplitFlag:      true,
				EvaluatedAt:    "2026-01-05T08:18:00Z",
				Gates: []EvaluationGate{
					{EvaluationID: 102, ItemID: "PA-0010", Gate: "clean-room-feasible", Passed: true},
					{EvaluationID: 102, ItemID: "PA-0010", Gate: "offline-deterministic", Passed: true},
				},
				Factors: []EvaluationFactor{
					{EvaluationID: 102, ItemID: "PA-0010", Factor: "contractor-time-saved", Rating: 4, Weight: 12, Points: 48},
					{EvaluationID: 102, ItemID: "PA-0010", Factor: "rule-clarity", Rating: 5, Weight: 8, Points: 40},
				},
			},
		},
		"PA-0011": {
			{
				EvaluationID: 103,
				ItemID:       "PA-0011",
				Profile:      "contractor-utility-v1",
				GatesPassed:  false,
				EvaluatedAt:  "2026-01-05T08:25:00Z",
				Gates: []EvaluationGate{
					{EvaluationID: 103, ItemID: "PA-0011", Gate: "clean-room-feasible", Passed: true},
					{EvaluationID: 103, ItemID: "PA-0011", Gate: "offline-deterministic", Passed: false, Reason: "Requires live external vendor SaaS credentials at runtime."},
				},
			},
		},
		"PA-0006": {
			{
				EvaluationID:   104,
				ItemID:         "PA-0006",
				Profile:        "contractor-utility-v1",
				GatesPassed:    true,
				Score:          &score41,
				Recommendation: "approve",
				SplitFlag:      false,
				EvaluatedAt:    "2026-01-04T19:20:00Z",
				Gates: []EvaluationGate{
					{EvaluationID: 104, ItemID: "PA-0006", Gate: "offline-deterministic", Passed: true},
				},
				Factors: []EvaluationFactor{
					{EvaluationID: 104, ItemID: "PA-0006", Factor: "contractor-time-saved", Rating: 3, Weight: 7, Points: 21},
					{EvaluationID: 104, ItemID: "PA-0006", Factor: "rule-clarity", Rating: 4, Weight: 5, Points: 20},
				},
			},
		},
	}

	decisions := map[string][]Decision{
		"PA-0001": {
			{
				DecisionID:     501,
				ItemID:         "PA-0001",
				EvaluationID:   101,
				Recommendation: "approve",
				Outcome:        "approve",
				Overridden:     false,
				Reason:         "Clear offline utility for small contractor rate checks.",
				DecidedAt:      "2026-01-05T06:20:00Z",
			},
		},
		"PA-0006": {
			{
				DecisionID:     502,
				ItemID:         "PA-0006",
				EvaluationID:   104,
				Recommendation: "approve",
				Outcome:        "park",
				Overridden:     true,
				Reason:         "Defer until synthetic escalation index table format stabilizes next quarter.",
				DecidedAt:      "2026-01-04T19:40:00Z",
			},
		},
	}

	history := map[string][]HistoryEntry{
		"PA-0001": {
			{EntryID: 1, ItemID: "PA-0001", Actor: "trawl", FromState: "", ToState: "discovered", Note: "recorded candidate", RecordedAt: "2026-01-05T05:30:00Z"},
			{EntryID: 2, ItemID: "PA-0001", Actor: "trawl", FromState: "discovered", ToState: "recorded", RecordedAt: "2026-01-05T05:35:00Z"},
			{EntryID: 3, ItemID: "PA-0001", Actor: "sextant", FromState: "recorded", ToState: "observed", RecordedAt: "2026-01-05T05:50:00Z"},
			{EntryID: 4, ItemID: "PA-0001", Actor: "assay", FromState: "observed", ToState: "scored", RecordedAt: "2026-01-05T06:10:00Z"},
			{EntryID: 5, ItemID: "PA-0001", Actor: "countersign", FromState: "scored", ToState: "approved", RecordedAt: "2026-01-05T06:20:00Z"},
			{EntryID: 6, ItemID: "PA-0001", Actor: "moldloft", FromState: "approved", ToState: "building", RecordedAt: "2026-01-05T07:10:00Z"},
			{EntryID: 7, ItemID: "PA-0001", Actor: "chartroom", FromState: "building", ToState: "live", RecordedAt: "2026-01-05T08:40:00Z"},
		},
		"PA-0007": {
			{EntryID: 20, ItemID: "PA-0007", Actor: "trawl", FromState: "", ToState: "discovered", RecordedAt: "2026-01-05T07:10:00Z"},
			{EntryID: 21, ItemID: "PA-0007", Actor: "trawl", FromState: "discovered", ToState: "recorded", RecordedAt: "2026-01-05T07:12:00Z"},
			{EntryID: 22, ItemID: "PA-0007", Actor: "sextant", FromState: "recorded", ToState: "needs_subtool", ErrorCode: "E_NEEDS_SUBTOOL", Note: "paused for unfamiliar bulletin table", RecordedAt: "2026-01-05T07:15:00Z"},
		},
	}

	pauses := []Pause{
		{
			PauseID:  1,
			ItemID:   "PA-0007",
			Worker:   "sextant",
			Pattern:  "archive-bulletin-v2",
			PausedAt: "2026-01-05T07:15:00Z",
		},
	}

	queueRows := []QueueDepthRow{
		{Worker: "trawl", Lane: "normal", Waiting: 1, Claimed: 0},
		{Worker: "sextant", Lane: "normal", Waiting: 1, Claimed: 0},
		{Worker: "assay", Lane: "normal", Waiting: 1, Claimed: 1},
		{Worker: "countersign", Lane: "urgent", Waiting: 1, Claimed: 0},
		{Worker: "tidegauge", Lane: "backfill", Waiting: 2, Claimed: 0},
	}

	proposals := []EditProposal{
		{
			ProposalID:  "EP-0001",
			RawID:       1,
			ElementID:   "catalog.sample-calculator.description",
			OwnerRepo:   "conn",
			EditClass:   "DATA",
			Status:      "live",
			Payload:     "Clarify that synthetic CAS 410-40 pool example excludes unallowable entertainment costs.",
			SubmittedAt: "2026-01-04T12:00:00Z",
			DecidedAt:   "2026-01-04T12:30:00Z",
		},
		{
			ProposalID:  "EP-0002",
			RawID:       2,
			ElementID:   "catalog.sample-clause-matrix.description",
			OwnerRepo:   "conn",
			EditClass:   "DATA",
			Status:      "pending_approval",
			Payload:     "", // Never shown publicly while pending_approval!
			SubmittedAt: "2026-01-05T08:45:00Z",
		},
	}

	drill := &RestoreDrill{
		DrillID:          12,
		RanAt:            "2026-01-01T04:00:00Z",
		Passed:           true,
		DecryptPassed:    true,
		LogbookPassed:    true,
		PlainforgePassed: true,
		LazarettePassed:  true,
	}

	health := make(map[string]ComponentHealth, len(canonicalRegistry))
	for _, rc := range canonicalRegistry {
		state := "healthy"
		if rc.Kind == "worker" && (rc.Slug == "moldloft" || rc.Slug == "shakedown" || rc.Slug == "tidegauge") {
			state = "idle"
		}
		health[rc.Slug] = ComponentHealth{
			Component:  rc.Slug,
			State:      state,
			ReportedAt: "2026-01-05T09:00:00Z",
		}
	}

	return &MemoryStore{
		catalog:     catalog,
		items:       items,
		evaluations: evaluations,
		decisions:   decisions,
		history:     history,
		pauses:      pauses,
		queueRows:   queueRows,
		proposals:   proposals,
		latestDrill: drill,
		health:      health,
	}
}

// SetComponentHealth updates one component's synthetic health state (used in tests).
func (m *MemoryStore) SetComponentHealth(slug, state, code, reportedAt string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health[slug] = ComponentHealth{
		Component:  slug,
		State:      state,
		ErrorCode:  code,
		ReportedAt: reportedAt,
	}
}

// SetRestoreDrill replaces the latest synthetic restore drill (used in tests).
func (m *MemoryStore) SetRestoreDrill(d *RestoreDrill) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latestDrill = d
}

// PortalSnapshot returns a consistent copy of the standalone portal state.
func (m *MemoryStore) PortalSnapshot(ctx context.Context) (PortalData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lanes LaneSummary
	qCopy := make([]QueueDepthRow, len(m.queueRows))
	copy(qCopy, m.queueRows)
	for _, r := range qCopy {
		lanes.Claimed += r.Claimed
		switch r.Lane {
		case "urgent":
			lanes.Urgent += r.Waiting
		case "normal":
			lanes.Normal += r.Waiting
		case "backfill":
			lanes.Backfill += r.Waiting
		}
	}

	var openPauses []Pause
	for _, p := range m.pauses {
		if p.ReplayedAt == "" {
			openPauses = append(openPauses, p)
		}
	}
	lanes.NeedsSubtool = len(openPauses)

	hCopy := make(map[string]ComponentHealth, len(m.health))
	for k, v := range m.health {
		hCopy[k] = v
	}

	var drillCopy *RestoreDrill
	if m.latestDrill != nil {
		d := *m.latestDrill
		drillCopy = &d
	}

	limit := len(m.items)
	if limit > 8 {
		limit = 8
	}
	recent := make([]Item, limit)
	copy(recent, m.items[:limit])

	propCopy := make([]EditProposal, len(m.proposals))
	copy(propCopy, m.proposals)

	return PortalData{
		Lanes:        lanes,
		QueueRows:    qCopy,
		OpenPauses:   openPauses,
		Health:       hCopy,
		LatestDrill:  drillCopy,
		RecentItems:  recent,
		Proposals:    propCopy,
		CatalogCount: len(m.catalog),
	}, nil
}

// ListCatalog filters standalone catalog entries by search query and status.
func (m *MemoryStore) ListCatalog(ctx context.Context, query, status string) (CatalogListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries, counts := filterCatalogEntries(m.catalog, query, status)
	return CatalogListResult{
		Entries:        entries,
		CountsByStatus: counts,
	}, nil
}

// GetCatalogEntry returns one catalog entry by slug.
func (m *MemoryStore) GetCatalogEntry(ctx context.Context, slug string) (CatalogDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, e := range m.catalog {
		if e.Slug == slug {
			var props []EditProposal
			prefix := "catalog." + slug + "."
			for _, p := range m.proposals {
				if len(p.ElementID) >= len(prefix) && p.ElementID[:len(prefix)] == prefix {
					props = append(props, p)
				}
			}
			return CatalogDetail{
				Found:     true,
				Entry:     e,
				Proposals: props,
			}, nil
		}
	}
	return CatalogDetail{Found: false}, nil
}

// ListItems filters standalone pipeline items across all 14 Contract v1 states.
func (m *MemoryStore) ListItems(ctx context.Context, stateFilter string) (ItemListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items, counts := filterItems(m.items, stateFilter)
	return ItemListResult{
		Items:         items,
		CountsByState: counts,
	}, nil
}

// GetItemDetail returns full public evaluation, decision, history, and pause records for itemID.
func (m *MemoryStore) GetItemDetail(ctx context.Context, itemID string) (ItemDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, it := range m.items {
		if it.ItemID == itemID {
			evals := append([]Evaluation(nil), m.evaluations[itemID]...)
			decs := append([]Decision(nil), m.decisions[itemID]...)
			hist := append([]HistoryEntry(nil), m.history[itemID]...)
			var itemPauses []Pause
			for _, p := range m.pauses {
				if p.ItemID == itemID {
					itemPauses = append(itemPauses, p)
				}
			}
			return ItemDetail{
				Found:       true,
				Item:        it,
				Evaluations: evals,
				Decisions:   decs,
				History:     hist,
				Pauses:      itemPauses,
			}, nil
		}
	}
	return ItemDetail{Found: false}, nil
}

// ListComponentHealth returns sorted health states for all known components.
func (m *MemoryStore) ListComponentHealth(ctx context.Context) ([]ComponentHealth, bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]ComponentHealth, 0, len(m.health))
	for _, rc := range canonicalRegistry {
		if h, ok := m.health[rc.Slug]; ok {
			out = append(out, h)
		}
	}
	return out, false, ""
}
