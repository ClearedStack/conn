package pubstore

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ClearedStack/conn/internal/pgwire"
)

// Querier is satisfied by *pgwire.Pool and test doubles.
type Querier interface {
	Query(ctx context.Context, sql string) (*pgwire.Result, error)
}

// SQL statements querying ONLY Logbook's twelve pub.* security-barrier views.
// Never reference core.* tables or functions.
const (
	sqlSelectCatalogEntries = `SELECT item_id, slug, status, title, summary, repository, link, merge, provenance, retirement, published_at FROM pub.catalog_entry ORDER BY published_at DESC, slug ASC LIMIT 500`
	sqlSelectItems          = `SELECT item_id, state, title, recorded_at, changed_at FROM pub.item ORDER BY item_id DESC LIMIT 500`
	sqlSelectQueueDepth     = `SELECT worker, lane, waiting, claimed FROM pub.queue_depth ORDER BY worker ASC, lane ASC`
	sqlSelectOpenPauses     = `SELECT pause_id, item_id, worker, pattern, paused_at, replayed_at FROM pub.pause WHERE replayed_at IS NULL ORDER BY pause_id DESC LIMIT 100`
	sqlSelectComponentHlth  = `SELECT component, state, error_code, reported_at FROM pub.component_health ORDER BY component ASC`
	sqlSelectLatestDrill    = `SELECT drill_id, ran_at, passed, decrypt_passed, logbook_passed, plainforge_passed, lazarette_passed FROM pub.restore_drill ORDER BY ran_at DESC, drill_id DESC LIMIT 1`
	sqlSelectEditProposals  = `SELECT proposal_id, element_id, owner_repo, edit_class, status, payload, submitted_at, decided_at FROM pub.edit_proposal ORDER BY proposal_id DESC LIMIT 100`
)

var itemIDPattern = regexp.MustCompile(`^PA-([0-9]{4}|[1-9][0-9]{4,8})$`)
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// PGStore implements Reader over Logbook's pub.* views via pgwire.
type PGStore struct {
	db Querier
}

// NewPGStore wraps a read-only pgwire Querier.
func NewPGStore(db Querier) *PGStore {
	return &PGStore{db: db}
}

// PortalSnapshot reads the portal dashboard views and degrades cleanly on timeout.
func (s *PGStore) PortalSnapshot(ctx context.Context) (PortalData, error) {
	out := PortalData{
		Health: make(map[string]ComponentHealth),
	}

	qRes, err := s.db.Query(ctx, sqlSelectQueueDepth)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	for _, r := range qRes.Rows {
		if len(r) < 4 {
			continue
		}
		row := QueueDepthRow{
			Worker:  r[0].Text,
			Lane:    r[1].Text,
			Waiting: atoiSafe(r[2]),
			Claimed: atoiSafe(r[3]),
		}
		out.QueueRows = append(out.QueueRows, row)
		out.Lanes.Claimed += row.Claimed
		switch row.Lane {
		case "urgent":
			out.Lanes.Urgent += row.Waiting
		case "normal":
			out.Lanes.Normal += row.Waiting
		case "backfill":
			out.Lanes.Backfill += row.Waiting
		}
	}

	pRes, err := s.db.Query(ctx, sqlSelectOpenPauses)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	out.OpenPauses = parsePauses(pRes)
	out.Lanes.NeedsSubtool = len(out.OpenPauses)

	hRes, err := s.db.Query(ctx, sqlSelectComponentHlth)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	for _, h := range parseComponentHealth(hRes) {
		out.Health[h.Component] = h
	}

	dRes, err := s.db.Query(ctx, sqlSelectLatestDrill)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	if len(dRes.Rows) > 0 && len(dRes.Rows[0]) >= 7 {
		r := dRes.Rows[0]
		out.LatestDrill = &RestoreDrill{
			DrillID:          atollSafe(r[0]),
			RanAt:            r[1].Text,
			Passed:           boolSafe(r[2]),
			DecryptPassed:    boolSafe(r[3]),
			LogbookPassed:    boolSafe(r[4]),
			PlainforgePassed: boolSafe(r[5]),
			LazarettePassed:  boolSafe(r[6]),
		}
	}

	iRes, err := s.db.Query(ctx, sqlSelectItems)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	items := parseItems(iRes)
	if len(items) > 8 {
		out.RecentItems = items[:8]
	} else {
		out.RecentItems = items
	}

	epRes, err := s.db.Query(ctx, sqlSelectEditProposals)
	if err == nil {
		proposals := parseProposals(epRes)
		if len(proposals) > 10 {
			out.Proposals = proposals[:10]
		} else {
			out.Proposals = proposals
		}
	}

	catEntries, fallback, cerr := s.loadCatalogEntries(ctx, items)
	if cerr != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(cerr)
		return out, nil
	}
	out.CatalogFallback = fallback
	out.CatalogCount = len(catEntries)
	return out, nil
}

// ListCatalog queries pub.catalog_entry (or gracefully falls back to pub.item if 0011 is not yet applied).
func (s *PGStore) ListCatalog(ctx context.Context, query, status string) (CatalogListResult, error) {
	out := CatalogListResult{
		CountsByStatus: make(map[string]int, len(CatalogStatuses)),
	}
	entries, fallback, err := s.loadCatalogEntries(ctx, nil)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	out.CatalogFallback = fallback
	out.Entries, out.CountsByStatus = filterCatalogEntries(entries, query, status)
	return out, nil
}

// GetCatalogEntry fetches a single catalog entry by slug plus matching public edit proposals.
func (s *PGStore) GetCatalogEntry(ctx context.Context, slug string) (CatalogDetail, error) {
	if !slugPattern.MatchString(slug) {
		return CatalogDetail{}, nil
	}
	entries, _, err := s.loadCatalogEntries(ctx, nil)
	if err != nil {
		return CatalogDetail{Degraded: true, ErrorCode: pgwire.PublicCode(err)}, nil
	}
	var found *CatalogEntry
	for i := range entries {
		if entries[i].Slug == slug {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		return CatalogDetail{Found: false}, nil
	}

	detail := CatalogDetail{
		Found: true,
		Entry: *found,
	}
	litPrefix, lerr := pgwire.QuoteLiteral("catalog." + slug + ".%")
	if lerr == nil {
		epSQL := "SELECT proposal_id, element_id, owner_repo, edit_class, status, payload, submitted_at, decided_at FROM pub.edit_proposal WHERE element_id LIKE " + litPrefix + " ORDER BY proposal_id DESC LIMIT 25"
		if epRes, qerr := s.db.Query(ctx, epSQL); qerr == nil {
			detail.Proposals = parseProposals(epRes)
		}
	}
	return detail, nil
}

// ListItems queries pub.item and computes per-state counts across all 14 states.
func (s *PGStore) ListItems(ctx context.Context, stateFilter string) (ItemListResult, error) {
	out := ItemListResult{
		CountsByState: make(map[string]int, len(AllStates)),
	}
	res, err := s.db.Query(ctx, sqlSelectItems)
	if err != nil {
		out.Degraded = true
		out.ErrorCode = pgwire.PublicCode(err)
		return out, nil
	}
	all := parseItems(res)
	out.Items, out.CountsByState = filterItems(all, stateFilter)
	return out, nil
}

// GetItemDetail queries pub.item, pub.evaluation, pub.evaluation_gate,
// pub.evaluation_factor, pub.decision, pub.item_history, and pub.pause for itemID.
func (s *PGStore) GetItemDetail(ctx context.Context, itemID string) (ItemDetail, error) {
	if !itemIDPattern.MatchString(itemID) {
		return ItemDetail{}, nil
	}
	litID, err := pgwire.QuoteLiteral(itemID)
	if err != nil {
		return ItemDetail{}, nil
	}

	itemRes, qerr := s.db.Query(ctx, "SELECT item_id, state, title, recorded_at, changed_at FROM pub.item WHERE item_id = "+litID)
	if qerr != nil {
		return ItemDetail{Degraded: true, ErrorCode: pgwire.PublicCode(qerr)}, nil
	}
	items := parseItems(itemRes)
	if len(items) == 0 {
		return ItemDetail{Found: false}, nil
	}

	detail := ItemDetail{
		Found: true,
		Item:  items[0],
	}

	evalRes, qerr := s.db.Query(ctx, "SELECT evaluation_id, item_id, profile, gates_passed, score, recommendation, split_flag, evaluated_at FROM pub.evaluation WHERE item_id = "+litID+" ORDER BY evaluation_id DESC")
	if qerr != nil {
		detail.Degraded = true
		detail.ErrorCode = pgwire.PublicCode(qerr)
		return detail, nil
	}
	evals := parseEvaluations(evalRes)

	gateRes, qerr := s.db.Query(ctx, "SELECT evaluation_id, item_id, gate, passed, reason FROM pub.evaluation_gate WHERE item_id = "+litID+" ORDER BY evaluation_id DESC, gate ASC")
	if qerr == nil {
		attachGates(evals, parseEvaluationGates(gateRes))
	}
	factorRes, qerr := s.db.Query(ctx, "SELECT evaluation_id, item_id, factor, rating, weight, points FROM pub.evaluation_factor WHERE item_id = "+litID+" ORDER BY evaluation_id DESC, factor ASC")
	if qerr == nil {
		attachFactors(evals, parseEvaluationFactors(factorRes))
	}
	detail.Evaluations = evals

	decRes, qerr := s.db.Query(ctx, "SELECT decision_id, item_id, evaluation_id, recommendation, outcome, overridden, reason, decided_at FROM pub.decision WHERE item_id = "+litID+" ORDER BY decision_id DESC")
	if qerr == nil {
		detail.Decisions = parseDecisions(decRes)
	}

	histRes, qerr := s.db.Query(ctx, "SELECT entry_id, item_id, actor, from_state, to_state, error_code, note, recorded_at FROM pub.item_history WHERE item_id = "+litID+" ORDER BY entry_id ASC")
	if qerr == nil {
		detail.History = parseHistory(histRes)
	}

	pauseRes, qerr := s.db.Query(ctx, "SELECT pause_id, item_id, worker, pattern, paused_at, replayed_at FROM pub.pause WHERE item_id = "+litID+" ORDER BY pause_id DESC")
	if qerr == nil {
		detail.Pauses = parsePauses(pauseRes)
	}

	return detail, nil
}

// ListComponentHealth reads pub.component_health and degrades cleanly on error.
func (s *PGStore) ListComponentHealth(ctx context.Context) ([]ComponentHealth, bool, string) {
	res, err := s.db.Query(ctx, sqlSelectComponentHlth)
	if err != nil {
		return nil, true, pgwire.PublicCode(err)
	}
	return parseComponentHealth(res), false, ""
}

func (s *PGStore) loadCatalogEntries(ctx context.Context, preloadedItems []Item) ([]CatalogEntry, bool, error) {
	res, err := s.db.Query(ctx, sqlSelectCatalogEntries)
	if err == nil {
		return parseCatalogEntries(res), false, nil
	}
	if pgwire.IsUndefinedTable(err) || pgwire.IsInsufficientPrivilege(err) {
		items := preloadedItems
		if items == nil {
			iRes, ierr := s.db.Query(ctx, sqlSelectItems)
			if ierr != nil {
				return nil, true, ierr
			}
			items = parseItems(iRes)
		}
		return synthesizeCatalogFromItems(items), true, nil
	}
	return nil, false, err
}

func synthesizeCatalogFromItems(items []Item) []CatalogEntry {
	var out []CatalogEntry
	for _, it := range items {
		if !ValidCatalogStatus(it.State) {
			continue
		}
		slug := strings.ToLower(it.ItemID)
		out = append(out, CatalogEntry{
			ItemID:      it.ItemID,
			Slug:        slug,
			Status:      it.State,
			Title:       it.Title,
			Summary:     "Published pipeline item listed from pub.item while pub.catalog_entry is unavailable.",
			Repository:  "conn",
			PublishedAt: coalesceText(it.ChangedAt, it.RecordedAt),
			EditTarget:  "catalog." + slug + ".description",
			Provenance: Provenance{
				Credit:        "ClearedStack clean-room pipeline",
				License:       "MIT",
				CleanRoomNote: "Built solely from Waybill specifications with zero raw capture transfer.",
				OptOutSLA:     "Reviewed within 2 business days via anonymous Edit intake.",
			},
		})
	}
	return out
}

func parseCatalogEntries(res *pgwire.Result) []CatalogEntry {
	out := make([]CatalogEntry, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 11 {
			continue
		}
		slug := r[1].Text
		e := CatalogEntry{
			ItemID:      r[0].Text,
			Slug:        slug,
			Status:      r[2].Text,
			Title:       r[3].Text,
			Summary:     r[4].Text,
			Repository:  r[5].Text,
			PublishedAt: r[10].Text,
			EditTarget:  "catalog." + slug + ".description",
		}
		if !r[6].Null && strings.TrimSpace(r[6].Text) != "" {
			var link CatalogLink
			if json.Unmarshal([]byte(r[6].Text), &link) == nil && link.URL != "" {
				e.Link = &link
			}
		}
		if !r[7].Null && strings.TrimSpace(r[7].Text) != "" {
			var m CatalogMerge
			if json.Unmarshal([]byte(r[7].Text), &m) == nil && m.IntoSlug != "" {
				e.Merge = &m
			}
		}
		if !r[8].Null && strings.TrimSpace(r[8].Text) != "" {
			_ = json.Unmarshal([]byte(r[8].Text), &e.Provenance)
		}
		if !r[9].Null && strings.TrimSpace(r[9].Text) != "" {
			var ret CatalogRetirement
			if json.Unmarshal([]byte(r[9].Text), &ret) == nil && ret.Reason != "" {
				e.Retirement = &ret
			}
		}
		out = append(out, e)
	}
	return out
}

func parseItems(res *pgwire.Result) []Item {
	out := make([]Item, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 5 {
			continue
		}
		out = append(out, Item{
			ItemID:     r[0].Text,
			State:      r[1].Text,
			Title:      r[2].Text,
			RecordedAt: r[3].Text,
			ChangedAt:  r[4].Text,
		})
	}
	return out
}

func parsePauses(res *pgwire.Result) []Pause {
	out := make([]Pause, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 6 {
			continue
		}
		out = append(out, Pause{
			PauseID:    atollSafe(r[0]),
			ItemID:     r[1].Text,
			Worker:     r[2].Text,
			Pattern:    r[3].Text,
			PausedAt:   r[4].Text,
			ReplayedAt: r[5].Text,
		})
	}
	return out
}

func parseComponentHealth(res *pgwire.Result) []ComponentHealth {
	out := make([]ComponentHealth, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 4 {
			continue
		}
		out = append(out, ComponentHealth{
			Component:  r[0].Text,
			State:      r[1].Text,
			ErrorCode:  r[2].Text,
			ReportedAt: r[3].Text,
		})
	}
	return out
}

func parseProposals(res *pgwire.Result) []EditProposal {
	out := make([]EditProposal, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 8 {
			continue
		}
		rawID := atollSafe(r[0])
		out = append(out, EditProposal{
			ProposalID:  FormatProposalID(rawID),
			RawID:       rawID,
			ElementID:   r[1].Text,
			OwnerRepo:   r[2].Text,
			EditClass:   r[3].Text,
			Status:      r[4].Text,
			Payload:     r[5].Text,
			SubmittedAt: r[6].Text,
			DecidedAt:   r[7].Text,
		})
	}
	return out
}

func parseEvaluations(res *pgwire.Result) []Evaluation {
	out := make([]Evaluation, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 8 {
			continue
		}
		var scorePtr *int
		if !r[4].Null && r[4].Text != "" {
			v := atoiSafe(r[4])
			scorePtr = &v
		}
		out = append(out, Evaluation{
			EvaluationID:   atollSafe(r[0]),
			ItemID:         r[1].Text,
			Profile:        r[2].Text,
			GatesPassed:    boolSafe(r[3]),
			Score:          scorePtr,
			Recommendation: r[5].Text,
			SplitFlag:      boolSafe(r[6]),
			EvaluatedAt:    r[7].Text,
		})
	}
	return out
}

func parseEvaluationGates(res *pgwire.Result) []EvaluationGate {
	out := make([]EvaluationGate, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 5 {
			continue
		}
		out = append(out, EvaluationGate{
			EvaluationID: atollSafe(r[0]),
			ItemID:       r[1].Text,
			Gate:         r[2].Text,
			Passed:       boolSafe(r[3]),
			Reason:       r[4].Text,
		})
	}
	return out
}

func parseEvaluationFactors(res *pgwire.Result) []EvaluationFactor {
	out := make([]EvaluationFactor, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 6 {
			continue
		}
		out = append(out, EvaluationFactor{
			EvaluationID: atollSafe(r[0]),
			ItemID:       r[1].Text,
			Factor:       r[2].Text,
			Rating:       atoiSafe(r[3]),
			Weight:       atoiSafe(r[4]),
			Points:       atoiSafe(r[5]),
		})
	}
	return out
}

func attachGates(evals []Evaluation, gates []EvaluationGate) {
	byEval := make(map[int64][]EvaluationGate)
	for _, g := range gates {
		byEval[g.EvaluationID] = append(byEval[g.EvaluationID], g)
	}
	for i := range evals {
		evals[i].Gates = byEval[evals[i].EvaluationID]
	}
}

func attachFactors(evals []Evaluation, factors []EvaluationFactor) {
	byEval := make(map[int64][]EvaluationFactor)
	for _, f := range factors {
		byEval[f.EvaluationID] = append(byEval[f.EvaluationID], f)
	}
	for i := range evals {
		evals[i].Factors = byEval[evals[i].EvaluationID]
	}
}

func parseDecisions(res *pgwire.Result) []Decision {
	out := make([]Decision, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 8 {
			continue
		}
		out = append(out, Decision{
			DecisionID:     atollSafe(r[0]),
			ItemID:         r[1].Text,
			EvaluationID:   atollSafe(r[2]),
			Recommendation: r[3].Text,
			Outcome:        r[4].Text,
			Overridden:     boolSafe(r[5]),
			Reason:         r[6].Text,
			DecidedAt:      r[7].Text,
		})
	}
	return out
}

func parseHistory(res *pgwire.Result) []HistoryEntry {
	out := make([]HistoryEntry, 0, len(res.Rows))
	for _, r := range res.Rows {
		if len(r) < 8 {
			continue
		}
		out = append(out, HistoryEntry{
			EntryID:    atollSafe(r[0]),
			ItemID:     r[1].Text,
			Actor:      r[2].Text,
			FromState:  r[3].Text,
			ToState:    r[4].Text,
			ErrorCode:  r[5].Text,
			Note:       r[6].Text,
			RecordedAt: r[7].Text,
		})
	}
	return out
}

// FormatProposalID formats a numeric proposal_id per Contract v1 (EP-0001..EP-999999999).
func FormatProposalID(id int64) string {
	if id < 10000 {
		return fmt.Sprintf("EP-%04d", id)
	}
	return fmt.Sprintf("EP-%d", id)
}

func filterCatalogEntries(entries []CatalogEntry, query, status string) ([]CatalogEntry, map[string]int) {
	counts := make(map[string]int, len(CatalogStatuses))
	q := strings.ToLower(strings.TrimSpace(query))
	st := strings.ToLower(strings.TrimSpace(status))

	var filtered []CatalogEntry
	for _, e := range entries {
		if q != "" && !catalogMatchesQuery(e, q) {
			continue
		}
		counts[e.Status]++
		if st != "" && e.Status != st {
			continue
		}
		filtered = append(filtered, e)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].PublishedAt != filtered[j].PublishedAt {
			return filtered[i].PublishedAt > filtered[j].PublishedAt
		}
		return filtered[i].Slug < filtered[j].Slug
	})
	return filtered, counts
}

func catalogMatchesQuery(e CatalogEntry, q string) bool {
	if strings.Contains(strings.ToLower(e.Title), q) ||
		strings.Contains(strings.ToLower(e.Slug), q) ||
		strings.Contains(strings.ToLower(e.Summary), q) ||
		strings.Contains(strings.ToLower(e.ItemID), q) {
		return true
	}
	for _, c := range e.Provenance.Citations {
		if strings.Contains(strings.ToLower(c.Authority), q) ||
			strings.Contains(strings.ToLower(c.Section), q) ||
			strings.Contains(strings.ToLower(c.Title), q) {
			return true
		}
	}
	return false
}

func filterItems(all []Item, stateFilter string) ([]Item, map[string]int) {
	counts := make(map[string]int, len(AllStates))
	st := strings.ToLower(strings.TrimSpace(stateFilter))
	var out []Item
	for _, it := range all {
		counts[it.State]++
		if st != "" && it.State != st {
			continue
		}
		out = append(out, it)
	}
	return out, counts
}

func atoiSafe(v pgwire.Value) int {
	if v.Null || v.Text == "" {
		return 0
	}
	n, _ := strconv.Atoi(v.Text)
	return n
}

func atollSafe(v pgwire.Value) int64 {
	if v.Null || v.Text == "" {
		return 0
	}
	n, _ := strconv.ParseInt(v.Text, 10, 64)
	return n
}

func boolSafe(v pgwire.Value) bool {
	if v.Null {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v.Text)) {
	case "t", "true", "1", "yes":
		return true
	default:
		return false
	}
}

func coalesceText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
