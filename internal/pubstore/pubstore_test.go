package pubstore

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ClearedStack/conn/internal/pgwire"
)

type stubQuerier struct {
	fn func(sql string) (*pgwire.Result, error)
}

func (s stubQuerier) Query(ctx context.Context, sql string) (*pgwire.Result, error) {
	return s.fn(sql)
}

func TestMemoryStoreCoversAll14States4CatalogStatusesAnd17Components(t *testing.T) {
	ms := NewMemoryStore()
	ctx := context.Background()

	if got := len(AllRegistryComponents()); got != 17 {
		t.Fatalf("AllRegistryComponents() = %d, want 17", got)
	}

	itemsRes, err := ms.ListItems(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range AllStates {
		if itemsRes.CountsByState[st] < 1 {
			t.Errorf("MemoryStore missing seed item in state %q", st)
		}
	}

	catRes, err := ms.ListCatalog(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range CatalogStatuses {
		if catRes.CountsByStatus[cs] < 1 {
			t.Errorf("MemoryStore missing catalog entry in status %q", cs)
		}
	}

	// Search filter and status filter.
	searchRes, err := ms.ListCatalog(ctx, "CAS", "live")
	if err != nil || len(searchRes.Entries) != 1 || searchRes.Entries[0].Slug != "sample-calculator" {
		t.Fatalf("unexpected search result: %+v (%v)", searchRes, err)
	}

	// Item detail with gates, factors, decision, and history.
	det, err := ms.GetItemDetail(ctx, "PA-0001")
	if err != nil || !det.Found || len(det.Evaluations) == 0 || len(det.Decisions) == 0 || len(det.History) == 0 {
		t.Fatalf("unexpected PA-0001 detail: %+v (%v)", det, err)
	}
	if len(det.Evaluations[0].Gates) == 0 || len(det.Evaluations[0].Factors) == 0 {
		t.Fatalf("expected gates and factors on PA-0001 evaluation: %+v", det.Evaluations[0])
	}
}

func TestPGStoreAllViewsMissingCatalogViewFallbackAndTimeoutDegradation(t *testing.T) {
	ctx := context.Background()

	// 1. Simulate Logbook where 0011_pub_catalog_entry.sql has NOT yet been applied (42P01),
	// verifying every other pub.* view works and catalog falls back cleanly to pub.item.
	var seenQueries []string
	pg := NewPGStore(stubQuerier{fn: func(sql string) (*pgwire.Result, error) {
		seenQueries = append(seenQueries, sql)
		switch {
		case strings.Contains(sql, "FROM pub.catalog_entry"):
			return nil, &pgwire.Error{Code: pgwire.CodeNeedsSubtool, SQLState: pgwire.SQLStateUndefinedTable, Message: "missing view"}
		case strings.Contains(sql, "FROM pub.queue_depth"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "sextant"}, {Text: "urgent"}, {Text: "2"}, {Text: "1"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.pause"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "1"}, {Text: "PA-0007"}, {Text: "sextant"}, {Text: "pat-1"}, {Text: "2026-01-05T07:15:00Z"}, {Null: true}},
			}}, nil
		case strings.Contains(sql, "FROM pub.component_health"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "assay"}, {Text: "degraded"}, {Text: "E_TIMEOUT"}, {Text: "2026-01-05T09:00:00Z"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.restore_drill"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "5"}, {Text: "2026-01-01T00:00:00Z"}, {Text: "t"}, {Text: "t"}, {Text: "t"}, {Text: "t"}, {Text: "t"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.item_history"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "1"}, {Text: "PA-0001"}, {Text: "chartroom"}, {Text: "building"}, {Text: "live"}, {Null: true}, {Text: "published"}, {Text: "2026-01-05T08:40:00Z"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.evaluation_gate"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "10"}, {Text: "PA-0001"}, {Text: "offline"}, {Text: "t"}, {Null: true}},
			}}, nil
		case strings.Contains(sql, "FROM pub.evaluation_factor"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "10"}, {Text: "PA-0001"}, {Text: "clarity"}, {Text: "5"}, {Text: "10"}, {Text: "50"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.evaluation"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "10"}, {Text: "PA-0001"}, {Text: "prof-v1"}, {Text: "t"}, {Text: "50"}, {Text: "approve"}, {Text: "f"}, {Text: "2026-01-05T08:00:00Z"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.decision"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "20"}, {Text: "PA-0001"}, {Text: "10"}, {Text: "approve"}, {Text: "approve"}, {Text: "f"}, {Text: "ok"}, {Text: "2026-01-05T08:10:00Z"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.edit_proposal"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "1"}, {Text: "catalog.pa-0001.description"}, {Text: "conn"}, {Text: "DATA"}, {Text: "approved"}, {Text: "Approved text"}, {Text: "2026-01-05T08:00:00Z"}, {Text: "2026-01-05T08:05:00Z"}},
			}}, nil
		case strings.Contains(sql, "FROM pub.item"):
			return &pgwire.Result{Rows: [][]pgwire.Value{
				{{Text: "PA-0001"}, {Text: "live"}, {Text: "Sample Tool"}, {Text: "2026-01-05T05:00:00Z"}, {Text: "2026-01-05T08:40:00Z"}},
			}}, nil
		default:
			t.Fatalf("unexpected SQL query: %s", sql)
			return nil, nil
		}
	}})

	snap, err := pg.PortalSnapshot(ctx)
	if err != nil || snap.Degraded || !snap.CatalogFallback || snap.CatalogCount != 1 {
		t.Fatalf("unexpected PortalSnapshot on missing pub.catalog_entry: %+v (%v)", snap, err)
	}
	if snap.Lanes.Urgent != 2 || snap.Lanes.NeedsSubtool != 1 || snap.Health["assay"].ErrorCode != "E_TIMEOUT" {
		t.Fatalf("unexpected portal lanes/health: %+v", snap)
	}

	det, err := pg.GetItemDetail(ctx, "PA-0001")
	if err != nil || !det.Found || len(det.Evaluations) != 1 || len(det.Decisions) != 1 || len(det.History) != 1 {
		t.Fatalf("unexpected GetItemDetail: %+v (%v)", det, err)
	}

	// 2. Simulate completely unreachable Logbook -> degraded E_TIMEOUT without crashing.
	downPG := NewPGStore(stubQuerier{fn: func(sql string) (*pgwire.Result, error) {
		return nil, &pgwire.Error{Code: pgwire.CodeTimeout, Message: "unable to connect to database"}
	}})
	downSnap, err := downPG.PortalSnapshot(ctx)
	if err != nil || !downSnap.Degraded || downSnap.ErrorCode != pgwire.CodeTimeout {
		t.Fatalf("expected degraded E_TIMEOUT PortalSnapshot, got %+v (%v)", downSnap, err)
	}
	downCat, err := downPG.ListCatalog(ctx, "", "")
	if err != nil || !downCat.Degraded || downCat.ErrorCode != pgwire.CodeTimeout {
		t.Fatalf("expected degraded E_TIMEOUT ListCatalog, got %+v (%v)", downCat, err)
	}

	// 3. Verify PGStore source code contains ZERO references to core.* schema in SQL.
	src, err := os.ReadFile("pgstore.go")
	if err != nil {
		t.Fatal(err)
	}
	coreInSQL := regexp.MustCompile(`(?i)(FROM|JOIN)\s+core\.`)
	if coreInSQL.Match(src) {
		t.Fatal("pgstore.go must never query core.* tables or views")
	}
}
