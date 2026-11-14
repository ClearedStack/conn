// Package pubstore defines the read-only data model and Reader interface over
// Logbook's twelve public security-barrier views (pub.*).
package pubstore

import "context"

// AllStates lists the 14 item lifecycle states in Muster Contract v1 order.
var AllStates = []string{
	"discovered",
	"recorded",
	"observed",
	"screened_out",
	"scored",
	"approved",
	"building",
	"live",
	"parked",
	"linked",
	"merged",
	"needs_subtool",
	"rejected",
	"retired",
}

// CatalogStatuses lists the four statuses shown in the public tool catalog.
var CatalogStatuses = []string{
	"live",
	"linked",
	"merged",
	"retired",
}

// ValidState reports whether state is one of the 14 Contract v1 item states.
func ValidState(state string) bool {
	for _, s := range AllStates {
		if s == state {
			return true
		}
	}
	return false
}

// ValidCatalogStatus reports whether status is one of the 4 catalog statuses.
func ValidCatalogStatus(status string) bool {
	for _, s := range CatalogStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// RegistryComponent describes one of the 17 canonical ClearedStack components.
type RegistryComponent struct {
	Slug           string
	Name           string
	Kind           string // "control-plane" or "worker"
	Stage          int    // 0 for control-plane, 1..10 for workers
	Namespace      string // "clearedstack" or "cs-workers"
	Repository     string
	Responsibility string
}

var canonicalRegistry = []RegistryComponent{
	{
		Slug:           "conn",
		Name:           "Conn",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "conn",
		Responsibility: "Sole public HTTPS portal, contractor tool catalog, live SSE status relay, and anonymous PoW intake.",
	},
	{
		Slug:           "muster",
		Name:           "Muster",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "muster",
		Responsibility: "Central queue lease coordinator, state-transition gatekeeper, SSE publisher, and 5-layer anti-spam shield.",
	},
	{
		Slug:           "logbook",
		Name:           "Logbook",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "logbook",
		Responsibility: "PostgreSQL 17 system of record enforcing core.* guards, append-only ledger, and pub.* security-barrier views.",
	},
	{
		Slug:           "plainforge",
		Name:           "Plainforge",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "plainforge",
		Responsibility: "Cluster-local Git forge hosting source repositories and build specifications with zero external cloud dependency.",
	},
	{
		Slug:           "lazarette",
		Name:           "Lazarette",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "lazarette",
		Responsibility: "Cluster-local OCI container registry holding signed, digest-pinned arm64 images for offline operation.",
	},
	{
		Slug:           "keelworks",
		Name:           "Keelworks",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "keelworks",
		Responsibility: "Deterministic ko image builder and signer publishing verified digests from Plainforge into Lazarette.",
	},
	{
		Slug:           "shipkeeper",
		Name:           "Shipkeeper",
		Kind:           "control-plane",
		Namespace:      "clearedstack",
		Repository:     "shipkeeper",
		Responsibility: "Reconciles digest-pinned workloads, runs health probes, and reports sanitized component health to Muster.",
	},
	{
		Slug:           "trawl",
		Name:           "Trawl",
		Kind:           "worker",
		Stage:          1,
		Namespace:      "cs-workers",
		Repository:     "trawl",
		Responsibility: "Stage 1 discovery worker normalizing candidate URLs and recording deduplicated finds.",
	},
	{
		Slug:           "sextant",
		Name:           "Sextant",
		Kind:           "worker",
		Stage:          2,
		Namespace:      "cs-workers",
		Repository:     "sextant",
		Responsibility: "Stage 2 observation worker extracting structured regulatory and portal facts.",
	},
	{
		Slug:           "assay",
		Name:           "Assay",
		Kind:           "worker",
		Stage:          3,
		Namespace:      "cs-workers",
		Repository:     "assay",
		Responsibility: "Stage 3 evaluation worker running screening gates and weighted rubric scoring.",
	},
	{
		Slug:           "countersign",
		Name:           "Countersign",
		Kind:           "worker",
		Stage:          4,
		Namespace:      "cs-workers",
		Repository:     "countersign",
		Responsibility: "Stage 4 human-in-the-loop review desk recording owner item decisions and edit approvals.",
	},
	{
		Slug:           "waybill",
		Name:           "Waybill",
		Kind:           "worker",
		Stage:          5,
		Namespace:      "cs-workers",
		Repository:     "waybill",
		Responsibility: "Stage 5 clean-room specification compiler producing self-contained build specs without raw captures.",
	},
	{
		Slug:           "moldloft",
		Name:           "Moldloft",
		Kind:           "worker",
		Stage:          6,
		Namespace:      "cs-workers",
		Repository:     "moldloft",
		Responsibility: "Stage 6 tool builder generating deterministic code strictly from Waybill specifications.",
	},
	{
		Slug:           "shakedown",
		Name:           "Shakedown",
		Kind:           "worker",
		Stage:          7,
		Namespace:      "cs-workers",
		Repository:     "shakedown",
		Responsibility: "Stage 7 verification worker running acceptance test suites, security checks, and resource gates.",
	},
	{
		Slug:           "chartroom",
		Name:           "Chartroom",
		Kind:           "worker",
		Stage:          8,
		Namespace:      "cs-workers",
		Repository:     "chartroom",
		Responsibility: "Stage 8 catalog publisher listing live, linked, merged, and retired entries with provenance credits.",
	},
	{
		Slug:           "tidegauge",
		Name:           "Tidegauge",
		Kind:           "worker",
		Stage:          9,
		Namespace:      "cs-workers",
		Repository:     "tidegauge",
		Responsibility: "Stage 9 drift monitor checking official rules and linked tools every seven days.",
	},
	{
		Slug:           "bellbuoy",
		Name:           "Bellbuoy",
		Kind:           "worker",
		Stage:          10,
		Namespace:      "cs-workers",
		Repository:     "bellbuoy",
		Responsibility: "Stage 10 incident and approved-edit dispatcher routing E_PARSE, E_NEEDS_SUBTOOL, and repository patches.",
	},
}

// AllRegistryComponents returns a copy of all 17 canonical platform components.
func AllRegistryComponents() []RegistryComponent {
	out := make([]RegistryComponent, len(canonicalRegistry))
	copy(out, canonicalRegistry)
	return out
}

// LookupRegistryComponent finds one of the 17 platform components by slug.
func LookupRegistryComponent(slug string) (RegistryComponent, bool) {
	for _, c := range canonicalRegistry {
		if c.Slug == slug {
			return c, true
		}
	}
	return RegistryComponent{}, false
}

// CatalogLink describes an external linked tool reference from pub.catalog_entry.link.
type CatalogLink struct {
	URL       string `json:"url"`
	Label     string `json:"label"`
	Publisher string `json:"publisher"`
}

// CatalogMerge describes a merged tool target from pub.catalog_entry.merge.
type CatalogMerge struct {
	IntoSlug  string `json:"into_slug"`
	IntoTitle string `json:"into_title"`
	Note      string `json:"note"`
}

// Citation names one authoritative source in a tool's provenance block.
type Citation struct {
	Authority string `json:"authority"`
	Section   string `json:"section"`
	Title     string `json:"title"`
}

// Provenance holds clean-room attribution, citations, and license metadata.
type Provenance struct {
	Credit        string     `json:"credit"`
	License       string     `json:"license"`
	CleanRoomNote string     `json:"clean_room_note"`
	OptOutSLA     string     `json:"opt_out_sla"`
	Citations     []Citation `json:"citations"`
}

// CatalogRetirement describes why and when a catalog entry was retired.
type CatalogRetirement struct {
	Reason     string `json:"reason"`
	ReplacedBy string `json:"replaced_by"`
	RetiredAt  string `json:"retired_at"`
}

// CatalogEntry mirrors one row of pub.catalog_entry.
type CatalogEntry struct {
	ItemID      string
	Slug        string
	Status      string // live, linked, merged, retired
	Title       string
	Summary     string
	Repository  string
	Link        *CatalogLink
	Merge       *CatalogMerge
	Provenance  Provenance
	Retirement  *CatalogRetirement
	PublishedAt string
	EditTarget  string // e.g. catalog.<slug>.description when present in ownership_map.json
}

// Item mirrors one row of pub.item.
type Item struct {
	ItemID     string
	State      string
	Title      string
	RecordedAt string
	ChangedAt  string
}

// HistoryEntry mirrors one row of pub.item_history.
type HistoryEntry struct {
	EntryID    int64
	ItemID     string
	Actor      string
	FromState  string
	ToState    string
	ErrorCode  string
	Note       string
	RecordedAt string
}

// EvaluationGate mirrors one row of pub.evaluation_gate.
type EvaluationGate struct {
	EvaluationID int64
	ItemID       string
	Gate         string
	Passed       bool
	Reason       string
}

// EvaluationFactor mirrors one row of pub.evaluation_factor.
type EvaluationFactor struct {
	EvaluationID int64
	ItemID       string
	Factor       string
	Rating       int
	Weight       int
	Points       int
}

// Evaluation mirrors one row of pub.evaluation joined with its gates and factors.
type Evaluation struct {
	EvaluationID   int64
	ItemID         string
	Profile        string
	GatesPassed    bool
	Score          *int
	Recommendation string
	SplitFlag      bool
	EvaluatedAt    string
	Gates          []EvaluationGate
	Factors        []EvaluationFactor
}

// Decision mirrors one row of pub.decision.
type Decision struct {
	DecisionID     int64
	ItemID         string
	EvaluationID   int64
	Recommendation string
	Outcome        string
	Overridden     bool
	Reason         string
	DecidedAt      string
}

// QueueDepthRow mirrors one row of pub.queue_depth.
type QueueDepthRow struct {
	Worker  string
	Lane    string
	Waiting int
	Claimed int
}

// LaneSummary aggregates waiting and claimed work across lanes.
type LaneSummary struct {
	Urgent       int
	Normal       int
	Backfill     int
	Claimed      int
	NeedsSubtool int
}

// Pause mirrors one row of pub.pause.
type Pause struct {
	PauseID    int64
	ItemID     string
	Worker     string
	Pattern    string
	PausedAt   string
	ReplayedAt string
}

// EditProposal mirrors one row of pub.edit_proposal.
type EditProposal struct {
	ProposalID  string // formatted as EP-0001
	RawID       int64
	ElementID   string
	OwnerRepo   string
	EditClass   string
	Status      string
	Payload     string // non-empty only for approved, building, live
	SubmittedAt string
	DecidedAt   string
}

// RestoreDrill mirrors one row of pub.restore_drill.
type RestoreDrill struct {
	DrillID          int64
	RanAt            string
	Passed           bool
	DecryptPassed    bool
	LogbookPassed    bool
	PlainforgePassed bool
	LazarettePassed  bool
}

// ComponentHealth mirrors one row of pub.component_health.
type ComponentHealth struct {
	Component  string
	State      string // healthy, idle, degraded, paused
	ErrorCode  string // E_TIMEOUT, E_PARSE, E_NEEDS_SUBTOOL, or ""
	ReportedAt string
}

// PortalData bundles the read-only state displayed on GET /.
type PortalData struct {
	Degraded        bool
	ErrorCode       string
	Lanes           LaneSummary
	QueueRows       []QueueDepthRow
	OpenPauses      []Pause
	Health          map[string]ComponentHealth
	LatestDrill     *RestoreDrill
	RecentItems     []Item
	Proposals       []EditProposal
	CatalogCount    int
	CatalogFallback bool
}

// CatalogListResult bundles filtered catalog entries for GET /tools/.
type CatalogListResult struct {
	Degraded        bool
	CatalogFallback bool
	ErrorCode       string
	Entries         []CatalogEntry
	CountsByStatus  map[string]int
}

// CatalogDetail bundles one tool's catalog page data for GET /tools/{slug}.
type CatalogDetail struct {
	Degraded  bool
	ErrorCode string
	Found     bool
	Entry     CatalogEntry
	Proposals []EditProposal
}

// ItemListResult bundles pipeline items and state counts for GET /items/.
type ItemListResult struct {
	Degraded      bool
	ErrorCode     string
	Items         []Item
	CountsByState map[string]int
}

// ItemDetail bundles everything public about one item for GET /items/{id}.
type ItemDetail struct {
	Degraded    bool
	ErrorCode   string
	Found       bool
	Item        Item
	Evaluations []Evaluation
	Decisions   []Decision
	History     []HistoryEntry
	Pauses      []Pause
}

// Reader is Conn's read-only boundary in front of Logbook's pub.* views.
type Reader interface {
	PortalSnapshot(ctx context.Context) (PortalData, error)
	ListCatalog(ctx context.Context, query, status string) (CatalogListResult, error)
	GetCatalogEntry(ctx context.Context, slug string) (CatalogDetail, error)
	ListItems(ctx context.Context, stateFilter string) (ItemListResult, error)
	GetItemDetail(ctx context.Context, itemID string) (ItemDetail, error)
	ListComponentHealth(ctx context.Context) ([]ComponentHealth, bool, string)
}
