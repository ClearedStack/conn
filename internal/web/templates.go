package web

import (
	"fmt"
	"html/template"
)

// AttentionAlert represents one deterministic P0, P1, or P2 banner item on GET /.
type AttentionAlert struct {
	Severity string // "P0", "P1", "P2"
	Code     string // optional public error code
	Summary  string
	Detail   string
}

// ComponentView merges canonical registry metadata with sanitized health state.
type ComponentView struct {
	Slug           string
	Name           string
	Kind           string
	Stage          int
	Namespace      string
	Repository     string
	Responsibility string
	State          string
	ErrorCode      string
	ReportedAt     string
}

type layoutMeta struct {
	Title     string
	Nav       string
	FeedStale bool
}

func proposalStageLabel(status string) string {
	switch status {
	case "pending_approval":
		return "Proposed"
	case "approved":
		return "Approved"
	case "building":
		return "Building"
	case "live":
		return "Live"
	case "rejected":
		return "Rejected"
	default:
		return status
	}
}

func formatOptionalScore(score *int) string {
	if score == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", *score)
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"proposalStage": proposalStageLabel,
		"formatScore":   formatOptionalScore,
	}
	t := template.New("conn").Funcs(funcs)
	for name, src := range rawTemplates {
		if _, err := t.New(name).Parse(src); err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
	}
	return t, nil
}

var rawTemplates = map[string]string{
	"head": `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Meta.Title}} - Conn | ClearedStack</title>
  <link rel="icon" type="image/svg+xml" href="/static/mark.svg">
  <link rel="stylesheet" href="/static/style.css">
  <script src="/static/app.js" defer></script>
</head>
<body>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand-link" href="/">
        <img src="/static/mark.svg" width="28" height="28" alt="Conn helm mark">
        <span>Conn</span>
        <span class="brand-sub">ClearedStack Command Portal &amp; Tool Catalog</span>
      </a>
      <nav class="site-nav" aria-label="Primary">
        <a class="nav-link {{if eq .Meta.Nav "portal"}}active{{end}}" href="/">Command Portal</a>
        <a class="nav-link {{if eq .Meta.Nav "tools"}}active{{end}}" href="/tools/">Tool Catalog</a>
        <a class="nav-link {{if eq .Meta.Nav "items"}}active{{end}}" href="/items/">Pipeline Items</a>
        <a class="nav-link {{if eq .Meta.Nav "registry"}}active{{end}}" href="/registry/">Registry</a>
        <a class="nav-link {{if eq .Meta.Nav "guides"}}active{{end}}" href="/guides/">Guides</a>
        {{if .Meta.FeedStale}}
        <span class="feed-indicator" data-feed-indicator data-feed-state="stale">SSE STALE (&gt;15s)</span>
        {{else}}
        <span class="feed-indicator" data-feed-indicator data-feed-state="live">SSE LIVE</span>
        {{end}}
      </nav>
    </div>
  </header>
  <main class="container">`,

	"foot": `  </main>
  <footer class="site-footer">
    <span>Conn (clearedstack) | Read-only pub.* boundary + Muster Contract v1 relay | Zero cookies, zero accounts, offline-ready</span>
  </footer>
</body>
</html>`,

	"portal": `{{template "head" .}}
    <div class="page-head">
      <h1>Command Portal</h1>
      <p>Single-pane operational view across all 17 ClearedStack components, live Muster queue lanes, restore drill verification, and anonymous tool intake.</p>
    </div>

    <section aria-label="Attention alerts" class="alerts-stack">
      {{if .Alerts}}
        {{range .Alerts}}
        <div class="alert-card {{if eq .Severity "P0"}}alert-p0{{else if eq .Severity "P1"}}alert-p1{{else}}alert-p2{{end}}">
          <span class="severity-tag">{{.Severity}}</span>
          <div>
            <strong>{{.Summary}}</strong>{{if .Code}} <code>({{.Code}})</code>{{end}}
            <div>{{.Detail}}</div>
          </div>
        </div>
        {{end}}
      {{else}}
        <div class="alert-card alert-ok">
          <span class="severity-tag">OK</span>
          <div>
            <strong>All control-plane and worker gates nominal.</strong>
            <div>Live SSE feed is fresh, zero components are degraded or paused, and the latest restore drill passed.</div>
          </div>
        </div>
      {{end}}
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Live Queue Lanes</h2>
        <span class="mono">{{.CatalogCount}} catalog entries published | <a href="/tools/">Browse Tool Catalog</a></span>
      </div>
      <div class="lanes-grid">
        <div class="metric-card">
          <div class="metric-label">Urgent Lane</div>
          <div class="metric-value" data-depth-lane="urgent">{{.Lanes.Urgent}}</div>
          <div class="metric-note">High-priority drift &amp; approved patches</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Normal Lane</div>
          <div class="metric-value" data-depth-lane="normal">{{.Lanes.Normal}}</div>
          <div class="metric-note">Active discovery, scoring &amp; clean-room builds</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Backfill Lane</div>
          <div class="metric-value" data-depth-lane="backfill">{{.Lanes.Backfill}}</div>
          <div class="metric-note">Background sweep &amp; scheduled verification</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Needs Sub-Tool</div>
          <div class="metric-value" data-depth-lane="needs_subtool">{{.Lanes.NeedsSubtool}}</div>
          <div class="metric-note">Items paused awaiting a new parser or rule</div>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>17-Component Health Grid</h2>
        <a href="/registry/">Full Registry &amp; Error Codes</a>
      </div>
      <div class="health-grid">
        {{range .Components}}
        <div class="component-card" data-component-card="{{.Slug}}">
          <div class="component-top">
            <span class="component-name">{{.Name}}</span>
            <span class="pill pill-{{.State}}" data-component-pill>{{.State}}{{if .ErrorCode}} ({{.ErrorCode}}){{end}}</span>
          </div>
          <div class="component-meta">
            <code>{{.Namespace}}/{{.Slug}}</code>
            {{if gt .Stage 0}}| Stage {{.Stage}}{{else}}| Control Plane{{end}}
          </div>
        </div>
        {{end}}
      </div>
    </section>

    <section class="section two-col">
      <div class="card">
        <div class="section-head">
          <h2>Latest Restore Drill</h2>
        </div>
        {{if .LatestDrill}}
          <p>
            Overall status:
            {{if .LatestDrill.Passed}}
              <span class="pill pill-pass">PASSED</span>
            {{else}}
              <span class="pill pill-fail">FAILED</span>
            {{end}}
            <span class="mono">({{.LatestDrill.RanAt}})</span>
          </p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>Subsystem Check</th><th>Result</th></tr>
              </thead>
              <tbody>
                <tr><td>Backup Decryption</td><td>{{if .LatestDrill.DecryptPassed}}<span class="pill pill-pass">pass</span>{{else}}<span class="pill pill-fail">fail</span>{{end}}</td></tr>
                <tr><td>Logbook PostgreSQL 17</td><td>{{if .LatestDrill.LogbookPassed}}<span class="pill pill-pass">pass</span>{{else}}<span class="pill pill-fail">fail</span>{{end}}</td></tr>
                <tr><td>Plainforge Git Repos</td><td>{{if .LatestDrill.PlainforgePassed}}<span class="pill pill-pass">pass</span>{{else}}<span class="pill pill-fail">fail</span>{{end}}</td></tr>
                <tr><td>Lazarette OCI Digests</td><td>{{if .LatestDrill.LazarettePassed}}<span class="pill pill-pass">pass</span>{{else}}<span class="pill pill-fail">fail</span>{{end}}</td></tr>
              </tbody>
            </table>
          </div>
        {{else}}
          <p>No restore drill record is published yet in <code>pub.restore_drill</code>.</p>
        {{end}}
      </div>

      <div class="card">
        <div class="section-head">
          <h2>Suggest a Contractor Tool</h2>
        </div>
        <p class="catalog-summary">Submit a public regulatory reference or workflow pain point anonymously. Your browser computes a 20-bit SHA-256 proof-of-work token before Muster records it.</p>
        <form class="form-grid" data-item-form method="post" action="/v1/items">
          <div>
            <label class="field-label" for="suggest-title">Candidate Tool Title</label>
            <input id="suggest-title" name="title" type="text" maxlength="240" required placeholder="e.g. Sample Per Diem Rate Cap Worksheet">
          </div>
          <div>
            <label class="field-label" for="suggest-address">Authoritative Public Rule URL</label>
            <input id="suggest-address" name="address" type="url" maxlength="2000" required placeholder="https://example.gov/regulations/sample-rule">
          </div>
          <div class="hp-trap" aria-hidden="true">
            <label for="suggest-hp">Leave blank</label>
            <input id="suggest-hp" name="honeypot" type="text" tabindex="-1" autocomplete="off">
          </div>
          <div class="status-row">
            <button type="submit" class="btn">Submit Candidate</button>
            <span class="mono" data-item-status aria-live="polite"></span>
          </div>
        </form>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Recent Pipeline Items</h2>
        <a href="/items/">Explore All 14 Lifecycle States</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Item ID</th>
              <th>State</th>
              <th>Title</th>
              <th>Updated (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {{range .RecentItems}}
            <tr>
              <td><a class="mono" href="/items/{{.ItemID}}">{{.ItemID}}</a></td>
              <td><span class="pill pill-{{.State}}">{{.State}}</span></td>
              <td><a href="/items/{{.ItemID}}">{{.Title}}</a></td>
              <td class="mono">{{.ChangedAt}}</td>
            </tr>
            {{else}}
            <tr><td colspan="4">No pipeline items recorded yet.</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
{{template "foot" .}}`,

	"tools_list": `{{template "head" .}}
    <div class="page-head">
      <h1>Contractor Tool Catalog</h1>
      <p>Deterministic, clean-room calculators, matrices, and authoritative reference links verified for disconnected and regulated contractor teams.</p>
    </div>

    {{if .Result.Degraded}}
    <div class="alert-card alert-p0">
      <span class="severity-tag">P0</span>
      <div>
        <strong>Catalog store temporarily degraded</strong> <code>({{.Result.ErrorCode}})</code>
        <div>Logbook did not respond within the read budget. Try refreshing shortly.</div>
      </div>
    </div>
    {{end}}

    <div class="filter-bar">
      <div class="chips" role="navigation" aria-label="Filter by catalog status">
        <a class="chip {{if eq .StatusFilter ""}}active{{end}}" href="/tools/{{if .Query}}?q={{.Query}}{{end}}">All ({{.TotalCount}})</a>
        {{range .Statuses}}
        <a class="chip {{if eq $.StatusFilter .Name}}active{{end}}" href="/tools/?status={{.Name}}{{if $.Query}}&amp;q={{$.Query}}{{end}}">{{.Name}} ({{.Count}})</a>
        {{end}}
      </div>
      <form class="search-form" method="get" action="/tools/">
        {{if .StatusFilter}}<input type="hidden" name="status" value="{{.StatusFilter}}">{{end}}
        <input type="search" name="q" value="{{.Query}}" placeholder="Search tools, slugs, citations..." aria-label="Search tools">
        <button type="submit" class="btn btn-secondary">Search</button>
      </form>
    </div>

    <div class="catalog-grid">
      {{range .Result.Entries}}
      <article class="catalog-card">
        <div>
          <div class="component-top">
            <span class="pill pill-{{.Status}}">{{.Status}}</span>
            <span class="mono">{{.ItemID}}</span>
          </div>
          <h3><a href="/tools/{{.Slug}}">{{.Title}}</a></h3>
          <p class="catalog-summary">{{.Summary}}</p>
        </div>
        <div class="component-top">
          <a href="/tools/{{.Slug}}">Open details &amp; provenance</a>
          <span class="component-meta mono">{{.Slug}}</span>
        </div>
      </article>
      {{else}}
      <div class="card">
        <p>No catalog entries matched your filter.</p>
      </div>
      {{end}}
    </div>
{{template "foot" .}}`,

	"tool_detail": `{{template "head" .}}
    <div class="page-head">
      <p><a href="/tools/">&larr; Back to Tool Catalog</a></p>
      <div class="status-row">
        <span class="pill pill-{{.Entry.Status}}">{{.Entry.Status}}</span>
        <span class="mono">Slug: {{.Entry.Slug}}</span>
        <span class="mono">| Pipeline Item: <a href="/items/{{.Entry.ItemID}}">{{.Entry.ItemID}}</a></span>
        <span class="mono">| Published: {{.Entry.PublishedAt}}</span>
      </div>
      <h1>{{.Entry.Title}}</h1>
      <p>{{.Entry.Summary}}</p>
    </div>

    {{if .Entry.Link}}
    <div class="callout">
      <strong>Linked External Tool:</strong> Maintained by {{.Entry.Link.Publisher}}.
      <div><a href="{{.Entry.Link.URL}}" rel="noopener noreferrer">{{.Entry.Link.Label}} ({{.Entry.Link.URL}})</a></div>
    </div>
    {{end}}

    {{if .Entry.Merge}}
    <div class="callout">
      <strong>Consolidated Entry:</strong> Merged into <a href="/tools/{{.Entry.Merge.IntoSlug}}">{{.Entry.Merge.IntoTitle}}</a>.
      <div>{{.Entry.Merge.Note}}</div>
    </div>
    {{end}}

    {{if .Entry.Retirement}}
    <div class="callout">
      <strong>Retired Entry ({{.Entry.Retirement.RetiredAt}}):</strong> {{.Entry.Retirement.Reason}}
      {{if .Entry.Retirement.ReplacedBy}}
      <div>Replacement tool: <a href="/tools/{{.Entry.Retirement.ReplacedBy}}">{{.Entry.Retirement.ReplacedBy}}</a></div>
      {{end}}
    </div>
    {{end}}

    <section class="section two-col">
      <div class="card">
        <div class="section-head">
          <h2>Provenance &amp; Clean-Room Credit</h2>
        </div>
        <p><strong>Attribution:</strong> {{.Entry.Provenance.Credit}}</p>
        <p><strong>License:</strong> <code>{{.Entry.Provenance.License}}</code></p>
        <p><strong>Clean-Room Boundary:</strong> {{.Entry.Provenance.CleanRoomNote}}</p>
        <p><strong>Correction &amp; Opt-Out SLA:</strong> {{.Entry.Provenance.OptOutSLA}}</p>

        {{if .Entry.Provenance.Citations}}
        <h3>Authoritative Citations</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Authority</th><th>Section</th><th>Title</th></tr>
            </thead>
            <tbody>
              {{range .Entry.Provenance.Citations}}
              <tr>
                <td>{{.Authority}}</td>
                <td class="mono">{{.Section}}</td>
                <td>{{.Title}}</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{end}}
      </div>

      <div class="card">
        <div class="section-head">
          <h2>Propose an Edit or Attribution Note</h2>
        </div>
        {{if .Editable}}
          <p class="catalog-summary">Target <code>{{.EditTarget}}</code> ({{.OwnerEntry.Kind}} in <code>{{.OwnerEntry.Repository}}</code>). No account or cookie is used; a 20-bit SHA-256 proof-of-work protects the review queue.</p>
          <form class="form-grid" data-edit-form method="post" action="/v1/edits">
            <input type="hidden" name="target" value="{{.EditTarget}}">
            <div>
              <label class="field-label" for="edit-change">Proposed Text or Correction</label>
              <textarea id="edit-change" name="change" maxlength="2000" required placeholder="Describe the updated description, rule threshold, or attribution text..."></textarea>
            </div>
            <div>
              <label class="field-label" for="edit-reason">Reason / Authoritative Citation / Opt-Out Request</label>
              <input id="edit-reason" name="reason" type="text" maxlength="500" required placeholder="Cite the section number or maintainer notice">
            </div>
            <div class="hp-trap" aria-hidden="true">
              <label for="edit-hp">Leave blank</label>
              <input id="edit-hp" name="honeypot" type="text" tabindex="-1" autocomplete="off">
            </div>
            <div class="status-row">
              <button type="submit" class="btn">Edit</button>
              <span class="pill" data-edit-pill hidden></span>
              <span class="mono" data-edit-status aria-live="polite"></span>
            </div>
          </form>
        {{else}}
          <p class="catalog-summary">This catalog entry does not currently expose an inline edit target in <code>ownership_map.json</code>.</p>
        {{end}}
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Public Edit Proposals ({{.EditTarget}})</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Proposal</th>
              <th>Live Status</th>
              <th>Submitted (UTC)</th>
              <th>Approved Change Summary</th>
            </tr>
          </thead>
          <tbody>
            {{range .Proposals}}
            <tr>
              <td class="mono">{{.ProposalID}}</td>
              <td><span class="pill pill-{{.Status}}" data-proposal-id="{{.ProposalID}}">{{.ProposalID}}: {{proposalStage .Status}}</span></td>
              <td class="mono">{{.SubmittedAt}}</td>
              <td>{{if .Payload}}{{.Payload}}{{else}}<span class="component-meta">Hidden until Countersign approval</span>{{end}}</td>
            </tr>
            {{else}}
            <tr><td colspan="4">No edit proposals recorded for this entry yet.</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
{{template "foot" .}}`,

	"items_list": `{{template "head" .}}
    <div class="page-head">
      <h1>Pipeline Item Explorer</h1>
      <p>Read-only ledger across all 14 Muster Contract v1 item states, from initial Trawl discovery through Assay scoring, Countersign review, clean-room Waybill specification, and Chartroom publication.</p>
    </div>

    {{if .Result.Degraded}}
    <div class="alert-card alert-p0">
      <span class="severity-tag">P0</span>
      <div>
        <strong>Item ledger temporarily degraded</strong> <code>({{.Result.ErrorCode}})</code>
        <div>Logbook did not complete the read within budget.</div>
      </div>
    </div>
    {{end}}

    <div class="filter-bar">
      <div class="chips" role="navigation" aria-label="Filter by lifecycle state">
        <a class="chip {{if eq .StateFilter ""}}active{{end}}" href="/items/">All ({{.TotalCount}})</a>
        {{range .States}}
        <a class="chip {{if eq $.StateFilter .Name}}active{{end}}" href="/items/?state={{.Name}}">{{.Name}} ({{.Count}})</a>
        {{end}}
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Item ID</th>
            <th>State</th>
            <th>Title</th>
            <th>Recorded (UTC)</th>
            <th>Last Transition (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {{range .Result.Items}}
          <tr>
            <td><a class="mono" href="/items/{{.ItemID}}">{{.ItemID}}</a></td>
            <td><span class="pill pill-{{.State}}">{{.State}}</span></td>
            <td><a href="/items/{{.ItemID}}">{{.Title}}</a></td>
            <td class="mono">{{.RecordedAt}}</td>
            <td class="mono">{{.ChangedAt}}</td>
          </tr>
          {{else}}
          <tr><td colspan="5">No items in this lifecycle state.</td></tr>
          {{end}}
        </tbody>
      </table>
    </div>
{{template "foot" .}}`,

	"item_detail": `{{template "head" .}}
    <div class="page-head">
      <p><a href="/items/">&larr; Back to Pipeline Items</a></p>
      <div class="status-row">
        <span class="mono">{{.Detail.Item.ItemID}}</span>
        <span class="pill pill-{{.Detail.Item.State}}">{{.Detail.Item.State}}</span>
        <span class="mono">Recorded: {{.Detail.Item.RecordedAt}} | Updated: {{.Detail.Item.ChangedAt}}</span>
      </div>
      <h1>{{.Detail.Item.Title}}</h1>
    </div>

    {{range .Detail.Pauses}}
    <div class="alert-card alert-p1">
      <span class="severity-tag">PAUSE</span>
      <div>
        <strong>Paused at worker <code>{{.Worker}}</code></strong> {{if .ReplayedAt}}(replayed {{.ReplayedAt}}){{else}}(active <code>E_NEEDS_SUBTOOL</code>){{end}}
        <div>Missing sub-tool pattern: <code>{{.Pattern}}</code> | Paused at {{.PausedAt}}</div>
      </div>
    </div>
    {{end}}

    <section class="section">
      <div class="section-head">
        <h2>Assay Screening Gates &amp; Weighted Rubric</h2>
      </div>
      {{range .Detail.Evaluations}}
      <div class="card">
        <div class="status-row">
          <strong>Profile: <code>{{.Profile}}</code></strong>
          {{if .GatesPassed}}
            <span class="pill pill-pass">gates passed</span>
          {{else}}
            <span class="pill pill-fail">screened out</span>
          {{end}}
          <span class="pill">Score: {{formatScore .Score}}</span>
          {{if .Recommendation}}<span class="pill">Recommendation: {{.Recommendation}}</span>{{end}}
          {{if .SplitFlag}}<span class="pill pill-paused">split candidate</span>{{end}}
          <span class="mono">Evaluated: {{.EvaluatedAt}}</span>
        </div>

        {{if .Gates}}
        <h3>Screening Gates</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Gate</th><th>Passed</th><th>Note</th></tr>
            </thead>
            <tbody>
              {{range .Gates}}
              <tr>
                <td class="mono">{{.Gate}}</td>
                <td>{{if .Passed}}<span class="pill pill-pass">pass</span>{{else}}<span class="pill pill-fail">fail</span>{{end}}</td>
                <td>{{.Reason}}</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{end}}

        {{if .Factors}}
        <h3>Weighted Rubric Factors</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Factor</th><th>Rating (1-5)</th><th>Weight</th><th>Points</th></tr>
            </thead>
            <tbody>
              {{range .Factors}}
              <tr>
                <td class="mono">{{.Factor}}</td>
                <td class="mono">{{.Rating}}</td>
                <td class="mono">{{.Weight}}</td>
                <td class="mono">{{.Points}}</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{end}}
      </div>
      {{else}}
      <div class="card"><p>No Assay evaluation recorded yet for this item.</p></div>
      {{end}}
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Countersign Decisions</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Outcome</th>
              <th>Assay Recommendation</th>
              <th>Overridden</th>
              <th>Reason</th>
              <th>Decided (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {{range .Detail.Decisions}}
            <tr>
              <td><span class="pill pill-{{.Outcome}}">{{.Outcome}}</span></td>
              <td class="mono">{{.Recommendation}}</td>
              <td class="mono">{{if .Overridden}}yes{{else}}no{{end}}</td>
              <td>{{.Reason}}</td>
              <td class="mono">{{.DecidedAt}}</td>
            </tr>
            {{else}}
            <tr><td colspan="5">No Countersign owner decision recorded yet.</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Append-Only Lifecycle History</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Recorded (UTC)</th>
              <th>Actor</th>
              <th>Transition</th>
              <th>Error Code</th>
              <th>Summary Note</th>
            </tr>
          </thead>
          <tbody>
            {{range .Detail.History}}
            <tr>
              <td class="mono">{{.RecordedAt}}</td>
              <td class="mono">{{.Actor}}</td>
              <td class="mono">{{if .FromState}}{{.FromState}} -&gt; {{end}}{{.ToState}}</td>
              <td>{{if .ErrorCode}}<code>{{.ErrorCode}}</code>{{else}}-{{end}}</td>
              <td>{{.Note}}</td>
            </tr>
            {{else}}
            <tr><td colspan="5">No history entries recorded yet.</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
{{template "foot" .}}`,

	"registry": `{{template "head" .}}
    <div class="page-head">
      <h1>17-Component Platform Registry</h1>
      <p>Canonical inventory of the 7 control-plane workloads in <code>clearedstack</code> and the 10 stage workers in <code>cs-workers</code>, paired with live sanitized health states.</p>
    </div>

    {{if .Degraded}}
    <div class="alert-card alert-p0">
      <span class="severity-tag">P0</span>
      <div>
        <strong>Component health view temporarily degraded</strong> <code>({{.ErrorCode}})</code>
        <div>Showing cached live SSE health where available.</div>
      </div>
    </div>
    {{end}}

    <section class="section">
      <div class="section-head">
        <h2>Control Plane (<code>clearedstack</code> namespace)</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Component</th>
              <th>Repository</th>
              <th>Health</th>
              <th>Error Code</th>
              <th>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            {{range .ControlPlane}}
            <tr data-component-card="{{.Slug}}">
              <td><strong>{{.Name}}</strong> (<code>{{.Slug}}</code>)</td>
              <td class="mono">{{.Repository}}</td>
              <td><span class="pill pill-{{.State}}" data-component-pill>{{.State}}{{if .ErrorCode}} ({{.ErrorCode}}){{end}}</span></td>
              <td>{{if .ErrorCode}}<code>{{.ErrorCode}}</code>{{else}}-{{end}}</td>
              <td>{{.Responsibility}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Pipeline Workers (<code>cs-workers</code> namespace, Stages 1-10)</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Stage</th>
              <th>Worker</th>
              <th>Repository</th>
              <th>Health</th>
              <th>Error Code</th>
              <th>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            {{range .Workers}}
            <tr data-component-card="{{.Slug}}">
              <td class="mono">{{.Stage}}</td>
              <td><strong>{{.Name}}</strong> (<code>{{.Slug}}</code>)</td>
              <td class="mono">{{.Repository}}</td>
              <td><span class="pill pill-{{.State}}" data-component-pill>{{.State}}{{if .ErrorCode}} ({{.ErrorCode}}){{end}}</span></td>
              <td>{{if .ErrorCode}}<code>{{.ErrorCode}}</code>{{else}}-{{end}}</td>
              <td>{{.Responsibility}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Sanitized Public Error Codes</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Code</th><th>Meaning</th></tr>
          </thead>
          <tbody>
            <tr><td><code>E_TIMEOUT</code></td><td>Transient timeout, rate limit, or store unavailability. Safe to retry with backoff; never leaks internal addresses or stack traces.</td></tr>
            <tr><td><code>E_PARSE</code></td><td>Input validation refusal, malformed JSON, invalid proof-of-work, or unparseable upstream artifact routed to Bellbuoy.</td></tr>
            <tr><td><code>E_NEEDS_SUBTOOL</code></td><td>Item or call encountered an unfamiliar format or rule pattern; work pauses cleanly until a sub-tool is built and replayed.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
{{template "foot" .}}`,

	"guides": `{{template "head" .}}
    <div class="page-head">
      <h1>Operational &amp; Governance Guides</h1>
      <p>How ClearedStack operates inside disconnected networks, enforces clean-room tool construction, and honors source attribution and anonymous opt-out requests.</p>
    </div>

    <section class="section card">
      <h2>1. Disconnected &amp; Offline-Ready Operation</h2>
      <p>Conn is the sole public HTTPS entry pod in <code>clearedstack</code>. Every asset served by Conn is compiled directly into its static <code>linux/arm64</code> binary:</p>
      <ul>
        <li><strong>Strict Content-Security-Policy:</strong> <code>default-src 'self'</code> with <code>frame-ancestors 'none'</code> and zero external scripts, stylesheets, fonts, or telemetry endpoints.</li>
        <li><strong>Cluster-Local Supply Chain:</strong> Source repositories live in <code>plainforge</code>, Keelworks builds deterministic <code>ko</code> images without <code>Dockerfile</code> daemons, and Shipkeeper deploys digest-pinned images from <code>lazarette.clearedstack.svc.cluster.local:5000</code>.</li>
        <li><strong>Zero Session State:</strong> Conn sets zero HTTP cookies, requires zero user logins, and fits inside a <code>128 MiB</code> memory limit on <code>arm64</code> nodes.</li>
      </ul>
    </section>

    <section class="section card">
      <h2>2. Clean-Room Specification Boundary</h2>
      <p>ClearedStack separates public rule observation from code generation so published tools are clean-room implementations grounded in public citations:</p>
      <ul>
        <li><strong>Observation &amp; Screening (Stages 1-4):</strong> Trawl records candidate URLs, Sextant extracts structured regulatory facts, Assay evaluates screening gates and weighted utility factors, and Countersign records human review decisions.</li>
        <li><strong>Waybill Clean-Room Spec (Stage 5):</strong> Waybill writes a self-contained specification naming inputs, formulas, edge cases, and authoritative section citations. Raw external page markup never crosses past Waybill.</li>
        <li><strong>Moldloft &amp; Shakedown (Stages 6-7):</strong> Moldloft builds deterministic tool code solely from the Waybill spec, and Shakedown verifies test suites and resource budgets before Chartroom lists the tool.</li>
      </ul>
    </section>

    <section class="section card">
      <h2>3. Attribution, Linked Listings &amp; Opt-Out SLA</h2>
      <p>When an authoritative public calculator or guide already serves contractors well, Countersign selects the <code>linked</code> outcome so Conn sends readers straight to the maintainer with full credit instead of duplicating their work.</p>
      <ul>
        <li><strong>Inline Anonymous Corrections:</strong> Every editable catalog page includes an inline <strong>Edit</strong> form backed by Muster's 5-layer anti-spam shield (<code>muster-pow-v1</code> 20-bit SHA-256 proof-of-work, honeypot trap, per-visitor salted daily HMAC budget in Muster, ownership map verification, and Countersign human review).</li>
        <li><strong>Privacy by Construction:</strong> Conn extracts the TCP peer address strictly in memory to populate Muster's daily rate-limit check and never logs, persists, or echoes visitor IP addresses.</li>
        <li><strong>2-Business-Day Review SLA:</strong> Attribution updates, citation fixes, and link opt-out requests submitted via inline Edit transition live on the page from <code>Proposed</code> to <code>Approved</code>, <code>Building</code>, and <code>Live</code>.</li>
      </ul>
    </section>
{{template "foot" .}}`,

	"not_found": `{{template "head" .}}
    <div class="page-head">
      <h1>404 - Page Not Found</h1>
      <p>{{.Message}}</p>
      <p><a href="/">Return to the Command Portal</a> or <a href="/tools/">browse the Tool Catalog</a>.</p>
    </div>
{{template "foot" .}}`,
}
