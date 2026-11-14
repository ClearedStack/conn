package ownership

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseValidAndInvalidMaps(t *testing.T) {
	validJSON := `{
  "elements": {
    "catalog.sample-calculator.description": {
      "repository": "conn",
      "file": "internal/pubstore/seed.go",
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
	m, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatalf("Parse validJSON failed: %v", err)
	}
	e, ok := m.Lookup("catalog.sample-calculator.description")
	if !ok || e.Kind != KindData || e.Repository != "conn" {
		t.Fatalf("unexpected lookup result: %+v, %v", e, ok)
	}
	if _, ok := m.Lookup("catalog.unknown.description"); ok {
		t.Fatal("expected unknown target to return false")
	}
	if got := len(m.Targets()); got != 3 {
		t.Fatalf("Targets() count = %d, want 3", got)
	}

	tmp := filepath.Join(t.TempDir(), "ownership_map.json")
	if err := os.WriteFile(tmp, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(tmp); err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	invalidCases := []struct {
		name string
		raw  string
	}{
		{"empty", ``},
		{"missing_elements", `{}`},
		{"unknown_top_field", `{"elements":{},"extra":1}`},
		{"unknown_entry_field", `{"elements":{"catalog.a.b":{"repository":"conn","file":"a.json","kind":"DATA","nope":true}}}`},
		{"bad_target_uppercase", `{"elements":{"Catalog.A.B":{"repository":"conn","file":"a.json","kind":"DATA"}}}`},
		{"too_long_target", `{"elements":{"` + strings.Repeat("a", 101) + `":{"repository":"conn","file":"a.json","kind":"DATA"}}}`},
		{"unknown_repo", `{"elements":{"catalog.a.b":{"repository":"unknown-repo","file":"a.json","kind":"DATA"}}}`},
		{"bad_kind", `{"elements":{"catalog.a.b":{"repository":"conn","file":"a.json","kind":"PATCH"}}}`},
		{"traversal_path", `{"elements":{"catalog.a.b":{"repository":"conn","file":"../secret.json","kind":"DATA"}}}`},
		{"trailing_json", `{"elements":{}}{"elements":{}}`},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.raw)); err == nil {
				t.Fatalf("expected Parse to reject %s", tc.name)
			}
		})
	}
}
