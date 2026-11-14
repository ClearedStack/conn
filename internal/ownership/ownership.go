// Package ownership parses and checks edit targets against ownership_map.json.
package ownership

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxFileBytes bounds ownership_map.json size on disk or in memory.
	MaxFileBytes = 1 << 20

	// MaxTargetBytes is the maximum length of a target identifier in Logbook.
	MaxTargetBytes = 100

	// MaxPathBytes is the maximum relative file path length in Logbook.
	MaxPathBytes = 500
)

// Edit classes permitted in ownership_map.json per Contract v1.
const (
	KindData   = "DATA"
	KindConfig = "CONFIG"
	KindIssue  = "ISSUE"
)

var (
	targetPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)
	relPathRe     = regexp.MustCompile(`^[A-Za-z0-9._\[\]-]+(/[A-Za-z0-9._\[\]-]+)*$`)

	validKinds = map[string]bool{
		KindData:   true,
		KindConfig: true,
		KindIssue:  true,
	}

	// Known repositories in the ClearedStack naming registry, including
	// clearedstack.com which appears in Muster Contract v1 saved examples.
	knownRepositories = map[string]bool{
		"conn":             true,
		"clearedstack.com": true,
		"muster":           true,
		"logbook":          true,
		"plainforge":       true,
		"lazarette":        true,
		"keelworks":        true,
		"shipkeeper":       true,
		"trawl":            true,
		"sextant":          true,
		"assay":            true,
		"countersign":      true,
		"waybill":          true,
		"moldloft":         true,
		"shakedown":        true,
		"chartroom":        true,
		"tidegauge":        true,
		"bellbuoy":         true,
	}
)

// Entry describes the owning repository, file path, and edit class for one target.
type Entry struct {
	Repository string `json:"repository"`
	File       string `json:"file"`
	Kind       string `json:"kind"`
}

// Map holds validated editable targets keyed by target name.
type Map struct {
	elements map[string]Entry
}

// Parse strictly validates raw ownership_map.json bytes.
func Parse(data []byte) (*Map, error) {
	if len(data) > MaxFileBytes {
		return nil, errors.New("ownership: map exceeds 1 MiB limit")
	}
	var doc struct {
		Elements map[string]Entry `json:"elements"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("ownership: invalid JSON document")
	}
	if dec.More() {
		return nil, errors.New("ownership: unexpected trailing JSON content")
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("ownership: unexpected second JSON value")
	}
	if doc.Elements == nil {
		return nil, errors.New("ownership: missing elements object")
	}

	clean := make(map[string]Entry, len(doc.Elements))
	for target, entry := range doc.Elements {
		if !ValidTargetName(target) {
			return nil, fmt.Errorf("ownership: invalid target %q", target)
		}
		if !knownRepositories[entry.Repository] {
			return nil, fmt.Errorf("ownership: target %q names unknown repository", target)
		}
		if !validRelativePath(entry.File) {
			return nil, fmt.Errorf("ownership: target %q has invalid relative file path", target)
		}
		if !validKinds[entry.Kind] {
			return nil, fmt.Errorf("ownership: target %q kind must be DATA, CONFIG, or ISSUE", target)
		}
		clean[target] = entry
	}
	return &Map{elements: clean}, nil
}

// LoadFile reads and validates ownership_map.json from path.
func LoadFile(path string) (*Map, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("ownership: cannot stat ownership map")
	}
	if info.Size() > MaxFileBytes {
		return nil, errors.New("ownership: file exceeds 1 MiB limit")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("ownership: cannot read ownership map")
	}
	return Parse(raw)
}

// Lookup returns the ownership entry for target, if registered.
func (m *Map) Lookup(target string) (Entry, bool) {
	if m == nil {
		return Entry{}, false
	}
	e, ok := m.elements[target]
	return e, ok
}

// Targets returns all registered targets in sorted order.
func (m *Map) Targets() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.elements))
	for k := range m.elements {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidTargetName reports whether target satisfies Logbook and Contract v1 naming rules.
func ValidTargetName(target string) bool {
	return len(target) > 0 && len(target) <= MaxTargetBytes && targetPattern.MatchString(target)
}

func validRelativePath(p string) bool {
	if len(p) == 0 || len(p) > MaxPathBytes {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if !relPathRe.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
