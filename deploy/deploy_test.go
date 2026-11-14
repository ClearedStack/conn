package deploy_test

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ClearedStack/conn/internal/ownership"
)

func TestManifestsAndRepositoryRules(t *testing.T) {
	connYAML, err := os.ReadFile("conn.yaml")
	if err != nil {
		t.Fatal(err)
	}
	netpolYAML, err := os.ReadFile("networkpolicy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	koYAML, err := os.ReadFile(filepath.Join("..", ".ko.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	appYAML, err := os.ReadFile(filepath.Join("..", "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compJSON, err := os.ReadFile(filepath.Join("..", "component.json"))
	if err != nil {
		t.Fatal(err)
	}
	goMod, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Module path and strict Go standard-library-only rule.
	if !strings.Contains(string(goMod), "module github.com/ClearedStack/conn\n") {
		t.Fatalf("go.mod does not declare module github.com/ClearedStack/conn:\n%s", goMod)
	}
	if strings.Contains(string(goMod), "require") {
		t.Fatalf("go.mod must have zero external dependencies:\n%s", goMod)
	}

	// 2. AST verification that every .go file imports ONLY stdlib or github.com/ClearedStack/conn/...
	fset := token.NewFileSet()
	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("failed parsing %s: %v", path, perr)
			return nil
		}
		for _, imp := range f.Imports {
			pkgPath, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				t.Errorf("%s: invalid import literal %s", path, imp.Path.Value)
				continue
			}
			if strings.HasPrefix(pkgPath, "github.com/ClearedStack/conn/") {
				continue
			}
			firstSeg, _, _ := strings.Cut(pkgPath, "/")
			if strings.Contains(firstSeg, ".") {
				t.Errorf("%s imports forbidden external package %q (stdlib only!)", path, pkgPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. No Dockerfile allowed; ko base image and app.yaml must be pinned by sha256 digest.
	if _, err := os.Stat(filepath.Join("..", "Dockerfile")); err == nil {
		t.Fatal("Dockerfile found; images must be built with ko, not Docker")
	}
	digestRE := regexp.MustCompile(`sha256:[0-9a-f]{64}\b`)
	if !digestRE.Match(koYAML) {
		t.Fatalf(".ko.yaml base image is not pinned by sha256 digest:\n%s", koYAML)
	}
	for _, needle := range []string{
		"lazarette.clearedstack.svc.cluster.local:5000/static@sha256:",
		"CGO_ENABLED=0",
		"-trimpath",
		"-s -w",
		"linux/arm64",
	} {
		if !strings.Contains(string(koYAML), needle) {
			t.Errorf(".ko.yaml missing %q", needle)
		}
	}

	for _, needle := range []string{
		"name: conn",
		"namespace: clearedstack",
		"image: conn",
		"digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"replicas: 1",
		"port: 8080",
		"memory: 128Mi",
	} {
		if !strings.Contains(string(appYAML), needle) {
			t.Errorf("app.yaml missing %q", needle)
		}
	}

	// 4. component.json metadata check.
	var comp struct {
		Slug      string   `json:"slug"`
		Name      string   `json:"name"`
		Formerly  string   `json:"formerly"`
		Kind      string   `json:"kind"`
		Namespace string   `json:"namespace"`
		Memory    string   `json:"memory"`
		Version   string   `json:"version"`
		DependsOn []string `json:"dependsOn"`
	}
	if err := json.Unmarshal(compJSON, &comp); err != nil {
		t.Fatalf("component.json invalid JSON: %v", err)
	}
	if comp.Slug != "conn" || comp.Formerly != "clearedstack-web" || comp.Kind != "control-plane" || comp.Namespace != "clearedstack" || comp.Memory != "128 MiB" {
		t.Fatalf("unexpected component.json metadata: %+v", comp)
	}

	// 5. ownership_map.json validation.
	owners, err := ownership.LoadFile("ownership_map.json")
	if err != nil {
		t.Fatalf("ownership_map.json failed validation: %v", err)
	}
	for _, wantTarget := range []string{
		"catalog.sample-calculator.description",
		"sextant.sample-portal.options",
		"assay.sample-profile.report",
	} {
		if _, ok := owners.Lookup(wantTarget); !ok {
			t.Errorf("ownership_map.json missing expected target %q", wantTarget)
		}
	}

	// 6. Hardened Deployment, ServiceAccount, ConfigMap, Service, Ingress, and zero plaintext Secret in Git.
	cy := string(connYAML)
	for _, needle := range []string{
		"kind: ServiceAccount",
		"kind: ConfigMap",
		"name: conn-ownership-map",
		"kind: Deployment",
		"namespace: clearedstack",
		"priorityClassName: clearedstack-high",
		"serviceAccountName: conn",
		"lazarette.clearedstack.svc.cluster.local:5000/conn@sha256:",
		"runAsNonRoot: true",
		"runAsUser: 65532",
		"readOnlyRootFilesystem: true",
		"allowPrivilegeEscalation: false",
		`drop: ["ALL"]`,
		"type: RuntimeDefault",
		"cpu: 50m",
		"memory: 64Mi",
		"cpu: 500m",
		"memory: 128Mi",
		"key: kubernetes.io/arch",
		`values: ["arm64"]`,
		"key: kubernetes.io/hostname",
		`values: ["cm3588-plus"]`,
		"secretName: logbook-pub-credentials",
		"CONN_DATABASE_PASSWORD_FILE",
		"kind: Service",
		"kind: Ingress",
	} {
		if !strings.Contains(cy, needle) {
			t.Errorf("deploy/conn.yaml missing required setting %q", needle)
		}
	}
	if strings.Contains(cy, "kind: Secret") {
		t.Error("deploy/conn.yaml must not commit a kind: Secret manifest in Git")
	}

	// 7. Default-deny NetworkPolicy opening only 8080 ingress and DNS/logbook/muster egress.
	np := string(netpolYAML)
	for _, needle := range []string{
		"name: conn-default-deny",
		"namespace: clearedstack",
		"app.kubernetes.io/name: conn",
		"- Ingress",
		"- Egress",
		"port: 8080",
		"port: 53",
		"app.kubernetes.io/name: logbook",
		"port: 5432",
		"app.kubernetes.io/name: muster",
		"port: 80",
	} {
		if !strings.Contains(np, needle) {
			t.Errorf("deploy/networkpolicy.yaml missing %q", needle)
		}
	}

	// 8. Zero UTF-8 em dashes (U+2014 = 0xE2 0x80 0x94) across ALL tracked/untracked repo files.
	emDash := []byte{0xe2, 0x80, 0x94}
	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(data, emDash) {
			t.Errorf("forbidden em dash (U+2014) found in %s", filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
