package server

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// declaredAPIPaths is the ground-truth set of paths the server registers
// under /api/v1. Bump this whenever you add or remove a route. The test
// below cross-checks it against what's actually in openapi.json, so spec
// drift becomes a build failure.
var declaredAPIPaths = map[string][]string{
	"/api/v1/openapi.json":             {"GET"},
	"/api/v1/whoami":                   {"GET"},
	"/api/v1/hosts":                    {"GET"},
	"/api/v1/hosts/{name}":             {"GET"},
	"/api/v1/hosts/{name}/wake":        {"POST"},
	"/api/v1/hosts/{name}/shutdown":    {"POST"},
	"/api/v1/hosts/{name}/ssh-cert":    {"POST"},
	"/api/v1/events":                   {"GET"},
	"/api/v1/events/stream":            {"GET"},
}

func TestOpenAPISpecParses(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(openapiSpec, &doc); err != nil {
		t.Fatalf("openapi.json doesn't parse: %v", err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.") {
		t.Errorf("openapi version should start with 3.; got %q", v)
	}
}

func TestOpenAPIPathsMatchRoutes(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openapiSpec, &doc); err != nil {
		t.Fatal(err)
	}

	// Spec uses the /api/v1 server prefix, so path keys are RELATIVE.
	// Convert to absolute by prepending /api/v1 for comparison.
	specPaths := map[string][]string{}
	for p, ops := range doc.Paths {
		full := "/api/v1" + p
		var methods []string
		for m := range ops {
			if mu := strings.ToUpper(m); mu == "GET" || mu == "POST" || mu == "PUT" || mu == "DELETE" || mu == "PATCH" {
				methods = append(methods, mu)
			}
		}
		sort.Strings(methods)
		specPaths[full] = methods
	}

	// declaredAPIPaths is the source of truth; both sides must match exactly.
	for path, wantMethods := range declaredAPIPaths {
		sort.Strings(wantMethods)
		gotMethods, ok := specPaths[path]
		if !ok {
			t.Errorf("path %q is declared by the server but missing from openapi.json", path)
			continue
		}
		if strings.Join(gotMethods, ",") != strings.Join(wantMethods, ",") {
			t.Errorf("path %q methods: spec has %v, server has %v", path, gotMethods, wantMethods)
		}
	}
	for path := range specPaths {
		if _, ok := declaredAPIPaths[path]; !ok {
			t.Errorf("path %q is in openapi.json but not declared by the server", path)
		}
	}
}
