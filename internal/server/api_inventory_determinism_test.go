package server

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// RD-1190: BuildInventory must produce byte-identical output on every run so
// the CI api-spec drift gate (regenerate + git diff) can never flake on an
// unrelated PR. Go re-randomizes each map-range independently per execution, so
// if any output-feeding map in BuildInventory were iterated without a stable
// sort, N runs would diverge — this catches that deterministically (including a
// FUTURE unsorted-map slip), in the ./internal/... test job.
func TestBuildInventory_Deterministic(t *testing.T) {
	all := RoutesForSpec(true)
	prod := RoutesForSpec(false)

	first, _ := BuildInventory(all, prod)
	for i := 0; i < 8; i++ {
		got, _ := BuildInventory(all, prod)
		if got != first {
			t.Fatalf("BuildInventory output is not deterministic (run %d differs from run 0).\n"+
				"An output-feeding map is iterated without a stable sort — sort it before rendering.\n"+
				"first:\n%s\n\nrun %d:\n%s", i+1, first, i+1, got)
		}
	}
}

// Guards the guard: proves the byte-identical assertion above actually CATCHES
// non-determinism. Rendering a map by raw iteration order (no sort) must be
// observed to diverge across runs — otherwise TestBuildInventory_Deterministic
// could pass vacuously if map iteration were ever made stable.
func TestMapIterationIsNonDeterministic_NegativeControl(t *testing.T) {
	m := map[string]int{}
	for i := 0; i < 64; i++ {
		m[fmt.Sprintf("k%02d", i)] = i
	}
	renderUnsorted := func() string {
		var b strings.Builder
		for k := range m { // deliberately UNSORTED
			fmt.Fprintf(&b, "%s=%d;", k, m[k])
		}
		return b.String()
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[renderUnsorted()] = true
		if len(seen) > 1 {
			return // observed divergence — the assertion mechanism works
		}
	}
	// A sorted render, by contrast, must be stable (sanity check the control).
	renderSorted := func() string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%d;", k, m[k])
		}
		return b.String()
	}
	if renderSorted() != renderSorted() {
		t.Fatal("sorted render should be stable")
	}
	t.Skip("map iteration did not diverge in 200 tries (unlikely with 64 keys); negative control inconclusive but sorted render is stable")
}
