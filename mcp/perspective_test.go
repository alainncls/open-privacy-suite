package main

import "testing"

func TestPerspective_LabelInactive(t *testing.T) {
	p := &Perspective{Active: false}
	if p.Label() != "" {
		t.Fatalf("expected empty label for inactive, got %q", p.Label())
	}
}

func TestPerspective_LabelNil(t *testing.T) {
	var p *Perspective
	if p.Label() != "" {
		t.Fatalf("expected empty label for nil, got %q", p.Label())
	}
}

func TestPerspective_Level1(t *testing.T) {
	p := &Perspective{Active: true, UserName: "Bob", Level: 1}
	got := p.Label()
	if got != "[PERSPECTIVE: Bob (approximate — read-only)]" {
		t.Fatalf("unexpected label: %q", got)
	}
}

func TestPerspective_Level2(t *testing.T) {
	p := &Perspective{Active: true, UserName: "Bob", Level: 2}
	got := p.Label()
	if got != "[IMPERSONATING: Bob]" {
		t.Fatalf("unexpected label: %q", got)
	}
}
