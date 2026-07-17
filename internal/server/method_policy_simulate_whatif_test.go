package server

import (
	"testing"

	"privacy-proxy/internal/rbac"
)

// TestHypotheticalCaptures_WhatIf proves the what-if simulate path: admin-supplied
// parties (no DB read) drive the SAME SimulateReader capture eval as a live
// record, so a freshly authored policy can be validated before any record exists.
func TestHypotheticalCaptures_WhatIf(t *testing.T) {
	const policy = `{"records":{"payment":{
      "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
        "remember":{"payer":{"source":"sender","merge":"set_once"},"audience":{"source":"visibleTo","merge":"union"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer","audience"]}],"onNoRecord":"deny","else":"deny"}]
    }}}`
	doc, err := rbac.ParseMethodPolicyDocument([]byte(policy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	rows := hypotheticalCaptures(map[string][]string{
		"payer":    {"did:test:alice"},
		"audience": {"did:test:charlie"},
	})
	load := func(string) ([]rbac.CapturedField, error) { return rows, nil }

	// A supplied party → allow (same eval a live record would give).
	for _, did := range []string{"did:test:alice", "did:test:charlie"} {
		res, gated, err := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity(did, nil), load)
		if err != nil || !gated {
			t.Fatalf("%s: gated=%v err=%v", did, gated, err)
		}
		if !res.Allow {
			t.Fatalf("%s: expected allow", did)
		}
	}

	// A caller not among the supplied parties → deny.
	if res, _, _ := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity("did:test:diana", nil), load); res.Allow {
		t.Fatal("diana (not a supplied party) must be denied")
	}

	// Merge is forced to "union", so multiple values in one field never trip
	// set-once poisoning — a what-if run tests admission, not accumulation.
	multi := func(string) ([]rbac.CapturedField, error) {
		return hypotheticalCaptures(map[string][]string{"payer": {"did:test:alice", "did:test:bob"}}), nil
	}
	res, _, _ := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity("did:test:bob", nil), multi)
	if res.Poisoned {
		t.Fatal("what-if rows must not trip set-once poisoning")
	}
	if !res.Allow {
		t.Fatal("bob is among the supplied payer values → allow")
	}
}

// TestSimulateSurfaces_FullLinkage proves the simulator reports the whole
// capture→reader→events→tx wiring: for a captured party the reader ALLOWS and
// the additive event/tx ADMIT; for a non-party the reader DENIES and the
// additive surfaces ABSTAIN (they never admit an outsider on their own).
func TestSimulateSurfaces_FullLinkage(t *testing.T) {
	const policy = `{"records":{"payment":{
      "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
        "remember":{"payer":{"source":"sender","merge":"set_once"},"audience":{"source":"visibleTo","merge":"union"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer","audience"]}],"onNoRecord":"deny","else":"deny"}],
      "events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},
        "allow":[{"callerIn":["payer","audience"]}]}],
      "transactions":[{"method":"processPayment(string,uint8)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer","audience"]}]}]
    }}}`
	doc, err := rbac.ParseMethodPolicyDocument([]byte(policy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	load := func(string) ([]rbac.CapturedField, error) {
		return hypotheticalCaptures(map[string][]string{"payer": {"did:test:alice"}, "audience": {"did:test:charlie"}}), nil
	}

	byKind := func(vs []rbac.SurfaceVerdict) map[string]rbac.SurfaceVerdict {
		m := map[string]rbac.SurfaceVerdict{}
		for _, v := range vs {
			m[v.Kind] = v
		}
		return m
	}

	// A captured party: reader allow + additive surfaces admit.
	party, err := doc.SimulateSurfaces(rbac.NewCallerIdentity("did:test:alice", nil), load)
	if err != nil {
		t.Fatalf("simulate surfaces: %v", err)
	}
	if len(party) != 3 {
		t.Fatalf("want 3 surfaces (reader+event+tx), got %d", len(party))
	}
	m := byKind(party)
	if m["reader"].Result != "allow" || m["reader"].Additive {
		t.Fatalf("reader: want allow/authoritative, got %+v", m["reader"])
	}
	if m["event"].Result != "admit" || !m["event"].Additive {
		t.Fatalf("event: want admit/additive, got %+v", m["event"])
	}
	if m["transaction"].Result != "admit" || !m["transaction"].Additive {
		t.Fatalf("transaction: want admit/additive, got %+v", m["transaction"])
	}

	// A non-party: reader deny + additive surfaces abstain (never self-admit).
	out, _ := doc.SimulateSurfaces(rbac.NewCallerIdentity("did:test:eve", nil), load)
	for _, v := range out {
		if v.Kind == "reader" && v.Result != "deny" {
			t.Fatalf("outsider reader: want deny, got %q", v.Result)
		}
		if v.Kind != "reader" && v.Result != "abstain" {
			t.Fatalf("outsider %s: want abstain, got %q", v.Kind, v.Result)
		}
	}
}
