package rbac

// LogEventRuleMode is the tri-state resolution of a viewer's event_rules for a
// contract, normalised so both the RPC and explorer layers describe it the
// same way.
type LogEventRuleMode int

const (
	// LogEventRulesDeny — nil/empty event_rules ⇒ deny-all (the default).
	LogEventRulesDeny LogEventRuleMode = iota
	// LogEventRulesWildcard — event_rules: "*" ⇒ every event passes.
	LogEventRulesWildcard
	// LogEventRulesAllowlist — an explicit set of allowed topic0s (each
	// optionally carrying param rules).
	LogEventRulesAllowlist
)

// LogEmitterFacts are the normalised, per-(viewer, log) inputs to the shared
// log-visibility decision. Each layer resolves these from its own data model
// and calls DecideLogEmitterAccess, so the admit/deny decision has a single
// source of truth and the RPC filter (rbac.FilterEventLogs) and the explorer
// redactor (explorer.RedactionEngine.RedactLogsWithOpts) cannot drift apart.
// (RD-1214 — completes RD-887; the symmetry invariant becomes an
// implementation, not a convention.)
type LogEmitterFacts struct {
	// IsAdmin: the viewer holds the admin claim in the emitting contract's
	// owning org (per-contract, org-scoped). Bypasses every gate below.
	IsAdmin bool

	// Unlocked: the emitter has `allow_visibleto_unlock` set, the viewer is
	// eligible, AND the viewer is in the tx's visibleTo set (RD-874). This is
	// the ONLY path by which visibleTo becomes a standalone grant; it bypasses
	// every gate below.
	Unlocked bool

	// HasGrant: the viewer holds a contract_grant on the emitter — the
	// load-bearing grant-eligibility signal (RD-874 / RD-1208). RPC:
	// perms.GetContractAccess(addr) != nil. Explorer: the emitter resolves to
	// VisibilityFull for the viewer.
	HasGrant bool

	// ABIResolvable: the emitter has a resolvable ABI, OR the ABI gate is
	// disabled for this call. When false the log is dropped — without an ABI,
	// non-indexed address params embedded in `data` cannot be decoded and
	// redacted (RD-875 / RD-889).
	ABIResolvable bool

	// DynamicPayloadDropped: the matched event declares a dynamic non-indexed
	// param AND the contract is not opted out of the drop gate (M15). Only ever
	// set when HasTopic0 is true.
	DynamicPayloadDropped bool

	// IsParticipant: the viewer is a from/to participant of the log's tx
	// (RD-1162). Grant-bounded — only admits together with HasGrant.
	IsParticipant bool

	// InVisibleTo: the viewer's DID is listed in the tx's (ordinary,
	// non-unlock) visibleTo set. Additive only: it extends the param-rule
	// fallback for a grant holder, never a standalone grant (RD-1208).
	InVisibleTo bool

	// Rules: the viewer's event_rules resolution for the emitter.
	Rules LogEventRuleMode

	// HasTopic0: the log carries a topic0 (i.e. is not an anonymous event).
	HasTopic0 bool

	// EventAllowed (allowlist mode only): topic0 matches an allowlisted rule
	// AND that rule's param constraints are satisfied (or it has none).
	EventAllowed bool

	// Topic0Allowlisted (allowlist mode only): topic0 matches some allowlisted
	// rule, ignoring its param constraints. Drives the visibleTo param-rule
	// fallback.
	Topic0Allowlisted bool
}

// DecideLogEmitterAccess is the single source of truth for "may this viewer see
// this log?", shared by the RPC filter and the explorer redactor. It returns
// true to admit the log, false to drop it. The gate order is identical for both
// layers:
//
//  1. admin / visibleTo-unlock  → admit  (bypass everything)
//  2. no resolvable ABI         → drop   (RD-875/889 embedded-address protection)
//  3. M15 dynamic payload       → drop   (embedded-address protection)
//  4. participant AND grant     → admit  (RD-1162, grant-bounded)
//  5. no grant                  → drop   (RD-874/RD-1208 — grant eligibility is load-bearing)
//  6. event_rules:
//     wildcard                → admit
//     allowlist               → admit iff topic0 is allowlisted AND
//     (param rules satisfied OR viewer in visibleTo); else drop
//     deny-all                → drop
//
// Two invariants are structural here (not left to each caller):
//   - The embedded-address protections (2, 3) are never relaxed by
//     participation or visibleTo.
//   - The grant gate (5) sits before event_rules and before the
//     participant/visibleTo relaxations, so neither can admit a no-grant
//     emitter — the class of leak RD-1208 closed.
func DecideLogEmitterAccess(f LogEmitterFacts) bool {
	if f.IsAdmin || f.Unlocked {
		return true
	}
	if !f.ABIResolvable {
		return false
	}
	if f.DynamicPayloadDropped {
		return false
	}
	if f.IsParticipant && f.HasGrant {
		return true
	}
	if !f.HasGrant {
		return false
	}
	switch f.Rules {
	case LogEventRulesWildcard:
		return true
	case LogEventRulesAllowlist:
		if !f.HasTopic0 {
			return false
		}
		if f.EventAllowed {
			return true
		}
		return f.Topic0Allowlisted && f.InVisibleTo
	default: // LogEventRulesDeny
		return false
	}
}
