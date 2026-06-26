package server

// Curated denial-reason codes (RD-1137).
//
// These are STABLE, tenant-facing identifiers for why a request was denied.
// They are written to access_logs.denial_reason (always, for the org-scoped
// admin Access Logs panel — RD-1137 Part B) and, for opt-in verbose callers,
// returned on the wire (RD-1137 Part A).
//
// Rules:
//   - Stable: external automations may switch on these once Part A ships, so
//     treat the string values as an API contract — add, don't rename.
//   - Tenant-safe: a code may only describe a fact about the caller's OWN
//     request. Codes that could reveal another tenant's state are marked
//     ORACLE-SENSITIVE below; the wire path (Part A) collapses those to a
//     single generic value. The access-log column always stores the precise
//     code (the admin view is already org-scoped, so it's safe there).
//   - Never derived from raw internal/DB error text.
const (
	// ReasonAuthRequired: no/invalid token on a method that requires auth.
	ReasonAuthRequired = "auth_required"
	// ReasonMethodNotAllowed: the caller's group(s) don't permit this method
	// or contract (RBAC entry-point deny).
	ReasonMethodNotAllowed = "method_not_allowed"
	// ReasonSenderNotLinked: a user-supplied `from` is not one of the caller's
	// linked EOAs. A fact about the caller's own request — safe to surface.
	ReasonSenderNotLinked = "sender_not_linked"
	// ReasonInvalidRequestShape: malformed params the proxy validates before
	// tracing (bad block tag, non-hex to/from, etc.).
	ReasonInvalidRequestShape = "invalid_request_shape"
	// ReasonCrossOrg: a traced call touched a contract owned by another org or
	// an unregistered (private-by-default) address. ORACLE-SENSITIVE — reveals
	// that some address is/ isn't registered elsewhere; the wire path collapses
	// it (Part A). Stored precisely in the log for the org-scoped admin view.
	ReasonCrossOrg = "cross_org"
	// ReasonTraceDepthExceeded: the trace exceeded max depth, so same-org could
	// not be proven; failed closed.
	ReasonTraceDepthExceeded = "trace_depth_exceeded"
	// ReasonTracingUnavailable: the upstream tracer errored / returned nil, so
	// the request failed closed.
	ReasonTracingUnavailable = "tracing_unavailable"
	// ReasonDeployClaimRequired: a debug_trace* / runtime-create path that
	// requires the deploy (or admin) claim.
	ReasonDeployClaimRequired = "deploy_claim_required"
	// ReasonComplianceBlocked: a travel-rule / sanctions check blocked the tx.
	ReasonComplianceBlocked = "compliance_blocked"
	// ReasonRateLimited: request- or daily-rate limit hit (429).
	ReasonRateLimited = "rate_limited"
	// ReasonConcurrencyLimited: per-user in-flight concurrency cap hit (429).
	ReasonConcurrencyLimited = "concurrency_limited"
	// ReasonUpstreamError: the upstream node was unreachable / returned a
	// transport error (502).
	ReasonUpstreamError = "upstream_error"
	// ReasonInternalError: an internal failure (500) — generic by construction.
	ReasonInternalError = "internal_error"
)
