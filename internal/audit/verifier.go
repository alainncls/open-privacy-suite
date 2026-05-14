package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ChainName identifies which audit chain the verifier walks. Constants
// match db.ChainNameAccessLogs / db.ChainNameRBACAuditLog. We redeclare
// them as audit-package constants to avoid the verifier importing the
// db package — the verifier reads via sql.DB directly so the same code
// can serve both the in-process scheduled worker and the
// privacy-cli subcommand.
type ChainName string

const (
	ChainAccessLogs   ChainName = "access_logs"
	ChainRBACAuditLog ChainName = "rbac_audit_log"
)

// Result captures one chain walk's outcome.
//
// OK true iff every row in scan order chained correctly back to the
// seed. False on the first mismatch; the remaining FirstMismatch*
// fields locate the offending row.
//
// ScannedRows counts the rows the verifier read regardless of outcome
// (rows-checked, not rows-passing). NullHashRows counts rows whose
// entry_hash is NULL — surfaced separately because they typically mean
// "writer crashed before storing the hash" (legacy / pre-RD-858) and
// not "tampering" but the verifier still flags them so the operator
// can decide.
type Result struct {
	Chain               ChainName
	OK                  bool
	ScannedRows         int64
	NullHashRows        int64
	Seed                string
	TailHash            string
	FirstMismatchID     int64
	FirstMismatchHash   string // stored hash on the offending row
	FirstMismatchExpect string // hash the verifier recomputed
	FirstMismatchTime   time.Time
	FirstMismatchReason string
	StartedAt           time.Time
	FinishedAt          time.Time
}

// Reason strings for FirstMismatchReason. Kept as exported constants
// so callers (notifier, CLI, tests) can switch on them without string-
// matching error prose.
const (
	ReasonHashMismatch    = "hash_mismatch"
	ReasonNullEntryHash   = "null_entry_hash"
	ReasonRowReadFailed   = "row_read_failed"
	ReasonSeedReadFailed  = "seed_read_failed"
	ReasonAnchorMismatch  = "anchor_mismatch"
	ReasonUnknownFormat   = "unknown_hash_format_version"
	ReasonContextCanceled = "context_canceled"
)

// SeedReader retrieves the chain seed for a given chain name. The
// production implementation is db.GetLatestAccessLogHash /
// GetLatestRBACAuditLogHash; tests can stub it.
type SeedReader interface {
	GetLatestAccessLogHash(ctx context.Context) (string, error)
	GetLatestRBACAuditLogHash(ctx context.Context) (string, error)
}

// Verifier walks an audit hash chain row-by-row, recomputing each
// row's hash and comparing it to the stored entry_hash. The first
// mismatch is reported in Result; the walk stops there.
//
// The verifier is intentionally **read-only** and DB-driver-agnostic:
// it accepts *sql.DB so the same code runs both inside the proxy
// (scheduled worker, admin API) and inside privacy-cli (auditor's
// command-line tool against a separate audit-role connection).
type Verifier struct {
	conn   *sql.DB
	seedFn SeedReader
}

// NewVerifier constructs a Verifier. conn must point at a database
// where the audit schema has been migrated to at least migration 057
// (rbac_audit_log entry_hash column). seedFn supplies the chain seed
// — in production this is the *db.DB itself.
func NewVerifier(conn *sql.DB, seedFn SeedReader) *Verifier {
	return &Verifier{conn: conn, seedFn: seedFn}
}

// Verify walks the named chain and returns a Result. ctx cancels the
// walk between rows; long chains can take seconds.
func (v *Verifier) Verify(ctx context.Context, chain ChainName) (*Result, error) {
	switch chain {
	case ChainAccessLogs:
		return v.verifyAccessLogs(ctx)
	case ChainRBACAuditLog:
		return v.verifyRBACAuditLog(ctx)
	default:
		return nil, fmt.Errorf("unknown chain: %q", chain)
	}
}

func (v *Verifier) verifyAccessLogs(ctx context.Context) (*Result, error) {
	res := &Result{Chain: ChainAccessLogs, StartedAt: time.Now().UTC(), OK: true}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	seed, err := v.seedFn.GetLatestAccessLogHash(ctx)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, fmt.Errorf("seed: %w", err)
	}
	// Resolve the starting prev hash. If the access_logs table has any
	// rows, the seed corresponds to the LAST entry — we don't want to
	// re-verify backwards from the tail; instead start from the
	// audit_chain_anchor (or empty) and walk forward.
	startPrev, anchorID, err := v.startingPrev(ctx, ChainAccessLogs)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, err
	}
	res.Seed = startPrev

	rows, err := v.conn.QueryContext(ctx,
		`SELECT id, external_id, method, status_code, COALESCE(response_status, status_code), ip_address, COALESCE(correlation_id, ''),
			COALESCE(request_params::text, ''), created_at, entry_hash, hash_format_version
		 FROM access_logs
		 WHERE id > $1
		 ORDER BY id ASC`,
		anchorID,
	)
	if err != nil {
		return nil, fmt.Errorf("query access_logs: %w", err)
	}
	defer rows.Close()

	prev := startPrev
	for rows.Next() {
		if ctx.Err() != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonContextCanceled
			return res, ctx.Err()
		}
		var (
			id, statusCode, responseStatus int64
			externalID, method, ipAddress  string
			correlationID, paramsDigest    string
			createdAt                      time.Time
			entryHash                      sql.NullString
			hashFormatVersion              int
		)
		if err := rows.Scan(&id, &externalID, &method, &statusCode, &responseStatus, &ipAddress,
			&correlationID, &paramsDigest, &createdAt, &entryHash, &hashFormatVersion); err != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonRowReadFailed
			res.FirstMismatchID = id
			return res, fmt.Errorf("scan access_logs row: %w", err)
		}
		res.ScannedRows++

		if !entryHash.Valid || entryHash.String == "" {
			res.NullHashRows++
			if res.OK {
				res.OK = false
				res.FirstMismatchReason = ReasonNullEntryHash
				res.FirstMismatchID = id
				res.FirstMismatchTime = createdAt
			}
			// Cannot advance the chain past a NULL-hash row — its
			// content can't be verified, and the next row's prev hash
			// would be unknown. Stop the walk; the caller decides
			// whether to continue from a manually-supplied anchor.
			break
		}

		if hashFormatVersion != 2 {
			res.OK = false
			res.FirstMismatchReason = ReasonUnknownFormat
			res.FirstMismatchID = id
			res.FirstMismatchTime = createdAt
			res.FirstMismatchHash = entryHash.String
			return res, nil
		}

		content := AccessLogChainContentV2(id, externalID, method, ipAddress, int(statusCode), int(responseStatus), createdAt, correlationID, paramsDigest)
		expect := computeChainHash(prev, content)
		if expect != entryHash.String {
			res.OK = false
			res.FirstMismatchReason = ReasonHashMismatch
			res.FirstMismatchID = id
			res.FirstMismatchHash = entryHash.String
			res.FirstMismatchExpect = expect
			res.FirstMismatchTime = createdAt
			return res, nil
		}
		prev = entryHash.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access_logs: %w", err)
	}
	res.TailHash = prev
	// Cross-check: the tail we computed must match what the seedFn
	// returned (the writer's view of the chain head). A mismatch here
	// means writer and verifier disagree on the chain state — usually a
	// row written after our snapshot, which is fine; only flag when
	// the seed hash is provably older than the rows we scanned (i.e.,
	// seed != tail AND we scanned at least one row).
	if res.OK && seed != "" && seed != prev {
		res.FirstMismatchReason = ReasonAnchorMismatch
		// Not necessarily a failure — seed lag is normal. Record but
		// keep OK = true.
	}
	return res, nil
}

func (v *Verifier) verifyRBACAuditLog(ctx context.Context) (*Result, error) {
	res := &Result{Chain: ChainRBACAuditLog, StartedAt: time.Now().UTC(), OK: true}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	seed, err := v.seedFn.GetLatestRBACAuditLogHash(ctx)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, fmt.Errorf("seed: %w", err)
	}
	startPrev, anchorID, err := v.startingPrev(ctx, ChainRBACAuditLog)
	if err != nil {
		res.OK = false
		res.FirstMismatchReason = ReasonSeedReadFailed
		return res, err
	}
	res.Seed = startPrev

	rows, err := v.conn.QueryContext(ctx,
		`SELECT id, COALESCE(actor_external_id, ''), action, resource_type, COALESCE(resource_id::text, ''),
			COALESCE(resource_name, ''), COALESCE(org_id::text, ''), COALESCE(ip_address, ''),
			created_at, COALESCE(old_value::text, ''), COALESCE(new_value::text, ''),
			entry_hash, hash_format_version
		 FROM rbac_audit_log
		 WHERE id > $1
		 ORDER BY id ASC`,
		anchorID,
	)
	if err != nil {
		return nil, fmt.Errorf("query rbac_audit_log: %w", err)
	}
	defer rows.Close()

	prev := startPrev
	for rows.Next() {
		if ctx.Err() != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonContextCanceled
			return res, ctx.Err()
		}
		var (
			id                                                                                 int64
			actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress string
			createdAt                                                                          time.Time
			oldValue, newValue                                                                 string
			entryHash                                                                          sql.NullString
			hashFormatVersion                                                                  int
		)
		if err := rows.Scan(&id, &actorExternalID, &action, &resourceType, &resourceID,
			&resourceName, &orgID, &ipAddress, &createdAt, &oldValue, &newValue,
			&entryHash, &hashFormatVersion); err != nil {
			res.OK = false
			res.FirstMismatchReason = ReasonRowReadFailed
			res.FirstMismatchID = id
			return res, fmt.Errorf("scan rbac_audit_log row: %w", err)
		}
		res.ScannedRows++

		if !entryHash.Valid || entryHash.String == "" {
			res.NullHashRows++
			if res.OK {
				res.OK = false
				res.FirstMismatchReason = ReasonNullEntryHash
				res.FirstMismatchID = id
				res.FirstMismatchTime = createdAt
			}
			break
		}

		if hashFormatVersion != 1 {
			res.OK = false
			res.FirstMismatchReason = ReasonUnknownFormat
			res.FirstMismatchID = id
			res.FirstMismatchTime = createdAt
			res.FirstMismatchHash = entryHash.String
			return res, nil
		}

		content := RBACAuditChainContentV1(id, actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress, createdAt, oldValue, newValue)
		expect := computeChainHash(prev, content)
		if expect != entryHash.String {
			res.OK = false
			res.FirstMismatchReason = ReasonHashMismatch
			res.FirstMismatchID = id
			res.FirstMismatchHash = entryHash.String
			res.FirstMismatchExpect = expect
			res.FirstMismatchTime = createdAt
			return res, nil
		}
		prev = entryHash.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rbac_audit_log: %w", err)
	}
	res.TailHash = prev
	if res.OK && seed != "" && seed != prev {
		res.FirstMismatchReason = ReasonAnchorMismatch
	}
	return res, nil
}

// startingPrev returns the (prev_hash, anchor_id) the walk should
// begin from. If audit_chain_anchor has a row for the chain (rows have
// been pruned), prev is the anchor hash and anchor_id is the last
// pruned id — we start from id > anchor_id. Otherwise prev = "" and
// anchor_id = 0 (walk from the very first row).
func (v *Verifier) startingPrev(ctx context.Context, chain ChainName) (string, int64, error) {
	var prev sql.NullString
	var anchorID sql.NullInt64
	err := v.conn.QueryRowContext(ctx,
		`SELECT last_pruned_entry_hash, last_pruned_id FROM audit_chain_anchor WHERE chain_name = $1`,
		string(chain),
	).Scan(&prev, &anchorID)
	if err == nil {
		return prev.String, anchorID.Int64, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return "", 0, fmt.Errorf("read audit_chain_anchor for %s: %w", chain, err)
}

// AccessLogChainContentV2 mirrors db.AccessLogChainContent but lives
// in the audit package so the verifier doesn't import db (which would
// create a cycle: db already imports audit via RBACAuditChain). Format
// MUST match db.AccessLogChainContent byte-for-byte.
func AccessLogChainContentV2(id int64, externalID, method, ipAddress string, statusCode, responseStatus int, createdAt time.Time, correlationID, paramsDigest string) string {
	return fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
		id, externalID, method, ipAddress, statusCode, responseStatus,
		createdAt.UTC().Format(time.RFC3339Nano),
		correlationID,
		paramsDigest,
	)
}

// RBACAuditChainContentV1 mirrors db.buildRBACAuditContent for v1 rows.
// The format MUST match byte-for-byte.
func RBACAuditChainContentV1(id int64, actorExternalID, action, resourceType, resourceID, resourceName, orgID, ipAddress string, createdAt time.Time, oldValue, newValue string) string {
	return fmt.Sprintf("v1|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		id,
		actorExternalID,
		action,
		resourceType,
		resourceID,
		resourceName,
		orgID,
		ipAddress,
		createdAt.UTC().Format(time.RFC3339Nano),
		oldValue,
		newValue,
	)
}

func computeChainHash(prev, content string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}
