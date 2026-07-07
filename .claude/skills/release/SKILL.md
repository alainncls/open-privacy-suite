---
name: release
description: Draft and publish a GitHub release for privacy-proxy with a consistent, operator-focused notes format. Use when the user asks to "release", "cut a release", "draft release notes", or "publish vX.Y.Z".
---

# Release

Produce a GitHub Release for `gateway-fm/privacy-proxy` whose notes are **operator-focused, precise, and short** — someone deploying the upgrade reads it in under two minutes and knows exactly what changed, what they MUST do, and how to verify it worked.

Never paste Linear descriptions or raw commit subjects. Judge what actually matters (business logic, client-visible features, security) and say it in plain language. Everything below is derived from the **code/diff**, not from tickets.

## 0. Inputs

- **Target tag** (e.g. `v0.12.0`). If not given, infer the next semver from the latest release + the size/nature of changes and **confirm with the user** before proceeding.
- **Range** = `<previous tag>..<target>`.
  - Previous tag: `gh release view --repo gateway-fm/privacy-proxy --json tagName -q .tagName` (latest), or `git describe --tags --abbrev=0`.
  - If the target tag doesn't exist yet, use `<previous tag>..HEAD` on `main`.

## 1. Gather the actual changes (read the evidence — don't guess)

- **Merged PRs in range:** `gh pr list --repo gateway-fm/privacy-proxy --state merged --base main --limit 300 --json number,title,mergedAt,labels`, keep those merged after the previous tag's date; cross-check with `git log --oneline <range>`.
- **Migrations:** `git diff --name-status <range> -- internal/db/migrations internal/db/migrations_audit`. Open each new `*.sql`; state in one line WHAT it changes and whether it's expand-only (safe/auto) or needs a manual/ordered step or a separate DB.
- **Env & config surface** — added / removed / renamed / newly-required keys and secrets:
  - `git diff <range> -- .env.example config.example.toml`
  - new required `getEnv*(...)` reads in `internal/config/*.go`
  - additions to `secretKeys` in `internal/config/file.go` (secret-class → MUST be injected via the secret store; rejected from the TOML config file)
- **Breaking / behavior changes:** scan PR titles + labels + diffs for renamed routes, changed response shapes, tightened auth gates, changed defaults.

## 2. Classify — keep only what an operator or the business cares about

For each change decide: **client-visible feature**, **business-logic change**, **security fix**, **breaking / migration / new env**, or **internal noise**. Drop refactors, test-only, doc-only, and dependency bumps from Highlights (a dep bump only appears if it's a security CVE). A **security fix** or a **required env / migration** is ALWAYS surfaced, even when the code change is tiny.

## 3. Write the notes — this exact structure, terse

```
## Highlights
- 3–7 bullets, plain operator/business language, value first (not the ticket id).
  Prefix security fixes with 🔒.
  e.g. "Per-org compliance currency — each org values transfers in its own currency (was cluster-wide)."

## ⚠️ Action required on upgrade
- **New required env:** `FOO_URL` — what it is; what breaks if unset.
- **Migrations:** N new (0xx–0yy), expand-only, applied automatically on startup / `make db-migrate`. Call out anything needing ordering, a separate DB, or a manual step.
- **Secrets:** `BAR_KEY` is secret-class — inject via the secret store, not the config file.
(If truly nothing: "None — drop-in upgrade.")

## Incompatibilities / breaking
- Changed behavior, response shapes, tightened gates. "None." if none.

## Deprecations
- Envs/configs still honored but going away, and what to move to. OMIT this section entirely if none.

## Verify after deploy
- 2–4 concrete checks: an endpoint that should now behave a certain way, a migration row/column present, a specific log line or metric. Precise enough for infra to run without asking.
```

Rules: no section longer than it needs to be; omit optional empty sections (Deprecations) rather than writing "None"; Highlights are business-first, not a changelog dump.

## 4. Confirm, then publish

- Show the drafted notes to the user. **Do NOT publish unprompted.**
- On approval, create as a **draft** first:
  `gh release create <tag> --repo gateway-fm/privacy-proxy --title "<tag>" --notes-file <file> --draft --target main`
  Share the draft URL.
- Publish only on an explicit "publish": `gh release edit <tag> --repo gateway-fm/privacy-proxy --draft=false`.
- **Heads-up:** pushing the `v*` tag / publishing triggers `deploy-docs.yml` (docs-site republish, version badge = the tag). Make sure this release's docs are already merged to `main` first.

## Notes

- Migrations are **expand-only by policy** (additive) — safe to auto-apply, no downtime; still list them.
- If the release is gated on manual acceptance (a current `ACCEPTANCE-*.local.md` exists and isn't signed off), say the release is **pending sign-off** and stop at the draft — don't cut the tag.
