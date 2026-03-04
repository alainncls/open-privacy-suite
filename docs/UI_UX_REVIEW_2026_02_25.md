# UI/UX Review - Privacy Proxy

Date: 2026-02-25
Reviewer: Codex (GPT-5)
Scope: Full frontend (`/login`, `/link-wallet`, `/success`, `/disclosure`, `/admin/*`)
Source of truth: `styleguide.md` (Gateway style baseline)

## Summary

The frontend has a strong baseline alignment with the Gateway palette and component shapes, but there are several high-impact UX and consistency gaps in critical user journeys:

1. Wallet modal theming diverges from the styleguide.
2. Login polling can dead-end in an indefinite waiting state.
3. Admin routes are browsable without frontend auth gating.
4. Mobile layout pressure in RBAC/Compliance headers risks clipped controls.
5. Accessibility consistency is uneven for custom/raw buttons.

## Findings (Priority Order)

### H1 - Wallet connect modal does not follow Gateway style baseline

- Severity: High
- Category: Visual consistency / brand fidelity
- Evidence:
  - `main.tsx` configures RainbowKit with `darkTheme` and an indigo accent `#6366f1` ([frontend/src/main.tsx:36](/Users/max/github/work/gateway/privacy-proxy/frontend/src/main.tsx:36), [frontend/src/main.tsx:38](/Users/max/github/work/gateway/privacy-proxy/frontend/src/main.tsx:38)).
  - Styleguide requires primary purple `#8950FA` and light theme default ([styleguide.md:14](/Users/max/github/work/gateway/privacy-proxy/styleguide.md:14), [styleguide.md:330](/Users/max/github/work/gateway/privacy-proxy/styleguide.md:330)).
- Impact:
  - The wallet connect modal is a critical onboarding surface and currently breaks the visual system users see elsewhere.
- Recommendation:
  - Switch to RainbowKit `lightTheme` (or custom theme object) aligned to styleguide tokens.
  - Use `accentColor: '#8950FA'` and a matching neutral/light surface palette.
  - Replace `fontStack: 'system'` with a stack aligned to the styleguide typography.
- Estimated effort: S

### H2 - Login polling timeout can strand users with no recovery state

- Severity: High
- Category: Flow reliability
- Evidence:
  - Polling stops once `pollCount >= maxPolls` and returns without updating UI state ([frontend/src/pages/LoginPage.tsx:103](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LoginPage.tsx:103), [frontend/src/pages/LoginPage.tsx:107](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LoginPage.tsx:107)).
  - Waiting copy remains active (`"Waiting for wallet confirmation..."`) ([frontend/src/pages/LoginPage.tsx:213](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LoginPage.tsx:213)).
- Impact:
  - After ~5 minutes, users can be left in a non-terminal UI state with no explicit timeout guidance.
- Recommendation:
  - Transition to an explicit timeout error state when max polls is reached.
  - Show a clear CTA set: `Retry`, `Generate new QR`, and optional `Open Wallet` fallback.
  - Add telemetry/logging for timeout frequency.
- Estimated effort: M

### H3 - Admin shell is routable without frontend auth guard

- Severity: High
- Category: UX gating / journey coherence
- Evidence:
  - `/admin` routes are mounted directly without a route guard wrapper ([frontend/src/main.tsx:60](/Users/max/github/work/gateway/privacy-proxy/frontend/src/main.tsx:60)).
  - Existing UI tests explicitly skip redirect expectations because admin routes are not frontend-protected ([e2e/playwright/tests/ui/01-auth.spec.ts:102](/Users/max/github/work/gateway/privacy-proxy/e2e/playwright/tests/ui/01-auth.spec.ts:102), [e2e/playwright/tests/ui/01-auth.spec.ts:104](/Users/max/github/work/gateway/privacy-proxy/e2e/playwright/tests/ui/01-auth.spec.ts:104)).
- Impact:
  - Unauthenticated users can enter admin UI chrome and only fail later on API calls, producing a confusing and inconsistent experience.
- Recommendation:
  - Add a `RequireAuth` route wrapper for `/admin/*`.
  - Route unauthenticated users to `/login` with a reason and return URL.
  - Keep backend localhost/admin restrictions as defense in depth.
- Estimated effort: M

### M1 - RBAC/Compliance header layout is not mobile-resilient under org-scoped controls

- Severity: Medium
- Category: Responsive UX
- Evidence:
  - RBAC header uses a single-row `flex items-center justify-between` with a fixed-width org selector `w-[280px]` ([frontend/src/components/rbac/RBACManager.tsx:185](/Users/max/github/work/gateway/privacy-proxy/frontend/src/components/rbac/RBACManager.tsx:185), [frontend/src/components/rbac/RBACManager.tsx:221](/Users/max/github/work/gateway/privacy-proxy/frontend/src/components/rbac/RBACManager.tsx:221)).
  - Compliance header uses the same pattern and width ([frontend/src/components/compliance/ComplianceManager.tsx:147](/Users/max/github/work/gateway/privacy-proxy/frontend/src/components/compliance/ComplianceManager.tsx:147), [frontend/src/components/compliance/ComplianceManager.tsx:182](/Users/max/github/work/gateway/privacy-proxy/frontend/src/components/compliance/ComplianceManager.tsx:182)).
  - Global CSS forces `overflow-x: hidden`, which can mask clipped/interactable overflow ([frontend/src/index.css:46](/Users/max/github/work/gateway/privacy-proxy/frontend/src/index.css:46)).
- Impact:
  - On small viewports, scope controls are likely compressed/clipped, especially when org names are long.
- Recommendation:
  - Add responsive wrapping (`flex-col` below `md`) and full-width selector on small screens.
  - Avoid fixed 280px selectors in compact layouts; use `w-full md:w-[280px]`.
  - Replace hard clipping (`overflow-x: hidden`) with component-level overflow handling where needed.
- Estimated effort: M

### M2 - Focus and semantic accessibility are inconsistent on raw buttons

- Severity: Medium
- Category: Accessibility / interaction quality
- Evidence:
  - Several raw `<button>` elements use color hover states only and omit explicit focus rings:
    - [frontend/src/pages/LinkWalletPage.tsx:203](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LinkWalletPage.tsx:203)
    - [frontend/src/pages/LinkWalletPage.tsx:211](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LinkWalletPage.tsx:211)
    - [frontend/src/pages/LinkWalletPage.tsx:283](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LinkWalletPage.tsx:283)
    - [frontend/src/pages/SuccessPage.tsx:309](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/SuccessPage.tsx:309)
    - [frontend/src/App.tsx:39](/Users/max/github/work/gateway/privacy-proxy/frontend/src/App.tsx:39)
  - Styleguide explicitly requires visible focus states and semantic/ARIA usage ([styleguide.md:343](/Users/max/github/work/gateway/privacy-proxy/styleguide.md:343), [styleguide.md:344](/Users/max/github/work/gateway/privacy-proxy/styleguide.md:344)).
- Impact:
  - Keyboard users get inconsistent focus affordances; icon-only actions depend on `title`, which is weaker than explicit `aria-label`.
- Recommendation:
  - Standardize on shared `Button` primitive where possible.
  - For raw buttons, add `focus-visible` ring classes and `aria-label` for icon-only controls.
- Estimated effort: M

### M3 - Design token usage is fragmented by heavy inline hex usage

- Severity: Medium
- Category: Design system maintainability
- Evidence:
  - Theme tokens are defined centrally in CSS variables ([frontend/src/index.css:7](/Users/max/github/work/gateway/privacy-proxy/frontend/src/index.css:7)).
  - Frontend source currently contains 1,544 direct hex color literals (`rg -o '#[0-9A-Fa-f]{6}' frontend/src | wc -l`).
- Impact:
  - Visual drift and refactor cost increase as soon as brand tokens change.
  - Harder to enforce consistent dark/light adjustments or palette updates.
- Recommendation:
  - Enforce semantic token classes (`text-primary`, `bg-surface-card`, etc.) over direct hex values.
  - Add lint/style rule to prevent net-new inline hex colors outside token definition files.
  - Prioritize top-traffic pages first (`Login`, `LinkWallet`, `Success`, admin shell).
- Estimated effort: L (incremental), M (if done broadly in one pass)

### L1 - Silent failure paths reduce user feedback quality

- Severity: Low
- Category: UX feedback / trust
- Evidence:
  - Wallet unlink catch block is intentionally silent ([frontend/src/pages/LinkWalletPage.tsx:132](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/LinkWalletPage.tsx:132)).
  - Dashboard token-price preload also silently fails ([frontend/src/components/dashboard/TestRequestPanel.tsx:176](/Users/max/github/work/gateway/privacy-proxy/frontend/src/components/dashboard/TestRequestPanel.tsx:176)).
- Impact:
  - Users/admins can’t distinguish success from silent backend/network failure in these paths.
- Recommendation:
  - Add lightweight inline toasts/messages for actionable failures.
  - Keep non-blocking behavior where appropriate, but communicate degraded state.
- Estimated effort: S

### L2 - Parallel disclosure admin implementations increase UX drift risk

- Severity: Low
- Category: Product consistency / maintainability
- Evidence:
  - Routed page uses `AdminDisclosureDashboard` ([frontend/src/main.tsx:24](/Users/max/github/work/gateway/privacy-proxy/frontend/src/main.tsx:24), [frontend/src/main.tsx:82](/Users/max/github/work/gateway/privacy-proxy/frontend/src/main.tsx:82)).
  - A separate `DisclosureAdminPage` implementation still exists ([frontend/src/pages/admin/DisclosureAdminPage.tsx:23](/Users/max/github/work/gateway/privacy-proxy/frontend/src/pages/admin/DisclosureAdminPage.tsx:23)).
- Impact:
  - Duplicate admin experiences can diverge and create inconsistent future UI behavior.
- Recommendation:
  - Consolidate to one disclosure admin experience and remove or archive the unused implementation.
- Estimated effort: S

## Quick Wins (1-3 days)

1. Align RainbowKit theme with styleguide tokens and light surfaces.
2. Add explicit login polling timeout state + retry CTA.
3. Add focus-visible ring classes and `aria-label` to icon-only raw buttons in auth/success flows.
4. Make RBAC/Compliance headers stack on small screens with responsive selector widths.

## Systemic Improvements (1-2 sprints)

1. Introduce semantic design token utilities and phase out direct hex usage.
2. Add a shared `RequireAuth` wrapper for all admin routes.
3. Add UI regression tests for timeout/error states and small-screen org-scoped headers.

## Validation Notes

- Direct non-browser fetches to `https://gateway.fm` returned HTTP 403 during review; style decisions were therefore evaluated against the local canonical styleguide (`styleguide.md`) plus publicly accessible Gateway brand guidance pages.
- Frontend lint was executed and failed with pre-existing issues unrelated to this review deliverable (`90 problems`, including test-file lint errors and hook dependency warnings).
- No repo code was modified as part of this review other than this report file.
