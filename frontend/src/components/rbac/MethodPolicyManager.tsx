import { useEffect, useMemo, useState } from "react";
import { rbacApi } from "@/api/rbac";
import type { Contract, MethodPolicyDocument } from "@/types/rbac";
import {
  parseAbiFunctions,
  parseAbiEvents,
  functionsWithKeyableParam,
  eventsWithKeyableParam,
  decompileWizard,
  renderPolicy,
  wizardStarterRecord,
  type AbiFnInfo,
  type WizardState,
} from "@/lib/methodPolicy";
import { MethodPolicyWizard } from "./MethodPolicyWizard";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { ShieldAlert, ShieldCheck, Check, Loader2, Info, FlaskConical } from "lucide-react";

interface Props {
  orgId: string;
  contractAddress: string;
  contractAbi?: string;
  initialPolicy?: MethodPolicyDocument | null;
  isReadonlyAdmin?: boolean;
  // Propagate the saved/cleared policy to the parent so its cached contract
  // (and a reopened settings dialog) reflect the new state — mirrors the
  // visibleTo-unlock toggle (RD-1075). Without this, "Clear policy" updates
  // only this component's local state and the stale policy reappears on reopen.
  onContractUpdated?: (contract: Contract) => void;
}

type Mode = "none" | "wizard" | "json" | "simulate";

export function MethodPolicyManager({ orgId, contractAddress, contractAbi, initialPolicy, isReadonlyAdmin, onContractUpdated }: Props) {
  const [policy, setPolicy] = useState<MethodPolicyDocument | null>(initialPolicy ?? null);
  const [mode, setMode] = useState<Mode>("none");
  const [w, setW] = useState<WizardState>({ records: [] });
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const fns = useMemo(() => parseAbiFunctions(contractAbi), [contractAbi]);
  const keyableFns = useMemo(() => functionsWithKeyableParam(fns), [fns]);
  const abiEvents = useMemo(() => parseAbiEvents(contractAbi), [contractAbi]);
  const keyableEvents = useMemo(() => eventsWithKeyableParam(abiEvents), [abiEvents]);
  // The gated readers the simulator can test — the policy's access methods.
  const readerMethods = useMemo(
    () => (policy ? [...new Set(Object.values(policy.records ?? {}).flatMap((r) => (r.access ?? []).map((a) => a.method)))] : []),
    [policy],
  );
  // The record's captured field names (payer/payee/audience…) — the what-if
  // simulator generates one hypothetical-party input per field.
  const captureFields = useMemo(
    () => (policy ? [...new Set(Object.values(policy.records ?? {}).flatMap((r) => (r.capture ?? []).flatMap((c) => Object.keys(c.remember ?? {}))))] : []),
    [policy],
  );
  const rendered = policy ? renderPolicy(policy) : [];
  const noAbi = !contractAbi;
  // Tier-2 org-admin control (RD-1206): editable by any non-read-only admin,
  // matching the contract's grants / ABI / visibleto-unlock managers. The admin
  // client authenticates with the org-admin JWT or the admin token.
  const canEdit = !isReadonlyAdmin;

  function resetBanners() {
    setError(null);
    setSuccess(null);
  }

  async function save(doc: MethodPolicyDocument | null): Promise<boolean> {
    setSaving(true);
    resetBanners();
    try {
      const res = await rbacApi.contracts.updateMethodPolicies(orgId, contractAddress, doc);
      setPolicy(doc);
      setMode("none");
      setSuccess(doc ? "Method policy saved." : "Method policy cleared.");
      // Propagate the updated contract (PUT returns it with method_policies
      // set/cleared) so the parent's cached copy and a reopened dialog aren't stale.
      onContractUpdated?.(res.data);
      return true;
    } catch (e: unknown) {
      const err = e as { response?: { status?: number; data?: { error?: string } } };
      const status = err?.response?.status;
      const backendMsg = err?.response?.data?.error;
      if (status === 400 && backendMsg) setError(backendMsg);
      else if (status === 401 || status === 403) setError("Saving a method policy requires org-admin access for this organization.");
      else setError("Failed to save method policy.");
      return false;
    } finally {
      setSaving(false);
    }
  }

  function openWizard() {
    const recs = policy ? decompileWizard(policy).records : [];
    setW({ records: recs.length ? recs : [wizardStarterRecord()] });
    resetBanners();
    setMode("wizard");
  }
  function openJson() {
    setJsonText(JSON.stringify(policy ?? { records: {} }, null, 2));
    setJsonError(null);
    resetBanners();
    setMode("json");
  }
  function saveJson() {
    let parsed: MethodPolicyDocument;
    try {
      parsed = JSON.parse(jsonText) as MethodPolicyDocument;
    } catch (e) {
      setJsonError("Invalid JSON: " + (e as Error).message);
      return;
    }
    setJsonError(null);
    const isEmpty = !parsed.records || Object.keys(parsed.records).length === 0;
    void save(isEmpty ? null : parsed);
  }
  function clearPolicy() {
    setConfirmClear(true);
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-neutral-500" />
        <span className="text-sm font-medium text-neutral-700">Method access policies</span>
        {policy && <span className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">configured</span>}
      </div>
      <p className="text-xs text-neutral-500">
        Gate record-reader methods (e.g. <code>getPaymentInfo</code>) to a record&apos;s stakeholders, so only that
        payment&apos;s parties — and any designated settlement party or compliance principal — can read it.
      </p>

      {error && (
        <div className="p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}
      {success && <p className="text-xs text-success-dark flex items-center gap-1"><Check className="w-3 h-3" /> {success}</p>}

      {/* Current policy */}
      {rendered.length === 0 ? (
        <div className="p-3 rounded-lg border border-neutral-200 bg-neutral-50 text-xs text-neutral-600">
          No method policies configured — record-reader getters are gated by the contract grant only (any member of a
          granted group may read any record).
        </div>
      ) : (
        <div className="space-y-2">
          {rendered.map((r) => (
            <div key={r.recordType} className="p-3 rounded-lg border border-neutral-200 text-xs space-y-1">
              <div className="font-medium text-neutral-700">record: {r.recordType}</div>
              {r.readers.map((rd, i) => (
                <div key={i} className="text-neutral-600"><span className="font-mono">{rd.method}</span> readable by: {rd.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.events.map((ev, i) => (
                <div key={`e${i}`} className="text-neutral-600">event <span className="font-mono">{ev.event}</span> admits: {ev.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.transactions.map((t, i) => (
                <div key={`t${i}`} className="text-neutral-600">tx <span className="font-mono">{t.method}</span> admits: {t.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.captures.map((c, i) => (
                <div key={`c${i}`} className="text-neutral-500">captured on <span className="font-mono">{c.method}</span>: {c.fields.join(", ")}</div>
              ))}
            </div>
          ))}
        </div>
      )}

      <div className="p-2 rounded bg-amber-50 border border-amber-200 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-amber-600 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-amber-700">
          The <strong>access</strong> section gates record-reader getters. The <strong>events</strong> and{" "}
          <strong>transactions</strong> sections additively admit the record&apos;s captured audience to matching
          logs / transactions (they widen, never narrow, the deny-by-default baseline). Use high-entropy, opaque
          record identifiers.
        </p>
      </div>

      {canEdit && mode === "none" && (
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={openWizard} disabled={noAbi}>{policy ? "Edit policy" : "Configure a policy"}</Button>
          <Button variant="ghost" size="sm" onClick={openJson} disabled={noAbi}>Edit JSON (advanced)</Button>
          {policy && <Button variant="ghost" size="sm" onClick={() => { resetBanners(); setMode("simulate"); }}>Simulate</Button>}
          {policy && <Button variant="ghost" size="sm" onClick={clearPolicy} disabled={saving}>Clear policy</Button>}
        </div>
      )}
      {isReadonlyAdmin && (
        <p className="text-xs text-neutral-500">Editing method policies requires org-admin (non-read-only) access; this view is read-only.</p>
      )}
      {canEdit && noAbi && <p className="text-xs text-neutral-500">Register the contract ABI first to configure method policies.</p>}

      {/* Guided wizard (primary) */}
      {mode === "wizard" && (
        <MethodPolicyWizard
          fns={fns}
          keyableFns={keyableFns}
          abiEvents={abiEvents}
          keyableEvents={keyableEvents}
          initialRecord={w.records[0] ?? wizardStarterRecord()}
          otherRecords={w.records.slice(1)}
          saving={saving}
          onSave={(doc) => void save(doc)}
          onCancel={() => setMode("none")}
        />
      )}

      {/* Advanced JSON */}
      {mode === "json" && (
        <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-2" data-testid="method-policy-json">
          <div className="text-xs text-neutral-600">Full policy document. Empty <code>{'{"records":{}}'}</code> clears it. Validated against the ABI on save; Simulate after saving to verify who can read.</div>
          <textarea className="w-full border rounded p-2 font-mono text-xs h-64" aria-label="Method policy JSON" value={jsonText} onChange={(e) => setJsonText(e.target.value)} spellCheck={false} />
          {jsonError && <p className="text-xs text-amber-700">{jsonError}</p>}
          <div className="flex gap-2">
            <Button size="sm" disabled={saving} onClick={saveJson}>{saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save JSON</Button>
            <Button variant="ghost" size="sm" onClick={() => setMode("none")} disabled={saving}>Cancel</Button>
          </div>
        </div>
      )}

      {/* Simulator */}
      {mode === "simulate" && (
        <SimulatorPanel orgId={orgId} contractAddress={contractAddress} readerMethods={readerMethods} captureFields={captureFields} fns={fns} onClose={() => setMode("none")} />
      )}

      <ConfirmDialog
        open={confirmClear}
        onOpenChange={setConfirmClear}
        variant="destructive"
        title="Clear the method policy?"
        description="This applies immediately to every record, including past ones. Record-reader getters (e.g. getPaymentInfo) revert to being readable by any member of a granted group, and each record's parties lose the added visibility of its event logs and transactions. The captured audience is kept, so re-adding a policy restores gating."
        confirmLabel="Clear policy"
        isLoading={saving}
        onConfirm={async () => { await save(null); }}
      />
    </div>
  );
}

// ---- Simulator panel ----
function SimulatorPanel({ orgId, contractAddress, readerMethods, captureFields, fns, onClose }: { orgId: string; contractAddress: string; readerMethods: string[]; captureFields: string[]; fns: AbiFnInfo[]; onClose: () => void }) {
  // Offer the policy's gated readers (fall back to all functions if none parsed);
  // auto-select when there's exactly one — the common case.
  const readerOptions = readerMethods.length ? readerMethods : fns.map((f) => f.signature);
  const [mode, setMode] = useState<"record" | "whatif">("record");
  const [method, setMethod] = useState(readerMethods.length === 1 ? readerMethods[0] : "");
  const [recordKey, setRecordKey] = useState("");
  const [callerDID, setCallerDID] = useState("");
  const [callerETH, setCallerETH] = useState("");
  const [parties, setParties] = useState<Record<string, string>>({}); // captureField → comma-sep values (what-if)
  const [dids, setDids] = useState<string[]>([]); // dev test-identity DIDs, for the picker
  const [running, setRunning] = useState(false);
  type Surface = { kind: string; signature: string; result: string; additive: boolean; matched_rule?: string };
  type SimResult = { result: string; matched_rule?: string; note?: string; captured: Record<string, string[]>; surfaces?: Surface[] };
  type SurfaceRow = { kind: string; signature: string; additive: boolean; admitted: string[]; excluded: { id: string; result: string }[] };
  const [result, setResult] = useState<SimResult | null>(null); // existing-record: one caller
  const [surfaceRows, setSurfaceRows] = useState<SurfaceRow[] | null>(null); // what-if: per-surface admitted-lists
  const [err, setErr] = useState<string | null>(null);

  // Populate a DID datalist from the dev identity picker (mockauth only; 403 in
  // production → empty list → the fields stay plain free-text).
  useEffect(() => {
    fetch("/api/v1/dev/test-identities")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => { if (data?.identities) setDids(data.identities.map((i: { did: string }) => i.did)); })
      .catch(() => {});
  }, []);

  const whatIf = mode === "whatif";
  const whatIfHasParties = Object.values(parties).some((v) => v.trim());
  const capturedMap = () => {
    const out: Record<string, string[]> = {};
    for (const [field, raw] of Object.entries(parties)) {
      const vals = raw.split(",").map((s) => s.trim()).filter(Boolean);
      if (vals.length) out[field] = vals;
    }
    return out;
  };
  const callerArgs = (id: string) =>
    id.startsWith("0x") ? { caller_did: "", caller_eth_addresses: [id] } : { caller_did: id, caller_eth_addresses: [] };
  const reset = () => { setErr(null); setResult(null); setSurfaceRows(null); };
  const admits = (r: string) => r === "allow" || r === "admit";

  // Existing-record mode: does this one caller pass the gate for a real record?
  // The response also carries per-surface verdicts (reader + additive event/tx).
  async function runRecord() {
    setRunning(true);
    reset();
    try {
      const res = await rbacApi.contracts.simulateMethodPolicy(orgId, contractAddress, {
        method,
        record_key: recordKey,
        caller_did: callerDID,
        caller_eth_addresses: callerETH.split(",").map((s) => s.trim()).filter(Boolean),
      });
      setResult(res.data as SimResult);
    } catch (e: unknown) {
      setErr((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Simulation failed.");
    } finally {
      setRunning(false);
    }
  }

  // What-if mode: given the parties, show — for EVERY governed surface (reader +
  // each additive event/tx) — who the policy admits, plus a non-party control.
  // One call per candidate; transpose the returned surfaces into per-surface rows.
  async function runWhatIf() {
    setRunning(true);
    reset();
    const captured = capturedMap();
    const readerSig = method || readerMethods[0] || "";
    const roleMap = new Map<string, string[]>();
    for (const [field, raw] of Object.entries(parties))
      for (const v of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
        const roles = roleMap.get(v) ?? [];
        if (!roles.includes(field)) roles.push(field);
        roleMap.set(v, roles);
      }
    const candidates = [...roleMap.keys()].map((id) => ({ id }));
    candidates.push({ id: "did:example:outsider" });
    try {
      const perCand: { id: string; surfaces: Surface[] }[] = [];
      for (const c of candidates) {
        const res = await rbacApi.contracts.simulateMethodPolicy(orgId, contractAddress, { method: readerSig, record_key: "", ...callerArgs(c.id), captured });
        perCand.push({ id: c.id, surfaces: (res.data as SimResult).surfaces ?? [] });
      }
      const order = perCand[0]?.surfaces ?? [];
      const rows: SurfaceRow[] = order.map((s) => {
        const admitted: string[] = [];
        const excluded: { id: string; result: string }[] = [];
        for (const pc of perCand) {
          const sv = pc.surfaces.find((x) => x.kind === s.kind && x.signature === s.signature);
          const r = sv?.result ?? "abstain";
          if (admits(r)) admitted.push(pc.id);
          else excluded.push({ id: pc.id, result: r });
        }
        return { kind: s.kind, signature: s.signature, additive: s.additive, admitted, excluded };
      });
      setSurfaceRows(rows);
    } catch (e: unknown) {
      setErr((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Simulation failed.");
    } finally {
      setRunning(false);
    }
  }

  const badgeCls = (r: string) => r === "allow" ? "bg-emerald-100 text-emerald-800" : r === "deny" ? "bg-error-light text-error-dark" : "bg-amber-100 text-amber-800";
  const canRun = !running && (whatIf ? whatIfHasParties : (!!method && !!recordKey));
  const tab = (active: boolean) => `px-2 py-0.5 rounded border ${active ? "bg-primary text-white border-primary" : "bg-neutral-50 text-neutral-600 border-neutral-200"}`;
  const label = (id: string) => id.replace(/^did:(test|example):/, "");
  const surfaceTag = (kind: string) => kind === "reader" ? "read gate" : kind === "event" ? "event · adds" : "tx · adds";
  const glyph = (r: string) => r === "deny" ? "deny" : r === "abstain" ? "—" : r;

  return (
    <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-2" data-testid="method-policy-simulate">
      <datalist id="sim-did-list">{dids.map((d) => <option key={d} value={d} />)}</datalist>
      <div className="text-xs text-neutral-600 flex items-start gap-1">
        <FlaskConical className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
        <span>
          Dry-run the policy — <strong>no on-chain call</strong>, it does not run <code>createPayment</code> or any method.
          The <strong>reader gate</strong> is authoritative (allow/deny); <strong>events &amp; transactions</strong> are
          additive (they widen a grants/participant baseline this dry-run can&apos;t see, shown as admit / —). The live
          return-address rule isn&apos;t simulated.
        </span>
      </div>
      {/* mode: test an existing record, or hypothetical parties (validate before any record exists) */}
      <div className="flex gap-1 text-xs">
        <button type="button" className={tab(mode === "record")} onClick={() => { setMode("record"); reset(); }}>Existing record</button>
        <button type="button" className={tab(mode === "whatif")} onClick={() => { setMode("whatif"); reset(); }}>What-if parties</button>
      </div>
      {mode === "record" && (
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-0.5">
            <div className="text-xs text-neutral-500">Reader method to test</div>
            <select className="border rounded px-2 py-1 text-sm w-full" aria-label="simulate method" value={method} onChange={(e) => setMethod(e.target.value)}>
              <option value="">reader method…</option>
              {readerOptions.map((sig) => <option key={sig} value={sig}>{sig}</option>)}
            </select>
          </div>
          <div className="space-y-0.5">
            <div className="text-xs text-neutral-500">Record key — an existing record</div>
            <input className="border rounded px-2 py-1 text-sm w-full" aria-label="simulate record key" placeholder="PAY-1" value={recordKey} onChange={(e) => setRecordKey(e.target.value)} />
          </div>
        </div>
      )}
      {mode === "record" && (
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-0.5">
            <div className="text-xs text-neutral-500">Caller DID — the identity to test</div>
            <input className="border rounded px-2 py-1 text-sm w-full" list="sim-did-list" aria-label="simulate caller did" placeholder="did:test:alice" value={callerDID} onChange={(e) => setCallerDID(e.target.value)} />
          </div>
          <div className="space-y-0.5">
            <div className="text-xs text-neutral-500">Caller ETH address(es) — for address-typed parties</div>
            <input className="border rounded px-2 py-1 text-sm w-full" aria-label="simulate caller eth" placeholder="0x… (comma-sep; e.g. the payee address)" value={callerETH} onChange={(e) => setCallerETH(e.target.value)} />
          </div>
        </div>
      )}
      {whatIf && (
        <div className="space-y-1 border-t border-neutral-100 pt-2" data-testid="whatif-parties">
          <div className="text-xs font-medium text-neutral-600">Hypothetical parties — as if a record were created with these</div>
          {captureFields.length === 0 && <p className="text-xs text-neutral-400">This policy captures no fields.</p>}
          {captureFields.map((f) => (
            <div key={f} className="flex items-center gap-2">
              <span className="text-xs text-neutral-500 w-24 shrink-0 font-mono">{f}</span>
              <input className="border rounded px-2 py-1 text-sm w-full" list="sim-did-list" aria-label={`whatif party ${f}`} placeholder="did:… or 0x… (comma-sep)" value={parties[f] ?? ""} onChange={(e) => setParties((p) => ({ ...p, [f]: e.target.value }))} />
            </div>
          ))}
        </div>
      )}
      <p className="text-xs text-neutral-400">
        {whatIf
          ? "Fill the parties, then Simulate to see — for every governed surface — who the policy admits, plus a non-party control."
          : "Uses a real captured record. A party captured as an address (e.g. payee) matches on the caller's ETH address, not the DID."}
      </p>
      {err && <p className="text-xs text-amber-700">{err}</p>}
      {result && !whatIf && (
        <div className="text-xs space-y-1">
          <div><span className={`px-2 py-0.5 rounded font-medium ${badgeCls(result.result)}`}>{result.result}</span>{result.matched_rule ? <span className="ml-2 text-neutral-500">via {result.matched_rule}</span> : null} <span className="text-neutral-400">— reader gate</span></div>
          {result.note && <p className="text-amber-700">{result.note}</p>}
          {result.surfaces && result.surfaces.some((s) => s.additive) && (
            <div className="text-neutral-500">additive surfaces for this caller: {result.surfaces.filter((s) => s.additive).map((s) => `${s.signature} ${s.result === "admit" ? "✓" : "—"}`).join("; ")}</div>
          )}
          <div className="text-neutral-500">record admit-set: {Object.entries(result.captured || {}).map(([k, v]) => `${k}=[${v.join(", ")}]`).join("; ") || "(none)"}</div>
        </div>
      )}
      {surfaceRows && whatIf && (
        <div className="text-xs space-y-1.5 border-t border-neutral-100 pt-2" data-testid="whatif-verdicts">
          <div className="font-medium text-neutral-600">Who can access each surface with these parties?</div>
          {surfaceRows.map((row) => (
            <div key={row.kind + row.signature} className="flex flex-wrap items-baseline gap-x-2">
              <code className="font-mono">{row.signature}</code>
              <span className="text-[10px] uppercase tracking-wide text-neutral-400">{surfaceTag(row.kind)}</span>
              <span className="text-neutral-700">→ {row.admitted.map(label).join(", ") || "(none)"}</span>
              {row.excluded.length > 0 && (
                <span className="text-neutral-400">· {row.excluded.map((e) => `${label(e.id)}: ${glyph(e.result)}`).join(", ")}</span>
              )}
            </div>
          ))}
          <p className="text-neutral-400">read = authoritative gate · adds = additive (widens the grants/participant baseline); an additive &quot;—&quot; may still see it via a grant.</p>
        </div>
      )}
      <div className="flex gap-2">
        <Button size="sm" disabled={!canRun} onClick={() => void (whatIf ? runWhatIf() : runRecord())}>{running ? <Loader2 className="w-3 h-3 animate-spin" /> : null} Simulate</Button>
        <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
      </div>
    </div>
  );
}
