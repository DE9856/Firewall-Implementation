import { useMemo, useState } from "react";
import { api, refreshRules, useStore } from "../../api/store";
import type { RuleRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/Shell";
import { ACTION_WORD, actionTone, fmt, ruleSentence } from "../../lib/format";
import { setParams, useRoute } from "../../lib/router";
import { RuleDetail } from "./RuleDetail";
import { RuleEditor } from "./RuleEditor";
import { Tester } from "./Tester";
import "./rules.css";

const show = (v: unknown) => (v == null || v === "" || v === "any" ? "any" : Array.isArray(v) ? v.join(", ") : String(v));

export function Rules() {
  const rules = useStore((s) => s.rules);
  const config = useStore((s) => s.config);
  const stats = useStore((s) => s.stats);
  const readOnly = useStore((s) => !!s.source?.readOnly);
  const { params } = useRoute();
  const selected = Number(params.get("rule")) || null;
  const editing = params.get("edit");
  const testing = params.get("test") === "1";
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testMatch, setTestMatch] = useState<number | null>(null);
  const maxHits = Math.max(1, ...rules.map((r) => r.hits));

  const act = async (id: number, fn: () => Promise<unknown>) => {
    setBusy(id); setError(null);
    try { await fn(); await refreshRules(); } catch (e) { setError((e as Error).message); } finally { setBusy(null); }
  };
  const move = (r: RuleRec, delta: number) => {
    const ids = rules.map((x) => x.id);
    const i = ids.indexOf(r.id), j = i + delta;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    act(r.id, () => api.reorder(ids));
  };
  const toggle = (r: RuleRec) => act(r.id, () => api.updateRule(r.id, { ...r.spec, enabled: !r.enabled }));

  const enabled = rules.filter((r) => r.enabled).length;
  const flagged = rules.filter((r) => r.enabled && r.finding).length;
  const nextId = Math.max(0, ...rules.map((r) => r.id)) + 1;
  const panel = editing ? "edit" : testing ? "test" : selected ? "detail" : null;
  const selRule = useMemo(() => rules.find((r) => r.id === selected) ?? null, [rules, selected]);
  const editRule = useMemo(() => (editing && editing !== "new" ? rules.find((r) => r.id === Number(editing)) ?? null : null), [rules, editing]);

  return (
    <>
      <PageHeader title="Firewall rules"
        finding={`${enabled} of ${rules.length} rules active, checked from the top; the first match decides. Anything unmatched gets ${config?.defaultPolicy === "ACCEPT" ? "allowed" : "blocked"}.${flagged ? ` ${flagged} rule${flagged > 1 ? "s" : ""} can never decide anything: see the marked rows.` : ""}${readOnly ? " This public demo is read-only: try changes and see their effect, but nothing is saved." : ""}`}>
        <button className="btn" onClick={() => setParams({ test: 1, edit: "", rule: "" })}>Test a packet</button>
        <button className="btn primary" onClick={() => setParams({ edit: "new", test: "", rule: "" })}><Icon name="plus" size={14} />{readOnly ? "Try a new rule" : "New rule"}</button>
      </PageHeader>

      <div className={`ru-body${panel ? " with-panel" : ""}`}>
        <section className="panel ru-table" aria-label="Rule table, in evaluation order">
          {error && <div className="error-box" role="alert">Change not saved: {error}</div>}
          <table>
            <thead>
              <tr>
                <th className="num">#</th><th>Rule</th><th>Action</th><th>Direction</th><th>Protocol</th>
                <th>Source</th><th>Destination</th><th>Ports</th><th className="num">Matches</th><th>On</th>{!readOnly && <th><span className="sr-only">Order</span></th>}
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => {
                const s = r.spec;
                return (
                  <tr key={r.id} className={`${r.id === selected ? "on " : ""}${r.enabled ? "" : "off "}${testMatch === r.id ? "tested" : ""}`}
                    onClick={() => setParams({ rule: r.id, edit: "", test: "" })} aria-selected={r.id === selected}>
                    <td className="num faint">{r.position}</td>
                    <td className="ru-name">
                      <button className="row-link" onClick={(e) => { e.stopPropagation(); setParams({ rule: r.id, edit: "", test: "" }); }}>
                        {s.name || `Rule ${r.id}`}<span className="faint mono"> #{r.id}</span>
                      </button>
                      <span className="muted">{ruleSentence(s)}</span>
                      {r.finding && r.enabled && (
                        <span className="ru-flag" title={r.finding.message}>
                          {r.finding.kind === "redundant" ? `Redundant: rule ${r.finding.by} above already does this`
                            : r.finding.kind === "never" ? "Can never match"
                              : `Never decides: rule ${r.finding.by} above catches these packets first`}
                        </span>
                      )}
                    </td>
                    <td><span className={`verdict ${actionTone(s.action)}`}>{ACTION_WORD[s.action]}</span></td>
                    <td>{show(s.direction)}</td>
                    <td className="mono">{show(s.protocol)}{(s.protocol === "icmp" || s.protocol === "icmpv6") && s.icmp_type != null ? ` type ${s.icmp_type}` : ""}</td>
                    <td className="mono ell">{show(s.src)}</td>
                    <td className="mono ell">{show(s.dst)}</td>
                    <td className="mono ell">{s.dst_port != null ? show(s.dst_port) : s.src_port != null ? `from ${show(s.src_port)}` : "any"}{s.rate_limit ? <span className="faint"> · {s.rate_limit}</span> : null}</td>
                    <td className="num">{r.hits || !r.enabled ? <span className="mono">{fmt(r.hits)}</span> : <span className="faint small" title="No packet has matched this rule since PyWall started">none yet</span>}<i className="hitbar" style={{ width: `${(r.hits / maxHits) * 100}%` }} /></td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <button className="switch" role="switch" aria-checked={r.enabled} disabled={busy === r.id || readOnly}
                        title={readOnly ? "Read-only demo" : undefined}
                        aria-label={`${r.enabled ? "Disable" : "Enable"} rule ${r.id}`} onClick={() => toggle(r)} />
                    </td>
                    <td className="ru-order" onClick={(e) => e.stopPropagation()} hidden={readOnly}>
                      <button className="btn ghost small" disabled={i === 0 || busy != null} onClick={() => move(r, -1)} aria-label={`Move rule ${r.id} up`}><Icon name="up" size={14} /></button>
                      <button className="btn ghost small" disabled={i === rules.length - 1 || busy != null} onClick={() => move(r, 1)} aria-label={`Move rule ${r.id} down`}><Icon name="down" size={14} /></button>
                    </td>
                  </tr>
                );
              })}
              <tr className="policy-row">
                <td className="num faint">—</td>
                <td className="ru-name"><b>Default policy</b><span className="muted">Anything no rule matched.</span></td>
                <td><span className={`verdict ${config?.defaultPolicy === "ACCEPT" ? "allow" : "block"}`}>{config?.defaultPolicy === "ACCEPT" ? "Allow" : "Drop"}</span></td>
                <td colSpan={panel ? 3 : 5} className="muted">Set in config/rules.json</td>
                <td className="num mono">{fmt(stats?.byStage.policy ?? 0)}</td><td />{!readOnly && <td />}
              </tr>
            </tbody>
          </table>
          {rules.length === 0 && <p className="empty">No rules: every new connection gets the default policy. Add one with New rule.</p>}
          <p className="ru-foot faint">Matches count since PyWall started. Replies on established connections skip this table (connection tracking), so they never count here.</p>
        </section>

        {panel === "detail" && selRule && <RuleDetail rule={selRule} readOnly={readOnly} onEdit={() => setParams({ edit: selRule.id })} onClose={() => setParams({ rule: "" })} />}
        {panel === "detail" && !selRule && <aside className="panel ru-panel"><p className="empty">{rules.length ? `Rule ${selected} no longer exists.` : "Loading the rule…"}</p></aside>}
        {panel === "edit" && (editing === "new" || editRule ? (
          <RuleEditor key={editing} rule={editing === "new" ? null : editRule} count={rules.length}
            nextId={nextId} readOnly={readOnly} onDone={(id) => setParams({ edit: "", rule: id ?? "" })} />
        ) : (
          // The form copies the rule once, when it opens: wait for the rule table rather than open an empty form
          // that would save over the rule.
          <aside className="panel ru-panel"><p className="empty">{rules.length ? `Rule ${editing} no longer exists.` : "Loading the rule…"}</p></aside>
        ))}
        {panel === "test" && <Tester onMatch={setTestMatch} onClose={() => { setTestMatch(null); setParams({ test: "", src: "", dst: "", sport: "", dport: "", proto: "", flags: "", dir: "" }); }} />}
      </div>
    </>
  );
}
