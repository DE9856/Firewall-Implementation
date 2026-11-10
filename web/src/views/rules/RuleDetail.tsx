import { useMemo, useState } from "react";
import { api, refreshRules, useStore } from "../../api/store";
import type { RuleRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { actionTone, clock, endpoint, fmt, ruleSentence, verdictWord } from "../../lib/format";
import { go, href, setParams } from "../../lib/router";
import { Impact, useImpact } from "./Impact";

export function RuleDetail({ rule, onEdit, onClose, readOnly = false }: { rule: RuleRec; onEdit: () => void; onClose: () => void; readOnly?: boolean }) {
  const packets = useStore((s) => s.packets);
  const held = useStore((s) => s.held);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const s = rule.spec;
  const impact = useImpact(confirm ? { op: "delete", id: rule.id } : null, 0);
  const recent = useMemo(() => {
    const pool = new Map([...held, ...packets].map((p) => [p.id, p]));
    return [...pool.values()].filter((p) => p.rule === rule.id).sort((a, b) => a.id - b.id).slice(-8).reverse();
  }, [packets, held, rule.id]);

  const conds: [string, string][] = [];
  if (s.direction && s.direction !== "any") conds.push(["Direction", s.direction === "in" ? "inbound (to this host)" : "outbound (from this host)"]);
  if (s.protocol && s.protocol !== "any") conds.push(["Protocol", s.protocol === "icmpv6" ? "ICMPv6" : s.protocol.toUpperCase()]);
  if (s.src) conds.push(["Source address", [s.src].flat().join(", ")]);
  if (s.dst) conds.push(["Destination address", [s.dst].flat().join(", ")]);
  if (s.src_port != null) conds.push(["Source port", [s.src_port].flat().join(", ")]);
  if (s.dst_port != null) conds.push(["Destination port", [s.dst_port].flat().join(", ")]);
  if (s.icmp_type != null) conds.push([s.protocol === "icmpv6" ? "ICMPv6 type" : "ICMP type", String(s.icmp_type)]);
  if (s.tcp_flags) conds.push(["TCP flags", `${s.tcp_flags} (letters before ! must be set, after ! must be clear)`]);

  const allRules = useStore((st) => st.rules);
  const moveAbove = async () => {
    const by = rule.finding?.by;
    const ids = allRules.map((r) => r.id).filter((id) => id !== rule.id);
    const at = ids.indexOf(by as number);
    if (at < 0) return;
    ids.splice(at, 0, rule.id);
    try { await api.reorder(ids); await refreshRules(); } catch (e) { setError((e as Error).message); }
  };

  const remove = async () => {
    try { await api.deleteRule(rule.id); await refreshRules(); setParams({ rule: "" }); }
    catch (e) { setError((e as Error).message); }
  };

  return (
    <aside className="panel ru-panel" aria-label={`Rule ${rule.id}`}>
      <div className="panel-head">
        <div><h2>{s.name || `Rule ${rule.id}`}</h2><p className="muted small">Rule #{rule.id} · position {rule.position}{rule.enabled ? "" : " · disabled"}</p></div>
        <button className="btn ghost small" onClick={onClose} aria-label="Close"><Icon name="close" size={14} /></button>
      </div>
      <div className="ru-pad">
        <p className="sentence">{ruleSentence(s)}</p>
        <span className={`verdict ${actionTone(s.action)}`}>{s.action === "ACCEPT" ? "Allows matching packets" : s.action === "REJECT" ? "Rejects matching packets" : "Drops matching packets"}</span>
      </div>
      {rule.finding && rule.enabled && (
        <div className="ru-finding-box" role="note">
          <b>{rule.finding.kind === "redundant" ? "Redundant rule" : "This rule never decides anything"}</b>
          <p className="small">{rule.finding.message}</p>
          <div className="ru-finding-actions">
            {rule.finding.kind === "shadowed" && rule.finding.by != null && !readOnly && (
              <button className="btn small" onClick={moveAbove}>Move it above rule {rule.finding.by}</button>
            )}
            {rule.finding.kind === "redundant" && !readOnly && !confirm && (
              <button className="btn small" onClick={() => setConfirm(true)}>Delete it</button>
            )}
            {rule.finding.by != null && <a className="link small" href={href("rules", { rule: rule.finding.by })}>Open rule {rule.finding.by}</a>}
          </div>
        </div>
      )}
      <h3 className="ru-sub">Conditions it checks</h3>
      {conds.length ? (
        <dl className="cond-list">{conds.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}</dl>
      ) : <p className="ru-pad muted">None: every packet that reaches this rule matches it.</p>}
      <p className="ru-pad muted small">A packet matches only if every condition holds. Conditions not listed accept any value.</p>
      {(s.rate_limit || s.log) && (
        <dl className="cond-list">
          {s.rate_limit && <div><dt>Rate limit</dt><dd className="mono">{s.rate_limit} per source; extra packets are blocked</dd></div>}
          {s.log && <div><dt>Logging</dt><dd>Every match is written to the log</dd></div>}
        </dl>
      )}
      <h3 className="ru-sub">Matches since start <span className="mono">{fmt(rule.hits)}</span></h3>
      {recent.length ? (
        <ul className="ru-packets">
          {recent.map((p) => (
            <li key={p.id}><button onClick={() => go("traffic", { packet: p.id })}>
              <span className="mono faint">{clock(p.t)}</span><span className="mono ell">{endpoint(p.src, p.sport)} → {endpoint(p.dst, p.dport)}</span>
              <span className={`verdict ${p.verdict === "ACCEPT" ? "allow" : p.rateLimited ? "warn" : "block"}`}>{p.rateLimited ? "Rate limited" : verdictWord(p)}</span>
            </button></li>
          ))}
        </ul>
      ) : <p className="empty">No recent packets matched this rule.</p>}
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="ru-actions">
        {readOnly ? (
          <>
            <button className="btn small" onClick={onEdit}><Icon name="edit" size={14} />Try changing it</button>
            <span className="muted small">Read-only demo: see a change's effect without saving it.</span>
          </>
        ) : confirm ? (
          <>
            <Impact {...impact} ruleId={null} />
            <span className="small">Delete rule {rule.id}? This rewrites config/rules.json and cannot be undone here.</span>
            <button className="btn danger small" onClick={remove}>Delete rule {rule.id}</button>
            <button className="btn ghost small" onClick={() => setConfirm(false)}>Keep it</button>
          </>
        ) : (
          <>
            <button className="btn small" onClick={onEdit}><Icon name="edit" size={14} />Edit</button>
            <button className="btn small danger" onClick={() => setConfirm(true)}><Icon name="trash" size={14} />Delete</button>
          </>
        )}
      </div>
    </aside>
  );
}
