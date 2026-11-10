import { useEffect, useRef, useState } from "react";
import { api } from "../../api/store";
import type { Finding, Preview, PreviewGroup } from "../../api/types";
import { duration, fmt } from "../../lib/format";
import { href } from "../../lib/router";

type Change = { op: "create" | "update" | "delete"; spec?: unknown; id?: number; position?: number };

/** "What if": replays recent real traffic against the rule table as it would be after
 *  this change, and lists the packets whose verdict would change. Nothing is saved. */
export function useImpact(change: Change | null, delay = 350) {
  const [res, setRes] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const key = change ? JSON.stringify(change) : "";
  const seq = useRef(0);
  useEffect(() => {
    if (!change) { setRes(null); setError(null); return; }
    const n = ++seq.current;
    setBusy(true);
    const t = setTimeout(() => {
      api.preview(change)
        .then((r) => { if (n === seq.current) { setRes(r); setError(null); } })
        .catch((e: Error) => { if (n === seq.current) { setError(e.message); setRes(null); } })
        .finally(() => { if (n === seq.current) setBusy(false); });
    }, delay);
    return () => clearTimeout(t);
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return { res, error, busy };
}

const by = (action: string, id: number | null) =>
  id == null ? "default policy" : `rule ${id}${action === "REJECT" ? " (reject)" : ""}`;

function Group({ g }: { g: PreviewGroup }) {
  const flip = g.before !== g.after;
  const target = g.port != null ? (g.proto === "TCP" || g.proto === "UDP" ? `${g.proto} :${g.port}` : `${g.proto} type ${g.port}`) : g.proto;
  return (
    <li className="imp-row">
      <span className="mono ell">{g.src}</span>
      <span className="mono faint ell">{g.dir === "in" ? "→" : "←"} {g.service ?? target}</span>
      <span className="mono imp-count">{fmt(g.count)}×</span>
      <span className="imp-change small">
        <span className={`verdict ${g.before === "ACCEPT" ? "allow" : "block"}`}>{g.before === "ACCEPT" ? "Allowed" : "Blocked"}</span>
        <span className="faint"> by {by(g.beforeAction, g.beforeBy)}</span>
        <span className="faint"> → </span>
        {flip ? <span className={`verdict ${g.after === "ACCEPT" ? "allow" : "block"}`}>{g.after === "ACCEPT" ? "allowed" : "blocked"}</span> : <span>same verdict</span>}
        <span className="faint"> by {by(g.afterAction, g.afterBy)}</span>
      </span>
    </li>
  );
}

export function Impact({ res, error, busy, ruleId, readOnly }: {
  res: Preview | null; error: string | null; busy: boolean; ruleId: number | null; readOnly?: boolean;
}) {
  if (error) return <div className="impact"><p className="small"><b>Can't preview yet:</b> {error}</p></div>;
  if (!res) return <div className="impact" aria-busy="true"><p className="muted small">Checking this change against recent traffic…</p></div>;

  const span = res.from != null && res.to != null ? duration(Math.max(1, Math.round(res.to - res.from))) : null;
  const flips = res.nowBlocked + res.nowAllowed;
  const own: Finding | undefined = ruleId != null ? res.findings[String(ruleId)] : undefined;
  const caused = Object.entries(res.findings).filter(([id, f]) => f.by === ruleId && Number(id) !== ruleId);

  return (
    <section className={`impact${busy ? " busy" : ""}`} aria-live="polite" aria-label="Effect of this change on recent traffic">
      <h3>What this change would do</h3>
      {res.checked === 0 ? (
        <p className="small muted">No new-connection traffic has reached the rule table yet, so there's nothing to replay.</p>
      ) : flips === 0 ? (
        <p className="small">None of the last <b className="mono">{fmt(res.checked)}</b> new connections{span ? ` (${span})` : ""} would get a different verdict.
          {res.otherRule ? ` ${fmt(res.otherRule)} would be decided by a different rule, with the same result.` : ""}</p>
      ) : (
        <p className="small">Of the last <b className="mono">{fmt(res.checked)}</b> new connections{span ? ` (${span})` : ""},{" "}
          {res.nowBlocked > 0 && <><b className="imp-block mono">{fmt(res.nowBlocked)}</b> allowed would now be <b>blocked</b></>}
          {res.nowBlocked > 0 && res.nowAllowed > 0 && " and "}
          {res.nowAllowed > 0 && <><b className="imp-allow mono">{fmt(res.nowAllowed)}</b> blocked would now be <b>allowed</b></>}.
        </p>
      )}
      {res.groups.length > 0 && (
        <ul className="imp-list">
          {res.groups.slice(0, 6).map((g, i) => <Group key={i} g={g} />)}
          {res.groups.length + res.moreGroups > 6 && <li className="faint small imp-more">and {fmt(res.groups.length + res.moreGroups - 6)} more groups</li>}
        </ul>
      )}
      {own && <p className="imp-warn small"><b>{own.kind === "redundant" ? "This rule would be redundant." : "This rule would never decide anything."}</b> {own.message}</p>}
      {caused.map(([id, f]) => (
        <p key={id} className="imp-warn small"><b>This change would make <a className="link" href={href("rules", { rule: id })}>rule {id}</a> {f.kind === "redundant" ? "redundant" : "unreachable"}.</b> It sits below this rule and covers nothing this rule doesn't.</p>
      ))}
      <p className="faint small">Replays the first packet of each recent connection through the new rule order. Rate limits and the replies that follow are not simulated.{readOnly ? " Nothing is saved on this read-only demo." : ""}</p>
    </section>
  );
}
