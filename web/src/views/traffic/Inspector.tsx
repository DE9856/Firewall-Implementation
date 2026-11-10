import { useEffect, useState } from "react";
import { api } from "../../api/store";
import type { HeaderField, PacketDetail } from "../../api/types";
import { Icon } from "../../components/Icon";
import { STAGE_IN_TEXT, clock, endpoint, STAGE_EXPLAIN, STAGE_LABEL, verdictWord } from "../../lib/format";
import { href } from "../../lib/router";

const OUTCOME = { pass: "passed", match: "decided", skipped: "not re-checked" } as const;

export function Inspector({ id, onClose }: { id: number; onClose: () => void }) {
  const [data, setData] = useState<PacketDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hot, setHot] = useState<HeaderField | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null); setError(null);
    api.packet(id).then((d) => alive && setData(d)).catch((e: Error) => alive && setError(e.message));
    return () => { alive = false; };
  }, [id]);

  return (
    <aside className="panel inspector" aria-label={`Packet ${id}`}>
      <div className="panel-head">
        <h2>Packet <span className="mono">{id}</span></h2>
        <button className="btn ghost small" onClick={onClose} aria-label="Close inspector"><Icon name="close" size={14} /></button>
      </div>
      {error && <div className="error-box">Couldn't load this packet: {error}. The server keeps the latest 5,000 packets.</div>}
      {!data && !error && <div className="insp-loading" aria-busy="true">{[70, 90, 60, 85, 50].map((w, i) => <span key={i} className="skeleton" style={{ width: `${w}%`, height: 14 }} />)}</div>}
      {data && <Detail d={data} hot={hot} setHot={setHot} />}
    </aside>
  );
}

function Detail({ d, hot, setHot }: { d: PacketDetail; hot: HeaderField | null; setHot: (f: HeaderField | null) => void }) {
  const p = d.packet;
  const ex = d.explain;
  const held = p.verdict === "DROP";
  const changed = ex && (ex.verdict !== p.verdict || ex.stage !== p.stage);
  const matchedRule = ex?.rules.find((r) => r.matched);
  const bytes = p.header.match(/../g) ?? [];

  return (
    <div className="insp">
      <section className="insp-verdict">
        <span className={`verdict ${p.idsAlert || p.rateLimited ? "warn" : held ? "block" : "allow"} big`}>{verdictWord(p)}</span>
        <p>{p.reject ? "Rejected" : held ? "Dropped" : "Accepted"} at the <b>{STAGE_IN_TEXT[p.stage]}</b>: {p.reason}.</p>
        {p.reject && <p className="small">PyWall dropped it and sent the sender a <b>{p.reject}</b>{p.reject.startsWith("TCP") ? ", so its connection fails at once with \u201cconnection refused\u201d instead of hanging until a timeout" : ", so it learns at once that nothing will answer"}.</p>}
        <p className="muted mono small">{clock(p.t, true)} · {p.dir === "in" ? "inbound to this host" : p.dir === "out" ? "outbound from this host" : "direction unknown"}{p.state ? ` · connection ${p.state}` : ""}</p>
        <p className="mono addr">{endpoint(p.src, p.sport)} <span className="faint">→</span> {endpoint(p.dst, p.dport)}</p>
        <div className="insp-actions">
          {p.src && <a className="btn small" href={href("overview", { journey: p.id })}>Watch its journey</a>}
          {p.rule != null && <a className="btn small" href={href("rules", { rule: p.rule })}>Open rule {p.rule}</a>}
          {p.src && <a className="btn small ghost" href={href("rules", { test: 1, src: p.src, dst: p.dst ?? "", sport: p.sport ?? "", dport: p.dport ?? "", proto: p.proto, flags: p.flags ?? "", dir: p.dir ?? "" })}>Test variations</a>}
        </div>
      </section>

      {ex && (
        <section>
          <h3>How the pipeline handled it</h3>
          <p className="muted small">{changed
            ? `Re-checked now, this packet would get ${ex.verdict === "ACCEPT" ? "allowed" : "blocked"} at the ${STAGE_IN_TEXT[ex.stage]}: rules, bans or connections have changed since it arrived. The verdict above is what happened.`
            : "Each stage in order. The first stage that decides wins; the rest never see the packet."}</p>
          <ol className="trace">
            {ex.stages.map((s) => (
              <li key={s.stage} className={s.verdict ? "decided" : s.outcome}>
                <span className="t-stage">{STAGE_LABEL[s.stage]}</span>
                <span className="t-outcome">{s.verdict ? (s.verdict === "ACCEPT" ? "allowed" : p.reject && s.stage === "rule" ? "rejected" : "blocked") : OUTCOME[s.outcome]}</span>
                <span className="t-detail" title={STAGE_EXPLAIN[s.stage]}>{s.detail}</span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {matchedRule && (
        <section>
          <h3>Why rule {matchedRule.id} matched</h3>
          <table className="conds">
            <thead><tr><th>Condition</th><th>Rule asks for</th><th>Packet has</th><th><span className="sr-only">Result</span></th></tr></thead>
            <tbody>
              {matchedRule.conditions.length ? matchedRule.conditions.map((c) => (
                <tr key={c.field}><td>{c.field}</td><td className="mono">{String(c.rule)}</td><td className="mono">{c.packet ?? "—"}</td><td className={c.ok ? "ok" : "no"}>{c.ok ? "yes" : "no"}</td></tr>
              )) : <tr><td colSpan={4} className="muted">This rule has no conditions: it matches everything that reaches it.</td></tr>}
            </tbody>
          </table>
          {ex && ex.rules.length > 1 && <p className="muted small">Rules {ex.rules.filter((r) => !r.matched).map((r) => r.id).join(", ")} were checked first and did not match.</p>}
        </section>
      )}

      {p.reject && p.replyHeader && <ReplyBytes hex={p.replyHeader} what={p.reject} from={endpoint(p.dst, p.dport)} to={endpoint(p.src, p.sport)} />}

      <section>
        <h3>Headers</h3>
        {d.layers.length === 0 && <p className="muted">These bytes are not a valid IPv4 or IPv6 packet, which is why the parser dropped them.</p>}
        {d.layers.map((l) => (
          <details key={l.layer} open>
            <summary><b>{l.layer}</b> <span className="faint mono">bytes {l.offset}–{l.offset + l.length - 1}</span></summary>
            <dl className="fields">
              {l.fields.map((f) => (
                <div key={f.name} onMouseEnter={() => setHot(f)} onMouseLeave={() => setHot(null)} className={hot === f ? "hot" : ""}>
                  <dt>{f.name}</dt><dd className="mono">{String(f.value)}</dd>
                  {f.note && <dd className="note">{f.note}</dd>}
                </div>
              ))}
            </dl>
          </details>
        ))}
      </section>

      <section>
        <h3>Bytes <span className="faint small">first {bytes.length} of {p.len}; hover a field to find it</span></h3>
        <pre className="hex" aria-label="Hex dump of the packet header">
          {Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => (
            <div key={row}>
              <span className="faint">{(row * 16).toString(16).padStart(4, "0")}</span>
              {bytes.slice(row * 16, row * 16 + 16).map((b, i) => {
                const at = row * 16 + i;
                const on = hot && at >= hot.offset && at < hot.offset + hot.length;
                return <span key={i} className={on ? "byte on" : "byte"}>{b}</span>;
              })}
            </div>
          ))}
        </pre>
      </section>
    </div>
  );
}

/** The REJECT reply PyWall sent back: it travels from the packet's destination back to its source. */
function ReplyBytes({ hex, what, from, to }: { hex: string; what: string; from: string; to: string }) {
  const b = hex.match(/../g) ?? [];
  return (
    <section>
      <h3>Reply sent back <span className="faint small">{what}, {b.length} bytes</span></h3>
      <p className="mono small">{from} <span className="faint">→</span> {to}</p>
      <pre className="hex" aria-label="Hex dump of the reply">
        {Array.from({ length: Math.ceil(b.length / 16) }, (_, row) => (
          <div key={row}><span className="faint">{(row * 16).toString(16).padStart(4, "0")}</span>
            {b.slice(row * 16, row * 16 + 16).map((x, i) => <span key={i} className="byte">{x}</span>)}</div>
        ))}
      </pre>
    </section>
  );
}
