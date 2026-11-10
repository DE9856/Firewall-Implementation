import { useEffect, useState, type FormEvent } from "react";
import { api } from "../../api/store";
import type { Explanation } from "../../api/types";
import { Icon } from "../../components/Icon";
import { STAGE_IN_TEXT } from "../../lib/format";
import { useRoute } from "../../lib/router";

export function Tester({ onMatch, onClose }: { onMatch: (id: number | null) => void; onClose: () => void }) {
  const { params } = useRoute();
  const [f, setF] = useState({
    dir: params.get("dir") || "in", proto: params.get("proto") || "tcp", src: params.get("src") || "45.33.32.156",
    dst: params.get("dst") || "192.168.1.10", sport: params.get("sport") || "40000", dport: params.get("dport") || "22",
    flags: params.get("flags") || "S", icmpType: "8",
  });
  const [res, setRes] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const run = async (e?: FormEvent) => {
    e?.preventDefault();
    setError(null);
    try {
      const r = (await api.explain({ ...f, icmpType: Number(f.icmpType) })) as Explanation;
      setRes(r);
      onMatch(r.rules.find((x) => x.matched)?.id ?? null);
    } catch (err) { setError((err as Error).message); setRes(null); onMatch(null); }
  };
  useEffect(() => { run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <aside className="panel ru-panel" aria-label="Test a packet">
      <div className="panel-head">
        <h2>Test a packet</h2>
        <button className="btn ghost small" onClick={onClose} aria-label="Close tester"><Icon name="close" size={14} /></button>
      </div>
      <p className="ru-pad muted small">Describe a packet and see what PyWall would do with it right now. Nothing is sent and no counters change.</p>
      <form className="ru-form" onSubmit={run}>
        <div className="two">
          <label><span>Direction</span><select className="input" value={f.dir} onChange={set("dir")}><option value="in">Inbound</option><option value="out">Outbound</option></select></label>
          <label><span>Protocol</span><select className="input" value={f.proto} onChange={set("proto")}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></label>
        </div>
        <div className="two">
          <label><span>Source</span><input className="input mono" value={f.src} onChange={set("src")} /></label>
          <label><span>Destination</span><input className="input mono" value={f.dst} onChange={set("dst")} /></label>
        </div>
        {f.proto !== "icmp" ? (
          <div className="two">
            <label><span>Source port</span><input className="input mono" value={f.sport} onChange={set("sport")} inputMode="numeric" /></label>
            <label><span>Destination port</span><input className="input mono" value={f.dport} onChange={set("dport")} inputMode="numeric" /></label>
          </div>
        ) : <label><span>ICMP type</span><input className="input mono" value={f.icmpType} onChange={set("icmpType")} inputMode="numeric" /></label>}
        {f.proto === "tcp" && <label><span>TCP flags</span><input className="input mono" value={f.flags} onChange={set("flags")} placeholder="S = SYN, A = ACK, F, R, P, U" /></label>}
        <div className="ru-actions"><button className="btn primary" type="submit">Check packet</button></div>
      </form>
      {error && <div className="error-box" role="alert">{error}</div>}
      {res && (
        <div className="test-result">
          <p className={`verdict ${res.verdict === "ACCEPT" ? "allow" : "block"} big`}>{res.verdict === "ACCEPT" ? "Would be allowed" : "Would be blocked"}</p>
          <p className="small">Decided at the <b>{STAGE_IN_TEXT[res.stage]}</b>: {res.detail}.</p>
          {res.rules.length > 0 && (
            <>
              <h3 className="ru-sub">Rules checked, in order</h3>
              <ol className="checked">
                {res.rules.map((r) => (
                  <li key={r.id} className={r.matched ? "hit" : ""}>
                    <div className="checked-head"><span className="mono faint">#{r.id}</span> {r.name}
                      <span className="checked-out">{!r.enabled ? "disabled, skipped" : r.matched ? `matched: ${r.action === "ACCEPT" ? "allow" : "drop"}` : "no match"}</span></div>
                    {r.enabled && r.conditions.length > 0 && (
                      <ul>{r.conditions.map((c) => (
                        <li key={c.field} className={c.ok ? "ok" : "no"}>{c.field}: rule wants <span className="mono">{String(c.rule)}</span>, packet has <span className="mono">{c.packet ?? "none"}</span></li>
                      ))}</ul>
                    )}
                  </li>
                ))}
              </ol>
            </>
          )}
          {res.rules.length === 0 && <p className="muted small ru-pad">The rule table was not reached: an earlier stage decided.</p>}
        </div>
      )}
    </aside>
  );
}
