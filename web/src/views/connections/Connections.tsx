import { useEffect, useMemo, useState } from "react";
import { api, useStore } from "../../api/store";
import type { ConnRec, ConnTable, PacketRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/Shell";
import { bytes, clock, duration, endpoint, fmt, verdictWord } from "../../lib/format";
import { go, setParams, useRoute } from "../../lib/router";
import "./connections.css";

export const STATE_TEXT: Record<string, { label: string; explain: string }> = {
  SYN_SENT: { label: "Opening", explain: "The first SYN was allowed by a rule. PyWall is waiting for the SYN-ACK reply; if none comes within 30 s the entry is dropped." },
  ESTABLISHED: { label: "Open", explain: "The handshake finished. Every packet on this connection, either way, takes the fast path and skips the rule table." },
  CLOSING: { label: "Closing", explain: "A FIN was seen: one side is hanging up. The entry is removed 10 s after the last packet." },
  UDP: { label: "UDP flow", explain: "UDP has no handshake. Replies from the same address and port are treated as part of this flow until 60 s pass without a packet." },
  ICMP: { label: "Ping", explain: "A ping that a rule allowed. The matching echo reply is let back in for 30 s; any other reply is invalid." },
};
const TCP_STEPS = ["SYN_SENT", "ESTABLISHED", "CLOSING"];

function useConnections(paused: boolean) {
  const [data, setData] = useState<ConnTable | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () => {
      if (document.hidden || paused) return;
      api.connections(500).then((d) => { if (alive) { setData(d); setError(null); } })
        .catch((e: Error) => alive && setError(e.message));
    };
    load();
    const t = setInterval(load, 1000);
    return () => { alive = false; clearInterval(t); };
  }, [paused]);
  return { data, error };
}

const protoLabel = (p: string) => (p === "icmpv6" ? "ICMPv6" : p.toUpperCase());

function summary(d: ConnTable): string {
  if (!d.total) return "No connections are open right now. Each one appears here when a rule allows its first packet.";
  const s = d.states;
  const tcp = [s.ESTABLISHED && `${fmt(s.ESTABLISHED)} open`, s.SYN_SENT && `${fmt(s.SYN_SENT)} opening`, s.CLOSING && `${fmt(s.CLOSING)} closing`].filter(Boolean);
  const other = [s.UDP && `${fmt(s.UDP)} UDP`, s.ICMP && `${fmt(s.ICMP)} ping`].filter(Boolean);
  return `${fmt(d.total)} connection${d.total === 1 ? "" : "s"} tracked${tcp.length ? `: TCP ${tcp.join(", ")}` : ""}${other.length ? `${tcp.length ? "; " : ": "}${other.join(", ")} flows` : ""}. Their replies skip the rule table.`;
}

export function Connections() {
  const [paused, setPaused] = useState(false);
  const { data, error } = useConnections(paused);
  const { params } = useRoute();
  const proto = params.get("proto") ?? "";
  const side = params.get("side") ?? "";
  const selected = params.get("conn");
  const [q, setQ] = useState(params.get("q") ?? "");
  const [frozen, setFrozen] = useState<ConnRec | null>(null);

  const rows = useMemo(() => (data?.connections ?? []).filter((c) => {
    if (proto && (proto === "icmp" ? !c.proto.startsWith("icmp") : c.proto !== proto)) return false;
    if (side === "out" && !c.outbound) return false;
    if (side === "in" && c.outbound) return false;
    if (q) {
      const hay = `${c.src} ${c.sport ?? ""} ${c.dst} ${c.dport ?? ""} ${c.state} ${c.proto}`.toLowerCase();
      if (!q.toLowerCase().split(/\s+/).every((t) => hay.includes(t))) return false;
    }
    return true;
  }), [data, proto, side, q]);

  // Keep showing a connection after it expires from the table, so the panel doesn't vanish mid-read.
  const live = data?.connections.find((c) => c.key === selected) ?? null;
  useEffect(() => { if (live) setFrozen(live); else if (!selected) setFrozen(null); }, [live, selected]);
  const current = live ?? (frozen?.key === selected ? frozen : null);

  return (
    <>
      <PageHeader title="Connections" finding={data ? (paused ? `Paused. ${summary(data)}` : summary(data)) : "Loading the connection table…"}>
        <button className={`btn${paused ? " primary" : ""}`} onClick={() => setPaused(!paused)}>
          <Icon name={paused ? "play" : "pause"} size={14} />{paused ? "Resume" : "Pause"}
        </button>
      </PageHeader>
      <div className="tr-toolbar">
        <label className="search">
          <Icon name="search" size={14} /><span className="sr-only">Filter connections</span>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Address, port or state" />
        </label>
        <div className="seg" role="group" aria-label="Protocol">
          {[["", "All"], ["tcp", "TCP"], ["udp", "UDP"], ["icmp", "Ping"]].map(([v, l]) => (
            <button key={v} aria-pressed={proto === v} onClick={() => setParams({ proto: v })}>{l}</button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Who opened it">
          {[["", "Opened by anyone"], ["out", "By this host"], ["in", "From outside"]].map(([v, l]) => (
            <button key={v} aria-pressed={side === v} onClick={() => setParams({ side: v })}>{l}</button>
          ))}
        </div>
        <span className="tr-total muted">{fmt(rows.length)} shown{data && data.total > data.connections.length ? ` of the ${fmt(data.connections.length)} most recent` : ""}</span>
      </div>
      {error && <div className="error-box">Couldn't refresh the connection table ({error}). Retrying every second.</div>}

      <div className={`cn-body${current ? " with-panel" : ""}`}>
        <section className="panel cn-table" aria-label="Tracked connections, most recently active first">
          <table>
            <thead><tr>
              <th>Proto</th><th>Opened by</th><th>To</th><th>State</th>
              <th className="num">Packets</th><th className="num">Bytes</th><th className="num" title="Time from the first packet to the latest">Active for</th><th>Forgotten in</th>
            </tr></thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.key} className={c.key === selected ? "on" : ""} onClick={() => setParams({ conn: c.key })} aria-selected={c.key === selected}>
                  <td className="mono">{protoLabel(c.proto)}</td>
                  <td className="mono ell"><button className="row-link mono" onClick={(e) => { e.stopPropagation(); setParams({ conn: c.key }); }}>{endpoint(c.src, c.sport)}</button>
                    <span className="faint small"> {c.outbound ? "this host" : "remote"}</span></td>
                  <td className="mono ell">{endpoint(c.dst, c.dport)}</td>
                  <td><span className={`pill ${c.state === "ESTABLISHED" ? "allow" : ""}`}>{STATE_TEXT[c.state]?.label ?? c.state}</span></td>
                  <td className="num">{fmt(c.packets)} <span className="faint">({fmt(c.replies)} back)</span></td>
                  <td className="num">{bytes(c.bytes)}</td>
                  <td className="num">{duration(Math.max(0, Math.round(c.lastSeen - c.opened)))}</td>
                  <td><Expiry c={c} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && rows.length === 0 && <p className="empty">{data.total ? "No connections match these filters." : "No connections are open. They appear when a rule allows a new one."}</p>}
          {!data && !error && <p className="empty" aria-busy="true">Loading…</p>}
          <p className="ru-foot faint">{paused ? "Paused: the table is frozen until you resume." : "Refreshed every second."} PyWall forgets a connection when it has been idle for its timeout: 30 s while opening, 1 h when open, 10 s when closing, 60 s for UDP and 30 s for pings.</p>
        </section>
        {current && <ConnPanel c={current} gone={!live} onClose={() => setParams({ conn: "" })} />}
      </div>
    </>
  );
}

function Expiry({ c }: { c: ConnRec }) {
  const frac = Math.max(0, Math.min(1, c.expiresIn / c.timeout));
  const label = c.expiresIn >= 120 ? `${Math.round(c.expiresIn / 60)} min` : `${Math.max(0, Math.round(c.expiresIn))} s`;
  return (
    <span className="cn-exp" title={`Idle timeout ${duration(c.timeout)}; ${label} left unless another packet arrives`}>
      <span className="cn-track"><i style={{ width: `${frac * 100}%` }} /></span><span className="mono small">{label}</span>
    </span>
  );
}

function matches(c: ConnRec, p: PacketRec) {
  if (p.proto !== c.proto) return false;
  if (c.proto.startsWith("icmp")) return (p.src === c.src && p.dst === c.dst) || (p.src === c.dst && p.dst === c.src);
  return (p.src === c.src && p.sport === c.sport && p.dst === c.dst && p.dport === c.dport)
    || (p.src === c.dst && p.sport === c.dport && p.dst === c.src && p.dport === c.sport);
}

function label(p: PacketRec) {
  if (p.proto === "tcp") {
    const f = p.flags ?? "";
    const words = [f.includes("S") && "SYN", f.includes("F") && "FIN", f.includes("R") && "RST", f.includes("P") && "data", f.includes("A") && "ACK"].filter(Boolean);
    return words.join(" + ") || "no flags";
  }
  if (p.proto === "udp") return "datagram";
  return p.service.replace(/^ICMP(v6)? /, "");
}

function ConnPanel({ c, gone, onClose }: { c: ConnRec; gone: boolean; onClose: () => void }) {
  const packets = useStore((s) => s.packets);
  const seq = useMemo(() => packets.filter((p) => matches(c, p)), [packets, c]);
  const shown = seq.slice(-24);
  const st = STATE_TEXT[c.state];
  const tcp = c.proto === "tcp";
  const ROW = 30, W = 340, L = 56, R = W - 56;

  return (
    <aside className="panel ru-panel cn-panel" aria-label="Connection detail">
      <div className="panel-head">
        <div><h2>{protoLabel(c.proto)} connection</h2><p className="muted small">Opened {clock(c.opened)} by {c.outbound ? "this host" : "a remote host"}{gone ? " · no longer tracked" : ""}</p></div>
        <button className="btn ghost small" onClick={onClose} aria-label="Close"><Icon name="close" size={14} /></button>
      </div>
      <div className="ru-pad">
        <p className="mono addr">{endpoint(c.src, c.sport)} <span className="faint">↔</span> {endpoint(c.dst, c.dport)}</p>
      </div>

      {tcp && (
        <ol className="cn-steps" aria-label="TCP connection states">
          {[...TCP_STEPS, "gone"].map((s) => (
            <li key={s} className={(gone ? s === "gone" : s === c.state) ? "on" : ""}>{s === "gone" ? "Forgotten" : STATE_TEXT[s].label}</li>
          ))}
        </ol>
      )}
      <p className="ru-pad small">{gone ? "This connection timed out or was reset, so PyWall removed it. A new packet on it would be checked against the rules again." : st?.explain}</p>

      <dl className="cond-list">
        <div><dt>Packets</dt><dd className="mono">{fmt(c.packets - c.replies)} sent, {fmt(c.replies)} back</dd></div>
        <div><dt>Data</dt><dd className="mono">{bytes(c.bytes)}</dd></div>
        <div><dt>Idle timeout</dt><dd className="mono">{duration(c.timeout)}{gone ? "" : `, ${Math.max(0, Math.round(c.expiresIn))} s left`}</dd></div>
      </dl>

      <h3 className="ru-sub">Packets on this connection <span className="faint small">{seq.length > shown.length ? `latest ${shown.length} of ${fmt(seq.length)} kept` : `${fmt(seq.length)} kept`}</span></h3>
      {shown.length === 0 ? <p className="empty">Its packets have left the dashboard's buffer of recent packets.</p> : (
        <div className="ladder" role="img" aria-label={`Sequence of ${shown.length} packets between the two ends`}>
          <svg width="100%" viewBox={`0 0 ${W} ${shown.length * ROW + 36}`} preserveAspectRatio="xMidYMin meet">
            <text x={L} y={14} textAnchor="middle" className="lad-end">{c.outbound ? "this host" : "remote"}</text>
            <text x={R} y={14} textAnchor="middle" className="lad-end">{c.outbound ? "remote" : "this host"}</text>
            <line x1={L} x2={L} y1={22} y2={shown.length * ROW + 30} className="lad-life" />
            <line x1={R} x2={R} y1={22} y2={shown.length * ROW + 30} className="lad-life" />
            {shown.map((p, i) => {
              const fwd = p.src === c.src;
              const y = 36 + i * ROW;
              const x1 = fwd ? L : R, x2 = fwd ? R : L;
              const tone = p.verdict === "ACCEPT" ? "allow" : "block";
              const end = p.verdict === "ACCEPT" ? x2 : (x1 + x2) / 2;
              return (
                <g key={p.id} className={`lad-pkt ${tone}`} onClick={() => go("traffic", { packet: p.id })} role="link" aria-label={`Packet ${p.id}: ${label(p)}, ${verdictWord(p)}`}>
                  <title>{`#${p.id} ${clock(p.t, true)} · ${label(p)} · ${p.len} bytes · ${verdictWord(p)} at ${p.stage}`}</title>
                  <rect x={L} y={y - 16} width={R - L} height={ROW - 2} className="lad-hit" />
                  <line x1={x1} x2={end} y1={y} y2={y} />
                  {p.verdict === "ACCEPT"
                    ? <path d={fwd ? `M${x2 - 6} ${y - 4}L${x2} ${y}L${x2 - 6} ${y + 4}` : `M${x2 + 6} ${y - 4}L${x2} ${y}L${x2 + 6} ${y + 4}`} />
                    : <path d={`M${end - 4} ${y - 4}L${end + 4} ${y + 4}M${end + 4} ${y - 4}L${end - 4} ${y + 4}`} />}
                  <text x={(L + R) / 2} y={y - 5} textAnchor="middle" className="lad-label">{label(p)}</text>
                  <text x={fwd ? L - 6 : R + 6} y={y + 4} textAnchor={fwd ? "end" : "start"} className="lad-len">{p.len}</text>
                </g>
              );
            })}
          </svg>
        </div>
      )}
      <p className="ru-pad faint small">Arrows are packets in time order, with their size in bytes. A cross marks one PyWall blocked. Click one to inspect it.</p>
    </aside>
  );
}
