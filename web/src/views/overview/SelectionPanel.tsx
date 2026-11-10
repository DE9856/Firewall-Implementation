import { useMemo } from "react";
import { useStore } from "../../api/store";
import type { FlowRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { STAGE_IN_TEXT, bytes, clock, decidedBy, endpoint, fmt, STAGE_EXPLAIN } from "../../lib/format";
import { go, href } from "../../lib/router";
import { COLUMNS, OTHERS, type Selection } from "./flowLayout";

function sum(fs: FlowRec[]) { return fs.reduce((a, f) => a + f.count, 0); }

function rank<K extends string>(fs: FlowRec[], key: (f: FlowRec) => K, n = 5) {
  const m = new Map<K, number>();
  fs.forEach((f) => m.set(key(f), (m.get(key(f)) ?? 0) + f.count));
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

export function SelectionPanel({ selection, flows, win, onClear }: {
  selection: NonNullable<Selection>; flows: FlowRec[]; win: number; onClear: () => void;
}) {
  const recentAll = useStore((s) => s.packets);
  const heldRing = useStore((s) => s.held);
  const config = useStore((s) => s.config);
  const span = win === 60 ? "last minute" : "last 5 minutes";

  const { title, subtitle, scoped, explain, trafficLink, eventsLink } = useMemo(() => {
    const bySrcCount = new Map<string, number>();
    flows.forEach((f) => bySrcCount.set(f.src, (bySrcCount.get(f.src) ?? 0) + f.count));
    switch (selection.type) {
      case "source": {
        const others = selection.id === OTHERS;
        const top = new Set([...bySrcCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([ip]) => ip));
        const scoped = flows.filter((f) => (others ? !top.has(f.src) : f.src === selection.id));
        const group = scoped[0]?.group;
        const ban = config?.bans.find((b) => b.src === selection.id);
        return {
          title: others ? "Grouped smaller sources" : selection.id,
          subtitle: others ? `${new Set(scoped.map((f) => f.src)).size} addresses` : group === "local" ? "On the local network" : "External address",
          scoped,
          explain: ban ? `Banned by the IDS for ${ban.remaining.toFixed(0)} s more: ${ban.reason}.` : null,
          trafficLink: others ? href("traffic") : href("traffic", { q: selection.id }),
          eventsLink: others ? null : href("events", { src: selection.id }),
        };
      }
      case "service": {
        const scoped = flows.filter((f) => f.service === selection.id && f.verdict === "ACCEPT");
        const port = selection.id.split(":")[1];
        return { title: selection.id === OTHERS ? "Other services" : selection.id, subtitle: "Destination service, forwarded traffic",
          scoped, explain: null, trafficLink: href("traffic", { q: port ? port.trim() : "" }), eventsLink: null };
      }
      case "column": {
        if (selection.id === "fast") {
          const scoped = flows.filter((f) => f.path === "fast" && f.verdict === "ACCEPT");
          return { title: "Fast path", subtitle: "Established connections", scoped, explain: STAGE_EXPLAIN.conntrack,
            trafficLink: href("traffic", { stage: "conntrack", verdict: "ACCEPT" }), eventsLink: null };
        }
        const col = COLUMNS.find((c) => c.id === selection.id)!;
        const scoped = flows.filter((f) => col.stages.includes(f.stage) && f.verdict === "DROP");
        return { title: `${col.label} stage`, subtitle: `Packets held at ${col.stages.map((s) => STAGE_IN_TEXT[s]).join(" and ")}`,
          scoped, explain: col.stages.map((s) => STAGE_EXPLAIN[s]).join(" "),
          trafficLink: href("traffic", { stage: col.stages[0], verdict: "DROP" }), eventsLink: null };
      }
      default:
        return { title: "PyWall pipeline", subtitle: "Every packet takes the same path", scoped: flows,
          explain: "Packets enter on the left. Each stage either decides or passes the packet on; the first stage that decides wins.",
          trafficLink: href("traffic"), eventsLink: href("events") };
    }
  }, [selection, flows, config]);

  const total = sum(scoped);
  const held = sum(scoped.filter((f) => f.verdict === "DROP"));
  const recent = useMemo(() => {
    const ips = new Set(scoped.map((f) => f.src));
    const svcs = new Set(scoped.map((f) => f.service));
    const stages = new Set(scoped.map((f) => `${f.stage}:${f.verdict}`));
    const pool = new Map([...heldRing, ...recentAll].map((p) => [p.id, p]));
    const parse = selection.type === "column" && selection.id === "parse";
    return [...pool.values()].sort((a, b) => a.id - b.id)
      .filter((p) => (parse ? p.stage === "parse" : p.src && ips.has(p.src) && svcs.has(p.service) && stages.has(`${p.stage}:${p.verdict}`)))
      .slice(-6).reverse();
  }, [recentAll, heldRing, scoped, selection]);

  const rows = selection.type === "source"
    ? rank(scoped, (f) => (f.verdict === "DROP" ? `held at ${STAGE_IN_TEXT[f.stage]}` : f.service))
    : rank(scoped, (f) => f.src);
  const rowsTitle = selection.type === "source" ? "Where its packets went" : "Top sources";

  return (
    <div className="sel">
      <div className="panel-head">
        <div className="sel-title"><h2 className={selection.type === "source" && selection.id !== OTHERS ? "mono" : ""}>{title}</h2><p className="muted">{subtitle}</p></div>
        <button className="btn ghost small" onClick={onClear} aria-label="Clear selection"><Icon name="close" size={14} /></button>
      </div>
      <dl className="sel-figures">
        <div><dt>Packets, {span}</dt><dd className="mono">{fmt(total)}</dd></div>
        <div><dt>Forwarded</dt><dd className="mono allow">{fmt(total - held)}</dd></div>
        <div><dt>Held</dt><dd className="mono block">{fmt(held)}</dd></div>
        <div><dt>Volume</dt><dd className="mono">{bytes(scoped.reduce((a, f) => a + f.bytes, 0))}</dd></div>
      </dl>
      {total > 0 && (
        <div className="mix" aria-hidden="true">
          <span className="allow" style={{ flexGrow: total - held }} /><span className="block" style={{ flexGrow: held }} />
        </div>
      )}
      {explain && <p className="sel-explain">{explain}</p>}
      <h3 className="sel-sub">{rowsTitle}</h3>
      {rows.length ? (
        <ul className="sel-rank">
          {rows.map(([k, n]) => (
            <li key={k}><span className={selection.type === "source" ? "" : "mono"}>{k}</span><span className="mono">{fmt(n)}</span>
              <i style={{ width: `${(n / rows[0][1]) * 100}%` }} /></li>
          ))}
        </ul>
      ) : <p className="empty">Nothing here in the {span}.</p>}
      <h3 className="sel-sub">Latest packets</h3>
      {recent.length ? (
        <ul className="sel-packets">
          {recent.map((p) => (
            <li key={p.id}>
              <button onClick={() => go("traffic", { packet: p.id })}>
                <span className="mono faint">{clock(p.t)}</span>
                <span className="mono">{endpoint(p.src, p.sport)} → {endpoint(p.dst, p.dport)}</span>
                <span className={`verdict ${p.verdict === "ACCEPT" ? "allow" : "block"}`}>{p.verdict === "ACCEPT" ? "Allowed" : "Held"}</span>
                <span className="faint">{decidedBy(p)}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : <p className="empty">No matching packets in the recent buffer.</p>}
      <div className="sel-links">
        <a className="btn small" href={trafficLink}>Open in Live traffic <Icon name="arrow" size={14} /></a>
        {eventsLink && <a className="btn small ghost" href={eventsLink}>Related events</a>}
      </div>
    </div>
  );
}
