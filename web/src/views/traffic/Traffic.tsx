import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "../../api/store";
import type { PacketRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/Shell";
import { STAGE_IN_TEXT, clock, decidedBy, endpoint, fmt, info } from "../../lib/format";
import { setParams, useRoute } from "../../lib/router";
import { Inspector } from "./Inspector";
import "./traffic.css";

const ROW = 30;

function useFilter() {
  const { params } = useRoute();
  return {
    q: params.get("q") ?? "", verdict: params.get("verdict") ?? "", proto: params.get("proto") ?? "",
    dir: params.get("dir") ?? "", stage: params.get("stage") ?? "", packet: Number(params.get("packet")) || null,
  };
}

function matchesQuery(p: PacketRec, q: string) {
  if (!q) return true;
  const hay = `${p.src ?? ""}:${p.sport ?? ""} ${p.dst ?? ""}:${p.dport ?? ""} ${p.proto} ${p.service} ${p.reason} ${p.ruleName ?? ""} ${p.rule != null ? `rule ${p.rule}` : ""} ${p.flags ?? ""}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
}

export function Traffic() {
  const live = useStore((s) => s.packets);
  const heldRing = useStore((s) => s.held);
  const missed = useStore((s) => s.missed);
  const f = useFilter();
  const [paused, setPaused] = useState<PacketRec[] | null>(null);
  const [query, setQuery] = useState(f.q);
  useEffect(() => { const t = setTimeout(() => setParams({ q: query }), 150); return () => clearTimeout(t); }, [query]);

  // Drops are rare, so held packets are kept in a longer ring of their own.
  const source = paused ?? (f.verdict === "DROP" ? heldRing : live);
  const newSince = paused ? live.filter((p) => p.id > (paused[paused.length - 1]?.id ?? 0)).length : 0;

  const rows = useMemo(() => {
    const out: PacketRec[] = [];
    for (let i = source.length - 1; i >= 0; i--) {
      const p = source[i];
      if (f.verdict && p.verdict !== f.verdict) continue;
      if (f.proto && p.proto !== f.proto) continue;
      if (f.dir && p.dir !== f.dir) continue;
      if (f.stage && p.stage !== f.stage) continue;
      if (!matchesQuery(p, f.q)) continue;
      out.push(p);
    }
    return out;
  }, [source, f.verdict, f.proto, f.dir, f.stage, f.q]);

  const counts = useMemo(() => {
    let a = 0;
    (paused ?? live).forEach((p) => { if (p.verdict === "ACCEPT") a++; });
    return { a, d: paused ? paused.filter((p) => p.verdict === "DROP").length : heldRing.length };
  }, [paused, live, heldRing]);

  const selected = f.packet;
  const filtered = !!(f.verdict || f.proto || f.dir || f.stage || f.q);

  return (
    <>
      <PageHeader title="Live traffic"
        finding={paused ? `Paused at packet ${fmt(paused[paused.length - 1]?.id ?? 0)}. ${fmt(newSince)} new packets since.`
          : `Every packet PyWall has decided, newest first. Keeping the latest ${fmt(source.length)} of this session.`}>
        <button className={`btn${paused ? " primary" : ""}`} onClick={() => setPaused(paused ? null : live.slice())}>
          <Icon name={paused ? "play" : "pause"} size={14} />{paused ? `Resume${newSince ? ` (${fmt(newSince)} new)` : ""}` : "Pause"}
        </button>
      </PageHeader>

      <div className="tr-toolbar">
        <label className="search">
          <Icon name="search" size={14} />
          <span className="sr-only">Filter packets</span>
          <input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Address, port, protocol or rule" />
        </label>
        <div className="seg" role="group" aria-label="Verdict">
          <button aria-pressed={!f.verdict} onClick={() => setParams({ verdict: "" })}>All</button>
          <button aria-pressed={f.verdict === "ACCEPT"} onClick={() => setParams({ verdict: "ACCEPT" })}>Allowed<span className="count">{fmt(counts.a)}</span></button>
          <button aria-pressed={f.verdict === "DROP"} onClick={() => setParams({ verdict: "DROP" })}>Blocked<span className="count">{fmt(counts.d)}</span></button>
        </div>
        <div className="seg" role="group" aria-label="Protocol">
          {["", "tcp", "udp", "icmp"].map((p) => (
            <button key={p} aria-pressed={f.proto === p} onClick={() => setParams({ proto: p })}>{p ? p.toUpperCase() : "Any protocol"}</button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Direction">
          {[["", "Both ways"], ["in", "Inbound"], ["out", "Outbound"]].map(([v, l]) => (
            <button key={v} aria-pressed={f.dir === v} onClick={() => setParams({ dir: v })}>{l}</button>
          ))}
        </div>
        {f.stage && <button className="btn small" onClick={() => setParams({ stage: "" })}>Decided at {STAGE_IN_TEXT[f.stage as keyof typeof STAGE_IN_TEXT] ?? f.stage} <Icon name="close" size={12} /></button>}
        {filtered && <button className="link" onClick={() => { setQuery(""); setParams({ q: "", verdict: "", proto: "", dir: "", stage: "" }); }}>Clear filters</button>}
        <span className="tr-total muted">{fmt(rows.length)} shown{missed ? ` · ${fmt(missed)} skipped during floods` : ""}</span>
      </div>

      <div className={`tr-body${selected ? " with-inspector" : ""}`}>
        <PacketTable rows={rows} selected={selected} onSelect={(id) => setParams({ packet: id })} empty={filtered ? "No packets match these filters." : "No packets yet. They appear here as PyWall decides them."} />
        {selected && <Inspector key={selected} id={selected} onClose={() => setParams({ packet: "" })} />}
      </div>
    </>
  );
}

function PacketTable({ rows, selected, onSelect, empty }: { rows: PacketRec[]; selected: number | null; onSelect: (id: number) => void; empty: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState(0);
  const [height, setHeight] = useState(600);
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setHeight(e.contentRect.height));
    if (ref.current) ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  const start = Math.max(0, Math.floor(scroll / ROW) - 10);
  const end = Math.min(rows.length, Math.ceil((scroll + height) / ROW) + 10);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = rows.findIndex((r) => r.id === selected);
    const next = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) {
      onSelect(next.id);
      const idx = rows.indexOf(next), el = ref.current!;
      if (idx * ROW < el.scrollTop) el.scrollTop = idx * ROW;
      if ((idx + 1) * ROW > el.scrollTop + el.clientHeight) el.scrollTop = (idx + 1) * ROW - el.clientHeight;
    }
  };

  return (
    <section className="panel tr-table" aria-label="Packets">
      <div className="tr-head" role="row">
        <span className="num">No.</span><span>Time</span><span>Dir</span><span>Source</span><span>Destination</span>
        <span>Proto</span><span className="num">Length</span><span>Info</span><span>Verdict</span><span>Decided by</span>
      </div>
      <div className="tr-scroll" ref={ref} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} tabIndex={0} onKeyDown={onKey}
        role="grid" aria-rowcount={rows.length} aria-label="Packet list. Use the arrow keys to move between packets.">
        {rows.length === 0 ? <p className="empty">{empty}</p> : (
          <div style={{ height: rows.length * ROW, position: "relative" }}>
            {rows.slice(start, end).map((p, i) => (
              <button key={p.id} className={`tr-row${p.id === selected ? " on" : ""}${p.verdict === "DROP" ? " held" : ""}`}
                style={{ top: (start + i) * ROW }} onClick={() => onSelect(p.id)} role="row" aria-selected={p.id === selected}>
                <span className="num faint">{p.id}</span>
                <span className="mono faint">{clock(p.t, true)}</span>
                <span className="faint">{p.dir === "in" ? "In" : p.dir === "out" ? "Out" : "—"}</span>
                <span className="mono ell">{endpoint(p.src, p.sport)}</span>
                <span className="mono ell">{endpoint(p.dst, p.dport)}</span>
                <span className="mono">{p.proto.toUpperCase()}</span>
                <span className="num">{p.len}</span>
                <span className="mono ell muted">{info(p)}{p.service && p.src ? <span className="faint"> · {p.service}</span> : null}</span>
                <span className={`verdict ${p.idsAlert || p.rateLimited ? "warn" : p.verdict === "ACCEPT" ? "allow" : "block"}`}>{p.verdict === "ACCEPT" ? "Allowed" : "Blocked"}</span>
                <span className="ell muted">{decidedBy(p)}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
