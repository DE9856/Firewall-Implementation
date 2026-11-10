import { scaleLinear } from "d3-scale";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, useStore } from "../../api/store";
import type { FlowRec, SeriesPoint } from "../../api/types";
import { PageHeader } from "../../components/Shell";
import { bytes, clock, fmt, STAGE_LABEL } from "../../lib/format";
import { href, setParams, useRoute } from "../../lib/router";
import "./analytics.css";

const RANGES = [{ s: 60, label: "1 min", bucket: 2 }, { s: 300, label: "5 min", bucket: 10 }, { s: 900, label: "15 min", bucket: 30 }];

function useHistory(window: number) {
  const [data, setData] = useState<{ flows: FlowRec[]; series: SeriesPoint[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () => api.flows(window).then((r) => { if (alive) { setData(r); setError(null); } }).catch((e: Error) => alive && setError(e.message));
    load();
    const t = setInterval(load, 3000);
    return () => { alive = false; clearInterval(t); };
  }, [window]);
  return { data, error };
}

function group<K>(fs: FlowRec[], key: (f: FlowRec) => K) {
  const m = new Map<K, { count: number; held: number; bytes: number }>();
  for (const f of fs) {
    const k = key(f);
    const g = m.get(k) ?? { count: 0, held: 0, bytes: 0 };
    g.count += f.count; g.bytes += f.bytes;
    if (f.verdict === "DROP") g.held += f.count;
    m.set(k, g);
  }
  return [...m.entries()].sort((a, b) => b[1].count - a[1].count);
}

export function Analytics() {
  const { params } = useRoute();
  const range = RANGES.find((r) => r.s === Number(params.get("range"))) ?? RANGES[1];
  const { data, error } = useHistory(range.s);
  const rules = useStore((s) => s.rules);
  const flows = data?.flows ?? [];
  const total = flows.reduce((a, f) => a + f.count, 0);
  const held = flows.filter((f) => f.verdict === "DROP").reduce((a, f) => a + f.count, 0);

  return (
    <>
      <PageHeader title="Analytics"
        finding={data ? (total ? `${fmt(total)} packets in the last ${range.label}: ${((held / total) * 100).toFixed(1)}% held, ${bytes(flows.reduce((a, f) => a + f.bytes, 0))} in total.` : `No packets in the last ${range.label}.`) : "Loading traffic history…"}>
        <div className="seg" role="group" aria-label="Time range">
          {RANGES.map((r) => <button key={r.s} aria-pressed={r.s === range.s} onClick={() => setParams({ range: r.s })}>{r.label}</button>)}
        </div>
      </PageHeader>
      {error && <div className="error-box" role="alert">Couldn't load traffic history: {error}. Retrying every 3 seconds.</div>}

      <div className="an-row first">
        <section className="panel">
          <div className="panel-head"><h2>Packets per {range.bucket} seconds</h2>
            <div className="aside"><span className="key"><i className="k allow" />Allowed, above the line</span><span className="key"><i className="k block" />Held, below</span></div></div>
          {data ? <Volume series={data.series} window={range.s} bucket={range.bucket} /> : <div className="chart-loading" />}
        </section>
        <div className="an-stack">
          <section className="panel">
            <div className="panel-head"><h2>Inbound and outbound</h2></div>
            <Split rows={group(flows, (f) => (f.dir === "in" ? "Inbound" : "Outbound"))} total={total} />
          </section>
          <section className="panel">
            <div className="panel-head"><h2>By protocol</h2></div>
            <Split rows={group(flows, (f) => (f.proto ?? "?").toUpperCase())} total={total} showBytes />
          </section>
        </div>
      </div>

      <div className="an-row lists">
        <Ranked title="Top sources" rows={group(flows, (f) => f.src)} mono link={(k) => href("traffic", { q: k })} />
        <Ranked title="Top destinations" rows={group(flows, (f) => f.dst ?? "?")} mono link={(k) => href("traffic", { q: k })} />
        <Ranked title="Rules matched" note="new connections only"
          rows={group(flows.filter((f) => f.rule != null), (f) => String(f.rule))}
          label={(k) => { const r = rules.find((x) => String(x.id) === k); return r ? `#${k} ${r.spec.name ?? ""}` : `#${k} (deleted)`; }}
          link={(k) => href("rules", { rule: k })} />
        <Ranked title="Where packets were held" heldOnly
          rows={group(flows.filter((f) => f.verdict === "DROP"), (f) => f.stage)}
          label={(k) => STAGE_LABEL[k as keyof typeof STAGE_LABEL] ?? k}
          link={(k) => href("traffic", { stage: k, verdict: "DROP" })} />
      </div>
    </>
  );
}

function Volume({ series, window, bucket }: { series: SeriesPoint[]; window: number; bucket: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(800);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    if (ref.current) ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  const now = Math.floor(Date.now() / 1000);
  const buckets = useMemo(() => {
    const start = Math.floor((now - window) / bucket) * bucket;
    const out: { t: number; a: number; d: number }[] = [];
    for (let t = start; t <= now; t += bucket) out.push({ t, a: 0, d: 0 });
    for (const p of series) {
      const i = Math.floor((p.t - start) / bucket);
      if (i >= 0 && i < out.length) { out[i].a += p.ACCEPT ?? 0; out[i].d += p.DROP ?? 0; }
    }
    return out;
  }, [series, window, bucket, now]);

  const H = 240, padL = 44, padR = 12, top = 12, bottom = 26;
  // One scale for both halves, so a held bar and an allowed bar of the same height mean the same count.
  const maxA = Math.max(1, ...buckets.map((b) => b.a)), maxD = Math.max(...buckets.map((b) => b.d), 0);
  const y = scaleLinear().domain([-Math.max(maxD, maxA * 0.15), maxA]).range([H - bottom, top]).nice(5);
  const zero = y(0);
  const px = (v: number) => y(0) - y(v);
  const ticks = y.ticks(5).filter((t) => t === 0 || Math.abs(px(t)) >= 16);
  const bw = (w - padL - padR) / buckets.length;
  const xLabelEvery = Math.ceil(buckets.length / 6);
  const hb = hover != null ? buckets[hover] : null;

  return (
    <div className="volume" ref={ref}>
      <svg width={w} height={H} role="img" aria-label="Packets over time, allowed above the zero line and held below it">
        {ticks.map((t) => (
          <g key={t}><line x1={padL} x2={w - padR} y1={y(t)} y2={y(t)} className="grid" />
            <text x={padL - 8} y={y(t) + 4} textAnchor="end" className="tick">{fmt(Math.abs(t))}</text></g>
        ))}
        <text x={padL + 6} y={top + 12} className="tick half">allowed</text>
        <text x={padL + 6} y={H - bottom - 6} className="tick half">held</text>
        {buckets.map((b, i) => (
          <g key={b.t} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
            <rect x={padL + i * bw} y={top} width={bw} height={H - top - bottom} fill="transparent" />
            {b.a > 0 && <rect x={padL + i * bw + 1} y={zero - px(b.a)} width={Math.max(1, bw - 2)} height={px(b.a)} className={`bar allow${hover === i ? " on" : ""}`} />}
            {b.d > 0 && <rect x={padL + i * bw + 1} y={zero} width={Math.max(1, bw - 2)} height={px(b.d)} fill="url(#an-held)" className={hover === i ? "on" : ""} />}
            {i % xLabelEvery === 0 && <text x={padL + i * bw + bw / 2} y={H - 8} textAnchor="middle" className="tick">{clock(b.t).slice(0, window > 300 ? 5 : 8)}</text>}
          </g>
        ))}
        <line x1={padL} x2={w - padR} y1={zero} y2={zero} className="zero" />
        <defs><pattern id="an-held" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="5" height="5" fill="#ec6a5c" fillOpacity="0.4" /><rect width="2" height="5" fill="#ec6a5c" /></pattern></defs>
      </svg>
      {hb && (
        <div className="an-tip" style={{ left: Math.min(padL + (hover! + 1) * bw + 8, w - 190) }}>
          <b className="mono">{clock(hb.t)}–{clock(hb.t + bucket)}</b>
          <span><i className="k allow" />{fmt(hb.a)} allowed</span><span><i className="k block" />{fmt(hb.d)} held</span>
        </div>
      )}
    </div>
  );
}

function Split({ rows, total, showBytes }: { rows: [string, { count: number; held: number; bytes: number }][]; total: number; showBytes?: boolean }) {
  if (!total) return <p className="empty">No packets in this range.</p>;
  return (
    <ul className="split">
      {rows.map(([k, v]) => (
        <li key={k}>
          <div className="split-head"><span>{k}</span><span className="mono">{fmt(v.count)}</span><span className="faint mono">{((v.count / total) * 100).toFixed(1)}%</span></div>
          <div className="split-bar" title={`${fmt(v.count - v.held)} allowed, ${fmt(v.held)} held`}>
            <span className="allow" style={{ width: `${((v.count - v.held) / total) * 100}%` }} />
            <span className="block" style={{ width: `${(v.held / total) * 100}%` }} />
          </div>
          <span className="faint small">{fmt(v.held)} held{showBytes ? ` · ${bytes(v.bytes)}` : ""}</span>
        </li>
      ))}
    </ul>
  );
}

function Ranked({ title, rows, mono, label, link, note, heldOnly }: {
  title: string; rows: [string, { count: number; held: number; bytes: number }][]; mono?: boolean;
  label?: (k: string) => string; link: (k: string) => string; note?: string; heldOnly?: boolean;
}) {
  const top = rows.slice(0, 8);
  const max = Math.max(1, ...top.map(([, v]) => v.count));
  return (
    <section className="panel">
      <div className="panel-head"><h2>{title}</h2>{note && <span className="aside">{note}</span>}</div>
      {top.length ? (
        <ol className="ranked">
          {top.map(([k, v]) => (
            <li key={k}>
              <a href={link(k)}>
                <span className={`ell${mono ? " mono" : ""}`}>{label ? label(k) : k}</span>
                <span className="mono">{fmt(v.count)}</span>
                <span className="rbar"><i className={heldOnly ? "block" : "allow"} style={{ width: `${((heldOnly ? v.count : v.count - v.held) / max) * 100}%` }} />
                  {!heldOnly && v.held > 0 && <i className="block" style={{ width: `${(v.held / max) * 100}%` }} />}</span>
              </a>
            </li>
          ))}
        </ol>
      ) : <p className="empty">Nothing in this range.</p>}
      {rows.length > 8 && <p className="faint small an-more">and {rows.length - 8} more</p>}
    </section>
  );
}
