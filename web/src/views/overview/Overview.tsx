import { useEffect, useMemo, useState } from "react";
import { api, useStore } from "../../api/store";
import type { FlowRec, SeriesPoint } from "../../api/types";
import { PageHeader } from "../../components/Shell";
import { EventRow } from "../events/EventRow";
import { fmt, STAGE_EXPLAIN, STAGE_IN_TEXT } from "../../lib/format";
import { setPref, usePref } from "../../lib/prefs";
import { go, href, setParams, useRoute } from "../../lib/router";
import { FlowMap } from "./FlowMap";
import { COLUMNS, OTHERS, type Selection } from "./flowLayout";
import { SelectionPanel } from "./SelectionPanel";
import "./overview.css";

function useWindowFlows(win: 60 | 300): { flows: FlowRec[]; error: string | null } {
  const live = useStore((s) => s.flows);
  const [wide, setWide] = useState<FlowRec[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (win === 60) { setWide(null); return; }
    let alive = true;
    const load = () => api.flows(win).then((r) => { if (alive) { setWide(r.flows); setError(null); } })
      .catch((e: Error) => alive && setError(e.message));
    load();
    const t = setInterval(load, 2000);
    return () => { alive = false; clearInterval(t); };
  }, [win]);
  return { flows: win === 60 ? live : wide ?? live, error };
}

function parseSel(v: string | null): Selection {
  if (!v) return null;
  if (v === "frame") return { type: "frame" };
  const i = v.indexOf(":");
  const type = v.slice(0, i), id = v.slice(i + 1);
  return type === "source" || type === "service" || type === "column" ? { type, id } as Selection : null;
}

/** The one-line finding, from the same per-second counts as the figure strip (so they always agree). */
function finding(series: SeriesPoint[], now: number, bans: { src: string; reason: string }[], win: number): string {
  const from = now - win;
  let total = 0, held = 0;
  const byStage = new Map<string, number>();
  for (const p of series) {
    if (p.t < from) continue;
    total += (p.ACCEPT ?? 0) + (p.DROP ?? 0);
    held += p.DROP ?? 0;
    for (const [k, v] of Object.entries(p)) if (k.startsWith("stage:") && v) byStage.set(k.slice(6), (byStage.get(k.slice(6)) ?? 0) + v);
  }
  const span = win === 60 ? "the last minute" : "the last 5 minutes";
  const counts = `${fmt(held)} of ${fmt(total)} packets blocked in ${span}`;
  if (bans.length) {
    const b = bans[0];
    return `${b.src} is banned for a ${b.reason.split(" (")[0]}${bans.length > 1 ? `, and ${bans.length - 1} more source${bans.length > 2 ? "s are" : " is"} banned` : ""}. ${counts}.`;
  }
  if (!total) return "Waiting for traffic.";
  if (!held) return `All ${fmt(total)} packets in ${span} were forwarded.`;
  const top = [...byStage.entries()].sort((a, b) => b[1] - a[1])[0];
  return `${counts}, most of them at the ${STAGE_IN_TEXT[top[0] as keyof typeof STAGE_IN_TEXT]}.`;
}

export function Overview() {
  const stats = useStore((s) => s.stats);
  const config = useStore((s) => s.config);
  const events = useStore((s) => s.events);
  const series = useStore((s) => s.series);
  const lastUpdate = useStore((s) => s.lastUpdate) ?? 0;
  const conn = useStore((s) => s.conn);
  const [win, setWin] = useState<60 | 300>(60);
  const { params } = useRoute();
  const selection = parseSel(params.get("sel"));
  const setSelection = (s: Selection) => setParams({ sel: s ? (s.type === "frame" ? "frame" : `${s.type}:${s.id}`) : "" });
  const animate = usePref("animate");
  const intro = usePref("intro");
  const source = useStore((s) => s.source);
  const { flows, error } = useWindowFlows(win);
  const height = useMapHeight();

  const recent = useMemo(() => events.filter((e) => e.kind !== "system").slice(-6).reverse(), [events]);
  const bans = config?.bans ?? [];
  const held = stats ? stats.dropped : 0;

  return (
    <>
      <PageHeader title="Overview" finding={stats ? finding(series, lastUpdate, bans, win) : "Loading the firewall's state…"}>
        {!intro && <button className="btn small ghost" onClick={() => setPref("intro", true)}>How to read this page</button>}
      </PageHeader>
      {intro && <Intro simulated={source?.kind === "simulated"} onClose={() => setPref("intro", false)} />}

      <section className={`figures panel${conn !== "live" && stats ? " stale" : ""}`} aria-label="Firewall totals since start">
        <Figure lead label="Packets checked" value={stats?.total} to={href("traffic")} />
        <Figure label="Allowed" value={stats?.accepted} tone="allow" to={href("traffic", { verdict: "ACCEPT" })} />
        <Figure label="Blocked" value={stats ? held : undefined} tone="block" to={href("traffic", { verdict: "DROP" })} />
        <Figure label="Speed" value={stats?.rate} unit="packets/s" to={href("analytics")} decimals />
        <Figure label="Open connections" value={stats?.connections} to={href("traffic", { stage: "conntrack" })} />
        <Figure label="Active rules" value={stats?.rules} unit={stats && stats.rulesTotal !== stats.rules ? `of ${stats.rulesTotal}` : undefined} to={href("rules")} />
        <Figure label="Banned attackers" value={stats?.bans} tone={stats?.bans ? "warn" : undefined} to={href("events", { kind: "ids" })} />
      </section>

      <div className="ov-body">
        <section className={`panel map-panel${conn !== "live" && stats ? " stale" : ""}`} aria-labelledby="map-title">
          <div className="panel-head">
            <h2 id="map-title">How packets moved through PyWall</h2>
            <div className="aside">
              <div className="seg" role="group" aria-label="Time window">
                <button aria-pressed={win === 60} onClick={() => setWin(60)}>1 min</button>
                <button aria-pressed={win === 300} onClick={() => setWin(300)}>5 min</button>
              </div>
              <button className="btn small ghost" onClick={() => setPref("animate", !animate)} aria-pressed={!animate}
                title={animate ? "Stop the packet animation" : "Animate packets"}>
                {animate ? "Pause motion" : "Show motion"}
              </button>
            </div>
          </div>
          {error && <div className="error-box">Couldn't load the 5-minute history ({error}). Showing the last minute. <button className="link" onClick={() => setWin(60)}>Switch to 1 min</button></div>}
          {!stats && conn !== "offline" ? <div className="map-loading" style={{ height }} aria-busy="true" /> :
            <FlowMap flows={flows} selection={selection} onSelect={setSelection} animate={animate && conn === "live"} height={height}
              parseHeld={series.filter((p) => p.t >= lastUpdate - win).reduce((a, p) => a + (p["stage:parse"] ?? 0), 0)} />}
          <footer className="map-legend">
            <span><i className="sw transit" />Not yet decided</span>
            <span><i className="sw allow" />Allowed</span>
            <span><i className="sw block" />Blocked</span>
            <span><i className="sw dot" />One real packet, sampled above about 100 per second</span>
            <span>Fast path: replies on known connections leave at State and skip the rules</span>
            <span className="faint">Width shows packet count. Click any stream, source, stage or bin to follow it.</span>
          </footer>
        </section>

        <aside className="panel side-panel">
          {selection ? (
            <SelectionPanel selection={selection} flows={flows} win={win} onClear={() => setSelection(null)} />
          ) : (
            <>
              <div className="panel-head"><h2>Recent events</h2>
                <div className="aside"><a className="link" href={href("events")}>View all</a></div></div>
              {recent.length ? (
                <ul className="event-list compact">{recent.map((e) => <EventRow key={e.id} e={e} compact onOpen={() => go("events", { event: e.id })} />)}</ul>
              ) : <p className="empty">No security events yet. Drops, IDS alerts and rule changes appear here.</p>}
              <div className="pipeline-key">
                <h3>Reading the pipeline</h3>
                <dl>
                  {COLUMNS.map((c) => (
                    <div key={c.id}><dt>{c.label}</dt><dd>{STAGE_EXPLAIN[c.stages[0]]}</dd></div>
                  ))}
                </dl>
              </div>
            </>
          )}
        </aside>
      </div>
    </>
  );
}

/** First-visit orientation: what PyWall is and how to read the screen. Closable; remembered in this browser. */
function Intro({ simulated, onClose }: { simulated: boolean; onClose: () => void }) {
  return (
    <section className="panel intro" aria-labelledby="intro-title">
      <div className="intro-text">
        <h2 id="intro-title">What you're looking at</h2>
        <p>
          <b>PyWall is a firewall.</b> It checks every packet of network traffic going into or out of a computer,
          lets the safe ones through and blocks the rest. This page shows it doing that in real time.
          {simulated && " The traffic here is simulated: real packets generated by the demo, including attacks."}
        </p>
      </div>
      <ul className="intro-key">
        <li><span className="verdict allow">Allowed</span><span>let through to where it was going</span></li>
        <li><span className="verdict block">Blocked</span><span>stopped by one of PyWall's checks</span></li>
        <li><span className="verdict warn">Attack detected</span><span>the sender is banned for 60 seconds</span></li>
        <li><span className="intro-dot" aria-hidden="true" /><span>each moving dot is one real packet; click anything on the map to see what it is</span></li>
      </ul>
      <button className="btn small" onClick={onClose}>Got it</button>
    </section>
  );
}

function Figure({ label, value, unit, tone, lead, to, decimals }: {
  label: string; value: number | undefined; unit?: string; tone?: "allow" | "block" | "warn"; lead?: boolean; to: string; decimals?: boolean;
}) {
  return (
    <a className={`figure${lead ? " lead" : ""}`} href={to}>
      <span className="f-label">{label}</span>
      {value == null ? <span className="skeleton" style={{ width: lead ? 96 : 56, height: lead ? 28 : 22 }} /> : (
        <b className={`f-value mono${tone ? ` ${tone}` : ""}`}>{decimals ? value.toFixed(1) : fmt(value)}{unit && <small> {unit}</small>}</b>
      )}
    </a>
  );
}

function useMapHeight() {
  const calc = () => Math.max(460, Math.min(640, window.innerHeight - 290));
  const [h, set] = useState(calc);
  useEffect(() => { const on = () => set(calc()); window.addEventListener("resize", on); return () => window.removeEventListener("resize", on); }, []);
  return h;
}

export { OTHERS };
