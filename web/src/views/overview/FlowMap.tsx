import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { onPackets, useStore } from "../../api/store";
import type { Ban, FlowRec, PacketRec } from "../../api/types";
import { bytes, fmt, STAGE_EXPLAIN } from "../../lib/format";

/** One plain phrase per stage, for hover tooltips on the stage names. */
const STAGE_PLAIN: Record<string, string> = {
  parse: "Parse: read the packet's label", lists: "Lists: always-trusted and always-blocked networks",
  bans: "Bans: attackers banned in the last minute", ids: "IDS: attack detectors",
  state: "State: replies to conversations already going on", rules: "Rules: your firewall rules, top to bottom",
  policy: "Policy: what happens to everything else",
};
import { COLUMNS, layout, matches, OTHERS, type Layout, type Ribbon, type Selection } from "./flowLayout";
import "./flowmap.css";

const MAX_DOTS = 160;
const DOTS_PER_BATCH = 24;      // the server batches every 250 ms: at most ~96 dots per second
const SPEED = 340;              // px per second

type RouteFlow = { src: string; service: string; stage: PacketRec["stage"]; verdict: "ACCEPT" | "DROP"; path: "fast" | "rules" };
// A dot remembers its packet (not a route object) and how far along its journey it is, as a
// fraction. The layout is rebuilt about once a second as totals change; the dot then
// continues on the new route from the same fraction instead of disappearing.
interface Dot { f: RouteFlow; key: string; t: number; label?: string; hold?: number; }

/** Why a blocked packet was stopped, in a few words (shown on its tag). */
export function shortReason(p: PacketRec): string {
  if (p.rateLimited) return "rate limit";
  if (p.stage === "rule" && p.rule != null) return `rule ${p.rule}: ${p.ruleName ?? ""}`.trim();
  return ({ ids_ban: "banned source", ids: "attack detected", conntrack: "no matching connection",
    policy: "default policy", blacklist: "blacklisted", whitelist: "whitelisted", parse: "malformed" } as Record<string, string>)[p.stage] ?? p.stage;
}

/** A single packet followed slowly through the pipeline, stage by stage. */
export interface Journey {
  packet: PacketRec;
  stages: { stage: string; verdict: string | null }[];   // the explanation's stages, in order
  playing: boolean;
  nonce: number;                                          // bump to restart
  advance: number;                                        // bump to skip to the next stage
}
const STAGE_NAME: Record<string, string> = { parse: "Parse", whitelist: "Lists", blacklist: "Lists", ids_ban: "Bans", ids: "IDS", conntrack: "State", rule: "Rules", policy: "Policy" };
const STAGE_COL: Record<string, number> = { parse: 0, whitelist: 1, blacklist: 1, ids_ban: 2, ids: 3, conntrack: 4, rule: 5, policy: 6 };

function usePrefersReducedMotion() {
  const [reduced, set] = useState(() => matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const mq = matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => set(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return reduced;
}

const NO_PINS: string[] = [];
const NO_BANS: Ban[] = [];   // stable empty value for useStore

export function FlowMap({ flows, selection, onSelect, animate, height, parseHeld = 0, speed = 1, onlyBlocked = false, journey = null, onJourneyStep, pinned = NO_PINS }: {
  pinned?: string[];
  flows: FlowRec[]; selection: Selection; onSelect: (s: Selection) => void; animate: boolean; height: number; parseHeld?: number;
  speed?: number; onlyBlocked?: boolean; journey?: Journey | null; onJourneyStep?: (step: number, done: boolean, onMap: boolean) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(1000);
  const [hover, setHover] = useState<{ r: Ribbon; x: number; y: number } | null>(null);
  const reduced = usePrefersReducedMotion();
  const bans = useStore((s) => s.config?.bans ?? NO_BANS);
  const maxNodes = width < 900 ? 4 : 6;

  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setWidth(Math.round(e.contentRect.width)));
    if (wrap.current) ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {   // narrow screens: the map scrolls sideways inside its panel; start at the pipeline
    if (wrap.current && wrap.current.clientWidth < 640) wrap.current.scrollLeft = Math.max(0, layoutRef.current.fx - 24);
  }, [width]);
  const L = useMemo(() => layout(flows, selection, width, height, maxNodes, parseHeld, pinned), [flows, selection, width, height, maxNodes, parseHeld, pinned]);
  const layoutRef = useRef<Layout>(L);
  layoutRef.current = L;
  const selRef = useRef(selection);
  selRef.current = selection;
  const opts = useRef({ speed, onlyBlocked, journey, onJourneyStep });
  opts.current = { speed, onlyBlocked, journey, onJourneyStep };

  // ---------------------------------------------------------- packet dots
  useEffect(() => {
    if (!animate || reduced) return;
    const cv = canvas.current!;
    const ctx = cv.getContext("2d")!;
    const dots: Dot[] = [];
    const lengths = new Map<string, number[]>();
    let raf = 0, last = performance.now();
    let lastLayout = layoutRef.current;
    // journey playback state: which stage we are heading for, and how far along the route we are
    const J = { nonce: -1, advance: 0, target: 1, s: 0, hold: 0, done: false, reportedDone: false, key: "" as string, lastStep: -1 };

    const cum = (key: string) => {
      let c = lengths.get(key);
      if (!c) {
        const pts = layoutRef.current.routes.get(key)!.pts;
        c = [0];
        for (let i = 1; i < pts.length; i++) c.push(c[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
        lengths.set(key, c);
      }
      return c;
    };
    const at = (key: string, s: number): [number, number] => {
      const c = cum(key), pts = layoutRef.current.routes.get(key)!.pts;
      let j = 1;
      while (j < c.length - 1 && c[j] < s) j++;
      const seg = c[j] - c[j - 1] || 1, f = Math.max(0, Math.min(1, (s - c[j - 1]) / seg));
      return [pts[j - 1][0] + (pts[j][0] - pts[j - 1][0]) * f, pts[j - 1][1] + (pts[j][1] - pts[j - 1][1]) * f];
    };
    const tag = (x: number, y: number, text: string, tone: "block" | "allow" | "plain") => {
      ctx.font = "500 12px 'Public Sans', system-ui, sans-serif";
      const w = ctx.measureText(text).width + 12, Lc = layoutRef.current;
      const tx = Math.min(Math.max(4, x + 8), Lc.width - w - 4), ty = Math.max(4, y - 26);
      ctx.fillStyle = "rgba(20, 21, 23, 0.92)";
      ctx.beginPath(); ctx.roundRect(tx, ty, w, 20, 4); ctx.fill();
      ctx.strokeStyle = tone === "block" ? "#ec6a5c" : tone === "allow" ? "#3fb8a9" : "#5a5d63";
      ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = "#f2f1ee"; ctx.fillText(text, tx + 6, ty + 14);
    };
    const dot = (x: number, y: number, r: number, fill: string) => {
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = fill; ctx.strokeStyle = "rgba(20, 21, 23, 0.85)"; ctx.lineWidth = 1.25;
      ctx.fill(); ctx.stroke();
    };

    // Positions (arc length) where the journey dot pauses: the source, each stage it passed, the end.
    const journeyStops = (key: string, j: Journey) => {
      const Lc = layoutRef.current, c = cum(key), pts = Lc.routes.get(key)!.pts;
      const stops = [0];
      for (const st of j.stages) {
        const col = STAGE_COL[st.stage] ?? 0;
        const x = Lc.colX[col];
        let i = 1;
        while (i < pts.length && !(pts[i][0] >= x && pts[i][0] > Lc.fx)) i++;
        stops.push(Math.max(stops[stops.length - 1], c[Math.min(i, c.length - 1)]));
        if (st.verdict) break;
      }
      stops.push(c[c.length - 1]);
      return stops;
    };

    const frame = (now: number) => {
      const o = opts.current;
      const dt = Math.min(0.05, (now - last) / 1000) * o.speed;
      last = now;
      const Lc = layoutRef.current;
      if (Lc !== lastLayout) {
        lengths.clear();
        lastLayout = Lc;
        for (let i = dots.length - 1; i >= 0; i--) {
          const key = Lc.routeKey(dots[i].f);
          if (key) dots[i].key = key; else dots.splice(i, 1);
        }
        J.key = "";
      }
      const dpr = window.devicePixelRatio || 1;
      if (cv.width !== Math.round(Lc.width * dpr) || cv.height !== Math.round(Lc.height * dpr)) {
        cv.width = Math.round(Lc.width * dpr); cv.height = Math.round(Lc.height * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, Lc.width, Lc.height);

      const j = o.journey;
      if (j) {
        // ---- one packet, slowly, stage by stage (other traffic paused) ----
        const p = j.packet;
        const f: RouteFlow = { src: p.src ?? "", service: p.service, stage: p.stage, verdict: p.verdict,
          path: p.stage === "conntrack" && p.verdict === "ACCEPT" ? "fast" : "rules" };
        if (J.nonce !== j.nonce) Object.assign(J, { nonce: j.nonce, advance: j.advance, target: 1, s: 0, hold: 0.6, done: false, reportedDone: false, lastStep: -1 });
        const key = p.src ? Lc.routeKey(f) : null;
        if (!key) {
          if (J.lastStep !== -2) { J.lastStep = -2; o.onJourneyStep?.(0, true, false); }
        } else {
          J.key = key;
          const stops = journeyStops(key, j);
          if (J.advance !== j.advance) { J.advance = j.advance; J.hold = 0; if (J.s < stops[J.target]) J.s = stops[J.target]; }
          if (j.playing && !J.done) {
            if (J.hold > 0) J.hold -= dt;
            else if (J.s < stops[J.target]) J.s = Math.min(stops[J.target], J.s + 150 * dt);
            else if (J.target < stops.length - 1) { J.target++; J.hold = J.target === 1 ? 0 : 1.6; }
            else J.done = true;
          }
          // which stage are we at? (step 0 = on its way in; step k = stage k of the explanation)
          const reached = stops.filter((st, i) => i > 0 && i < stops.length - 1 && J.s >= st - 0.5).length;
          const step = J.done ? stops.length - 2 : reached;
          if (step !== J.lastStep || (J.done && !J.reportedDone)) {
            o.onJourneyStep?.(step, J.done, true);
            J.lastStep = step;
            if (J.done) J.reportedDone = true;
          }
          const [x, y] = at(key, J.s);
          const route = Lc.routes.get(key)!;
          const decided = x >= route.decideAt - 1 || (route.verdict === "DROP" && J.done);
          dot(x, y, 6, !decided ? "#f2f1ee" : route.verdict === "ACCEPT" ? "#7fe0d3" : "#ff8f82");
          ctx.beginPath(); ctx.arc(x, y, 11, 0, Math.PI * 2);
          ctx.strokeStyle = decided ? (route.verdict === "ACCEPT" ? "#3fb8a9" : "#ec6a5c") : "#f2f1ee"; ctx.lineWidth = 1.5; ctx.stroke();
          const cur = reached > 0 ? j.stages[Math.min(reached, j.stages.length) - 1] : null;
          const text = !cur ? "on its way in" : cur.verdict ? (cur.verdict === "ACCEPT" ? `allowed at ${STAGE_NAME[cur.stage]}` : `BLOCKED at ${STAGE_NAME[cur.stage]}`) : `${STAGE_NAME[cur.stage]}: passed`;
          tag(x, y, `#${p.id} ${text}`, cur?.verdict === "DROP" ? "block" : cur?.verdict === "ACCEPT" ? "allow" : "plain");
        }
        raf = requestAnimationFrame(frame);
        return;
      }

      let tags = 0;
      for (let i = dots.length - 1; i >= 0; i--) {
        const d = dots[i];
        const route = Lc.routes.get(d.key);
        if (!route) { dots.splice(i, 1); continue; }
        const c = cum(d.key);
        const total = c[c.length - 1] || 1;
        if (d.t < 1) d.t += (SPEED * dt) / total;
        else {                                                      // arrived: blocked packets linger in their bin
          d.hold = (d.hold ?? (route.verdict === "DROP" ? (d.label ? 1.6 : 0.3) : 0)) - dt;
          if (d.hold <= 0) { dots.splice(i, 1); continue; }
        }
        if (d.t < 0) continue;
        const [x, y] = at(d.key, Math.min(d.t, 1) * total);
        const decided = x >= route.decideAt - 1 || (route.verdict === "DROP" && y > Lc.ft + 4 && x >= route.decideAt - 14 && d.t > 0.6);
        ctx.globalAlpha = d.t >= 1 && d.hold != null ? Math.min(1, d.hold / 0.3) : 1;
        dot(x, y, d.label ? 4 : 3, !decided ? "#f2f1ee" : route.verdict === "ACCEPT" ? "#d4fbf4" : "#ffd8d2");
        if (d.label && tags < 4 && (decided || o.onlyBlocked)) { tag(x, y, d.label, "block"); tags++; }
        ctx.globalAlpha = 1;
      }
      raf = dots.length || o.journey ? requestAnimationFrame(frame) : 0;
    };

    const off = onPackets((pkts: PacketRec[]) => {
      const o = opts.current;
      if (document.hidden || o.journey) return;
      const Lc = layoutRef.current;
      const sourceIps = new Set(Lc.sources.filter((s) => s.id !== OTHERS).map((s) => s.id));
      const usable = pkts.filter((p) => p.src && p.dir && (!o.onlyBlocked || p.verdict === "DROP"));
      // at slow playback fewer dots are spawned, so each one can be followed
      const perBatch = Math.max(1, Math.round(DOTS_PER_BATCH * Math.min(1, o.speed)));
      const step = Math.max(1, Math.ceil(usable.length / perBatch));
      for (let i = 0; i < usable.length && dots.length < MAX_DOTS; i += step) {
        const p = usable[i];
        const f: RouteFlow = { src: p.src!, service: p.service, stage: p.stage, verdict: p.verdict,
          path: p.stage === "conntrack" && p.verdict === "ACCEPT" ? "fast" : "rules" };
        if (!matches(selRef.current, { ...f, group: "external", dir: p.dir!, count: 1, bytes: 0 }, sourceIps)) continue;
        const key = Lc.routeKey(f);
        if (key) dots.push({ f, key, t: -Math.random() * 0.06, label: p.verdict === "DROP" ? shortReason(p) : undefined });
      }
      if (!raf && dots.length) { last = performance.now(); raf = requestAnimationFrame(frame); }
    });
    // keep the journey animating even when no traffic arrives
    const kick = setInterval(() => { if (!raf && opts.current.journey) { last = performance.now(); raf = requestAnimationFrame(frame); } }, 200);
    return () => { off(); clearInterval(kick); cancelAnimationFrame(raf); ctx.clearRect(0, 0, cv.width, cv.height); };
  }, [animate, reduced]);

  // ---------------------------------------------------------- rendering
  const sel = selection;
  const isSel = (r: Selection) => !!sel && !!r && sel.type === r.type && ("id" in sel ? (r as { id?: string }).id === sel.id : true);
  const key = (fn: () => void) => (e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fn(); } };
  const toggle = (s: Selection) => onSelect(isSel(s) ? null : s);

  return (
    <div className="flowmap" ref={wrap} style={{ height }}>
      <svg width={L.width} height={L.height} viewBox={`0 0 ${L.width} ${L.height}`} role="img"
        aria-label={`Flow of ${fmt(L.total)} packets through PyWall: sources on the left, the pipeline in the centre, destinations on the right.`}>
        <defs>
          <pattern id="held" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" fill="#ec6a5c" fillOpacity="0.38" />
            <rect width="2.2" height="6" fill="#ec6a5c" />
          </pattern>
        </defs>

        <g className="regions" aria-hidden="true">
          <text x={L.srcX + L.nodeW} y={16} textAnchor="end">Computers sending traffic</text>
          <text x={L.fx + L.fw / 2} y={16} textAnchor="middle">PyWall checks each packet, stage by stage</text>
          <text x={L.svcX} y={16}>Where allowed traffic goes</text>
        </g>
        <g className="idle">{L.idle.map((d, i) => <path key={i} d={d} />)}</g>

        <g className="frame" onClick={() => toggle({ type: "frame" })}>
          <rect x={L.fx} y={L.ft} width={L.fw} height={L.fb - L.ft} rx={6} />
          {L.colX.slice(1).map((x, i) => <line key={i} x1={x - L.colW / 2} x2={x - L.colW / 2} y1={L.ft + 6} y2={L.fb - 6} />)}
        </g>
        {COLUMNS.map((c, i) => (
          <text key={c.id} x={L.colX[i]} y={L.ft - 12} textAnchor="middle" className={`col-head${isSel({ type: "column", id: c.id }) ? " on" : ""}`}
            role="button" tabIndex={0} aria-label={`${c.label} stage`}
            onClick={() => toggle({ type: "column", id: c.id })} onKeyDown={key(() => toggle({ type: "column", id: c.id }))}>
            <title>{`${STAGE_PLAIN[c.id]}. ${STAGE_EXPLAIN[c.stages[0]]}`}</title>{c.label}</text>
        ))}

        <g className="ribbons">
          {L.ribbons.map((r) => (
            <path key={r.key} d={r.d} className={`rb ${r.kind}`} strokeWidth={Math.max(r.width, 1)}
              onMouseMove={(e) => setHover({ r, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
              onMouseLeave={() => setHover(null)}
              onClick={(e) => { e.stopPropagation(); toggle(r.ref); }} />
          ))}
        </g>

        <g className="cuts" aria-hidden="true">
          {L.colX.slice(1).map((x, i) => <line key={i} x1={x - L.colW / 2} x2={x - L.colW / 2} y1={L.ft + 4} y2={L.fb - 4} />)}
        </g>


        <g className="bins">
          {L.bins.map((b) => (
            <g key={b.col} className={`bin${isSel({ type: "column", id: COLUMNS[b.col].id }) ? " on" : ""}`} role="button" tabIndex={0}
              aria-label={`${b.count} packets blocked at ${COLUMNS[b.col].label}`}
              onClick={() => toggle({ type: "column", id: COLUMNS[b.col].id })} onKeyDown={key(() => toggle({ type: "column", id: COLUMNS[b.col].id }))}>
              <rect x={b.x - L.colW / 2 + 4} y={L.binTop} width={L.colW - 8} height={40} className="hit" />
              {b.level > 0 && <rect x={b.x - L.colW / 2 + 6} y={L.binTop + 38 - b.level} width={L.colW - 12} height={b.level} fill="url(#held)" />}
              <path d={`M${b.x - L.colW / 2 + 4},${L.binTop + 4}V${L.binTop + 40}H${b.x + L.colW / 2 - 4}V${L.binTop + 4}`} className="bin-edge" />
              <text x={b.x} y={L.binTop + 58} textAnchor="middle" className={`bin-count${b.count ? " held" : ""}`}>{fmt(b.count)}</text>
            </g>
          ))}
          <text x={L.fx} y={L.binTop + 78} className="note">Blocked, in the bin of the stage that stopped them</text>
        </g>

        <g className="nodes">
          {L.sources.map((s) => {
            const ref: Selection = { type: "source", id: s.id };
            const dim = sel && sel.type === "source" && !isSel(ref);
            return (
              <g key={s.id} className={`node src${isSel(ref) ? " on" : ""}${dim ? " dim" : ""}`} role="button" tabIndex={0}
                aria-label={`Source ${s.label}: ${s.count} packets, ${s.dropped} blocked`}
                onClick={() => toggle(ref)} onKeyDown={key(() => toggle(ref))}>
                <rect x={L.srcX} y={s.y0} width={L.nodeW} height={s.y1 - s.y0} rx={1.5} />
                <rect x={8} y={(s.y0 + s.y1) / 2 - 18} width={L.srcX - 8} height={36} className="hit" />
                <text x={L.srcX - 12} y={(s.y0 + s.y1) / 2 - 3} textAnchor="end" className={s.id === OTHERS ? "lbl" : "lbl mono"}>{s.label}{(() => {
                  const b = bans.find((x) => x.src === s.id);
                  return b ? <tspan className="banned"> banned<title>{`Banned by the IDS: ${b.reason}`}</title></tspan> : null;
                })()}</text>
                <text x={L.srcX - 12} y={(s.y0 + s.y1) / 2 + 13} textAnchor="end" className="sub">
                  {s.sub} · {fmt(s.count)}{s.dropped ? <tspan className="held"> · {fmt(s.dropped)} blocked</tspan> : null}
                </text>
              </g>
            );
          })}
          {L.services.map((s) => {
            const ref: Selection = { type: "service", id: s.id };
            const dim = sel && sel.type === "service" && !isSel(ref);
            const [name, port] = s.label.split(" :");
            return (
              <g key={s.id} className={`node svc${isSel(ref) ? " on" : ""}${dim ? " dim" : ""}`} role="button" tabIndex={0}
                aria-label={`Destination ${s.label}: ${s.count} packets allowed`}
                onClick={() => toggle(ref)} onKeyDown={key(() => toggle(ref))}>
                <rect x={L.svcX} y={s.y0} width={L.nodeW} height={s.y1 - s.y0} rx={1.5} />
                <rect x={L.svcX} y={(s.y0 + s.y1) / 2 - 18} width={L.width - L.svcX} height={36} className="hit" />
                <text x={L.svcX + 16} y={(s.y0 + s.y1) / 2 - 3} className="lbl">{name}{port && <tspan className="mono port"> :{port}</tspan>}</text>
                <text x={L.svcX + 16} y={(s.y0 + s.y1) / 2 + 13} className="sub">{fmt(s.count)} allowed</text>
              </g>
            );
          })}
        </g>
      </svg>
      <canvas ref={canvas} className="dots" style={{ width: L.width, height: L.height }} aria-hidden="true" />
      {L.total === 0 && <p className="flow-empty">No packets in this window yet. Streams appear as traffic arrives.</p>}
      {hover && (
        <div className="flow-tip" style={{ left: Math.min(hover.x + 14, L.width - 230), top: hover.y + 14 }} role="tooltip">
          <b>{hover.r.title}</b>
          <span className="mono">{fmt(hover.r.count)} packets · {bytes(hover.r.bytes)}</span>
          {L.shownTotal > 0 && <span>{((hover.r.count / L.shownTotal) * 100).toFixed(1)}% of the traffic shown</span>}
          <span className="faint">Click to {isSel(hover.r.ref) ? "clear the selection" : "follow this traffic"}</span>
        </div>
      )}
    </div>
  );
}
