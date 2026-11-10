// Geometry of the overview flow map. Pure functions: flows in, shapes out.
//
//   sources ──► intake │ sorting frame: one column per pipeline stage │ exit ──► services
//                      │ layers re-sorted by outcome; a held layer      │
//                      │ turns down into the bin of the stage that      │
//                      │ dropped it                                     │
//
// Layer order (top to bottom) guarantees nothing crosses: accepted layers on top
// run straight out; drop layers sit underneath in reverse stage order, so each
// one turns down after every layer below it has already left.
import type { FlowRec, Stage } from "../../api/types";

export const COLUMNS: { id: string; label: string; stages: Stage[] }[] = [
  { id: "parse", label: "Parse", stages: ["parse"] },
  { id: "lists", label: "Lists", stages: ["whitelist", "blacklist"] },
  { id: "bans", label: "Bans", stages: ["ids_ban"] },
  { id: "ids", label: "IDS", stages: ["ids"] },
  { id: "state", label: "State", stages: ["conntrack"] },
  { id: "rules", label: "Rules", stages: ["rule"] },
  { id: "policy", label: "Policy", stages: ["policy"] },
];
export const STATE_COL = 4;
const colOf = (stage: Stage) => COLUMNS.findIndex((c) => c.stages.includes(stage));

export type Selection =
  | { type: "source"; id: string }
  | { type: "service"; id: string }
  | { type: "column"; id: string }
  | { type: "frame" }
  | null;

export const OTHERS = "*others";

export interface NodeBox { id: string; label: string; sub: string; count: number; dropped: number; y0: number; y1: number; group?: string; ips?: string[]; }
export interface Ribbon { key: string; d: string; width: number; kind: "transit" | "allow" | "block" | "allow-dim" | "block-dim"; count: number; bytes: number; ref: Selection; title: string; }
export interface Layer { key: string; col: number; verdict: "ACCEPT" | "DROP"; fast: boolean; count: number; bytes: number; y: number; h: number; }
export interface Bin { col: number; x: number; count: number; level: number; }

export interface Layout {
  width: number; height: number; k: number; total: number; shownTotal: number;
  srcX: number; nodeW: number; svcX: number; fx: number; fw: number; ft: number; fb: number; exitX: number; binTop: number;
  colX: number[]; colW: number;
  sources: NodeBox[]; services: NodeBox[];
  ribbons: Ribbon[];       // drawn in order
  layers: Layer[];
  bins: Bin[];
  idle: string[];          // dotted guide paths (inactive connections)
  routes: Map<string, { pts: [number, number][]; decideAt: number; verdict: "ACCEPT" | "DROP" }>;
  routeKey: (f: { src: string; service: string; stage: Stage; verdict: "ACCEPT" | "DROP"; path: "fast" | "rules" }) => string | null;
}

const curve = (x0: number, y0: number, x1: number, y1: number) => {
  const mx = (x0 + x1) / 2;
  return `M${x0},${y0}C${mx},${y0} ${mx},${y1} ${x1},${y1}`;
};

function bez(p0: number[], p1: number[], p2: number[], p3: number[], steps = 24): [number, number][] {
  const out: [number, number][] = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps, u = 1 - t;
    out.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return out;
}
const sCurve = (x0: number, y0: number, x1: number, y1: number) => {
  const mx = (x0 + x1) / 2;
  return bez([x0, y0], [mx, y0], [mx, y1], [x1, y1]);
};

export function matches(sel: Selection, f: FlowRec, sourceIps: Set<string>): boolean {
  if (!sel || sel.type === "frame") return true;
  if (sel.type === "source") return sel.id === OTHERS ? !sourceIps.has(f.src) : f.src === sel.id;
  if (sel.type === "service") return f.verdict === "ACCEPT" && (sel.id === OTHERS ? false : f.service === sel.id);
  if (sel.type === "column") {
    if (sel.id === "fast") return f.path === "fast" && f.verdict === "ACCEPT";
    const col = COLUMNS.find((c) => c.id === sel.id);
    return !!col && col.stages.includes(f.stage) && f.verdict === "DROP";
  }
  return true;
}

export function layout(input: FlowRec[], sel: Selection, width: number, height: number, maxNodes: number, parseHeld = 0): Layout {
  const W = Math.max(640, width), H = height;
  const all = input.filter((f) => colOf(f.stage) >= 0);     // every stage has a column; never file one under another
  const total = all.reduce((a, f) => a + f.count, 0);

  // ---- nodes from all traffic (stable while selecting) ----
  const bySrc = new Map<string, { count: number; dropped: number; group: string }>();
  const bySvc = new Map<string, number>();
  for (const f of all) {
    const s = bySrc.get(f.src) ?? { count: 0, dropped: 0, group: f.group };
    s.count += f.count;
    if (f.verdict === "DROP") s.dropped += f.count;
    bySrc.set(f.src, s);
    if (f.verdict === "ACCEPT") bySvc.set(f.service, (bySvc.get(f.service) ?? 0) + f.count);
  }
  const srcList = [...bySrc.entries()].sort((a, b) => b[1].count - a[1].count);
  const topSrc = srcList.slice(0, maxNodes);
  const restSrc = srcList.slice(maxNodes);
  const sourceIps = new Set(topSrc.map(([ip]) => ip));
  const svcList = [...bySvc.entries()].sort((a, b) => b[1] - a[1]);
  const topSvc = svcList.slice(0, maxNodes);
  const restSvc = svcList.slice(maxNodes);
  const serviceNames = new Set(topSvc.map(([s]) => s));
  const srcNodeOf = (ip: string) => (sourceIps.has(ip) ? ip : OTHERS);
  const svcNodeOf = (svc: string) => (serviceNames.has(svc) ? svc : OTHERS);

  // ---- horizontal frame ----
  const srcX = Math.min(196, Math.max(170, W * 0.2)), nodeW = 6;
  const svcX = W - Math.min(196, W * 0.19);
  const fw = Math.max(270, Math.min(400, W * 0.28));
  const fx = Math.round((srcX + svcX) / 2 - fw / 2 - 16);
  const colW = fw / COLUMNS.length;
  const colX = COLUMNS.map((_, i) => fx + colW * (i + 0.5));
  const exitX = fx + fw + 34;
  const top = 34, bottom = H - 24;
  const FRAME_PAD = 22, BIN_GAP = 24, BIN_AREA = 84;

  // ---- one scale for every width, so widths compare honestly ----
  const dropByCol = COLUMNS.map((_, i) => all.filter((f) => f.verdict === "DROP" && colOf(f.stage) === i).reduce((a, f) => a + f.count, 0));
  const nSrc = topSrc.length + (restSrc.length ? 1 : 0);
  const nSvc = topSvc.length + (restSvc.length ? 1 : 0);
  const minGap = 38;
  let k = total ? Math.min(
    (H - 60 - 2 * FRAME_PAD - BIN_GAP - BIN_AREA) * 0.9 / total,
    (colW - 8) / Math.max(1, ...dropByCol),
    (bottom - top - minGap * Math.max(0, nSrc - 1)) / total,
    (bottom - top - minGap * Math.max(0, nSvc - 1)) / Math.max(1, svcList.reduce((a, [, c]) => a + c, 0)),
  ) : 0;
  k = Math.max(0, k);

  const stack = (items: { id: string; label: string; sub: string; count: number; dropped: number; group?: string; ips?: string[] }[]): NodeBox[] => {
    const hs = items.map((it) => Math.max(3, it.count * k));
    const sum = hs.reduce((a, b) => a + b, 0);
    const gap = items.length > 1 ? Math.min(96, (bottom - top - sum) / (items.length - 1)) : 0;
    let y = top + (bottom - top - (sum + gap * (items.length - 1))) / 2;
    return items.map((it, i) => { const box = { ...it, y0: y, y1: y + hs[i] }; y += hs[i] + gap; return box; });
  };
  const sources = stack([
    ...topSrc.map(([ip, s]) => ({ id: ip, label: ip, sub: s.group === "local" ? "LAN" : "External", count: s.count, dropped: s.dropped, group: s.group })),
    ...(restSrc.length ? [{ id: OTHERS, label: `${restSrc.length} more sources`, sub: "Grouped", count: restSrc.reduce((a, [, s]) => a + s.count, 0),
      dropped: restSrc.reduce((a, [, s]) => a + s.dropped, 0), ips: restSrc.map(([ip]) => ip) }] : []),
  ]);
  const services = stack([
    ...topSvc.map(([svc, c]) => ({ id: svc, label: svc, sub: "", count: c, dropped: 0 })),
    ...(restSvc.length ? [{ id: OTHERS, label: `${restSvc.length} more services`, sub: "", count: restSvc.reduce((a, [, c]) => a + c, 0), dropped: 0 }] : []),
  ]);

  // ---- the selection filters what flows through; nodes stay put ----
  const flows = all.filter((f) => matches(sel, f, sourceIps));
  const shownTotal = flows.reduce((a, f) => a + f.count, 0);
  const T = total * k;
  // the frame hugs the band, the bins sit right under it, and the group is centred
  const group = 2 * FRAME_PAD + Math.max(T, 40) + BIN_GAP + BIN_AREA;
  const ft = Math.max(46, Math.round((H - group) / 2) + 16);
  const bandTop = ft + FRAME_PAD + (T < 40 ? (40 - T) / 2 : 0);
  const fb = ft + 2 * FRAME_PAD + Math.max(T, 40);
  const binTop = fb + BIN_GAP;

  // ---- layers inside the frame ----
  const layerMap = new Map<string, Layer>();
  for (const f of all) {
    const col = colOf(f.stage);
    const fast = f.path === "fast" && f.verdict === "ACCEPT";
    const key = `${f.verdict}:${fast ? "fast" : col}`;
    if (!layerMap.has(key)) layerMap.set(key, { key, col: fast ? STATE_COL : col, verdict: f.verdict, fast, count: 0, bytes: 0, y: 0, h: 0 });
  }
  for (const f of flows) {
    const fast = f.path === "fast" && f.verdict === "ACCEPT";
    const l = layerMap.get(`${f.verdict}:${fast ? "fast" : colOf(f.stage)}`)!;
    l.count += f.count; l.bytes += f.bytes;
  }
  const accepts = [...layerMap.values()].filter((l) => l.verdict === "ACCEPT").sort((a, b) => (a.fast ? -1 : b.fast ? 1 : a.col - b.col));
  const drops = [...layerMap.values()].filter((l) => l.verdict === "DROP").sort((a, b) => b.col - a.col);
  let y = bandTop;
  for (const l of [...accepts, ...drops]) { l.h = l.count * k; l.y = y + l.h / 2; y += l.h; }
  const layers = [...accepts, ...drops].filter((l) => l.count > 0);

  const ribbons: Ribbon[] = [];
  const idle: string[] = [];

  // ---- left: sources to intake (allowed part on top, held part below) ----
  let iy = bandTop;
  const intake = new Map<string, number>();
  for (const s of sources) {
    const sf = flows.filter((f) => srcNodeOf(f.src) === s.id);
    const a = sf.filter((f) => f.verdict === "ACCEPT").reduce((x, f) => x + f.count, 0);
    const d = sf.filter((f) => f.verdict === "DROP").reduce((x, f) => x + f.count, 0);
    const ab = sf.filter((f) => f.verdict === "ACCEPT").reduce((x, f) => x + f.bytes, 0);
    const db = sf.filter((f) => f.verdict === "DROP").reduce((x, f) => x + f.bytes, 0);
    idle.push(curve(srcX + nodeW, (s.y0 + s.y1) / 2, fx, bandTop + T / 2));
    intake.set(s.id, iy);
    const ref: Selection = { type: "source", id: s.id };
    if (a) ribbons.push({ key: `in-a-${s.id}`, d: curve(srcX + nodeW, s.y0 + (a * k) / 2, fx, iy + (a * k) / 2), width: a * k, kind: "allow-dim", count: a, bytes: ab, ref, title: `${s.label}: ${a} forwarded` });
    if (d) ribbons.push({ key: `in-d-${s.id}`, d: curve(srcX + nodeW, s.y0 + a * k + (d * k) / 2, fx, iy + a * k + (d * k) / 2), width: d * k, kind: "block-dim", count: d, bytes: db, ref, title: `${s.label}: ${d} held` });
    iy += (a + d) * k;
  }

  // ---- frame: layers, decisions, bins ----
  for (const l of layers) {
    const xc = colX[l.col];
    const ref: Selection = l.fast ? { type: "column", id: "fast" } : l.verdict === "DROP" ? { type: "column", id: COLUMNS[l.col].id } : { type: "frame" };
    const label = l.fast ? "Established connections (fast path)" : l.verdict === "DROP" ? `Held at ${COLUMNS[l.col].label}` : `Forwarded by ${COLUMNS[l.col].label}`;
    if (l.verdict === "ACCEPT") {
      ribbons.push({ key: `t-${l.key}`, d: `M${fx},${l.y}H${xc}`, width: l.h, kind: "transit", count: l.count, bytes: l.bytes, ref, title: label });
      ribbons.push({ key: `a-${l.key}`, d: `M${xc},${l.y}H${exitX}`, width: l.h, kind: "allow", count: l.count, bytes: l.bytes, ref, title: label });
    } else {
      const r = Math.max(l.h / 2 + 3, 10);
      ribbons.push({ key: `t-${l.key}`, d: `M${fx},${l.y}H${xc - r}`, width: l.h, kind: "transit", count: l.count, bytes: l.bytes, ref, title: label });
      ribbons.push({ key: `d-${l.key}`, d: `M${xc - r},${l.y}Q${xc},${l.y} ${xc},${l.y + r}V${binTop + 14}`, width: l.h, kind: "block", count: l.count, bytes: l.bytes, ref, title: label });
    }
  }
  // Parse drops have no source address, so they never appear as flows; their bin comes from the per-second series.
  const showParse = !sel || sel.type === "frame" || (sel.type === "column" && sel.id === "parse");
  const maxBin = Math.max(1, ...dropByCol, parseHeld);
  const bins: Bin[] = COLUMNS.map((_, i) => {
    const c = i === 0 ? (showParse ? parseHeld : 0)
      : flows.filter((f) => f.verdict === "DROP" && colOf(f.stage) === i).reduce((a, f) => a + f.count, 0);
    return { col: i, x: colX[i], count: c, level: c ? Math.max(3, (c / maxBin) * 34) : 0 };
  });

  // ---- right: exit slices to services ----
  let ey = bandTop;
  const exitAt = new Map<string, number>();
  for (const s of services) {
    const sf = flows.filter((f) => f.verdict === "ACCEPT" && svcNodeOf(f.service) === s.id);
    const c = sf.reduce((a, f) => a + f.count, 0);
    idle.push(curve(exitX, bandTop + 4, svcX, (s.y0 + s.y1) / 2));
    exitAt.set(s.id, ey);
    if (c) ribbons.push({ key: `out-${s.id}`, d: curve(exitX, ey + (c * k) / 2, svcX, s.y0 + (c * k) / 2), width: c * k, kind: "allow", count: c,
      bytes: sf.reduce((a, f) => a + f.bytes, 0), ref: { type: "service", id: s.id }, title: `${s.label}: ${c} forwarded` });
    ey += c * k;
  }

  // ---- routes for animated packets (one per source x layer x service) ----
  const routes: Layout["routes"] = new Map();
  const routeKey: Layout["routeKey"] = (f) => {
    const sNode = srcNodeOf(f.src);
    const src = sources.find((s) => s.id === sNode);
    const fast = f.path === "fast" && f.verdict === "ACCEPT";
    const layer = layerMap.get(`${f.verdict}:${fast ? "fast" : colOf(f.stage)}`);
    if (!src || !layer || layer.h <= 0) return null;
    const svc = f.verdict === "ACCEPT" ? services.find((s) => s.id === svcNodeOf(f.service)) : null;
    if (f.verdict === "ACCEPT" && !svc) return null;
    const key = `${sNode}|${layer.key}|${svc?.id ?? ""}`;
    if (!routes.has(key)) {
      const sy = (src.y0 + src.y1) / 2;
      const iy0 = (intake.get(sNode) ?? bandTop) + Math.min(T, (src.count * k)) / 2;
      const xc = colX[layer.col];
      const pts: [number, number][] = [
        ...sCurve(srcX + nodeW, sy, fx, iy0),
        ...sCurve(fx, iy0, fx + colW * 0.45, layer.y).slice(1),
      ];
      if (layer.verdict === "DROP") {
        const r = Math.max(layer.h / 2 + 3, 10);
        pts.push([xc - r, layer.y]);
        pts.push(...bez([xc - r, layer.y], [xc - r / 2, layer.y], [xc, layer.y + r / 2], [xc, layer.y + r], 8).slice(1));
        pts.push([xc, binTop + 12]);
      } else {
        const sy1 = (exitAt.get(svc!.id) ?? bandTop) + 2;
        pts.push([exitX - 26, layer.y]);
        pts.push(...sCurve(exitX - 26, layer.y, exitX, Math.max(sy1, bandTop)).slice(1));
        pts.push(...sCurve(exitX, Math.max(sy1, bandTop), svcX, (svc!.y0 + svc!.y1) / 2).slice(1));
      }
      routes.set(key, { pts, decideAt: xc, verdict: layer.verdict });
    }
    return key;
  };

  return { width: W, height: H, k, total, shownTotal, srcX, nodeW, svcX, fx, fw, ft, fb, exitX, binTop, colX, colW,
    sources, services, ribbons, layers, bins, idle, routes, routeKey };
}
