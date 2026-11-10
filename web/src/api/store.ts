// Connection to PyWall: initial snapshot over HTTP, then Server-Sent Events.
// One external store for the whole app; views read it with useStore(selector).
import { useSyncExternalStore } from "react";
import type {
  Attack, ConfigInfo, ConnTable, EventRec, FlowRec, IdsSettings, PacketRec, Preview, RuleRec, SeriesPoint,
  SessionRec, Snapshot, Source, Stats, Update,
} from "./types";

export type ConnState = "connecting" | "live" | "reconnecting" | "offline";

export interface State {
  conn: ConnState;
  error: string | null;
  lastUpdate: number | null;     // unix seconds of the last server message
  serverOffset: number;          // server clock minus browser clock, seconds
  source: Source | null;
  started: number | null;
  stats: Stats | null;
  config: ConfigInfo | null;
  rules: RuleRec[];
  packets: PacketRec[];          // oldest first, capped
  held: PacketRec[];             // dropped packets only, kept longer (drops are rare)
  events: EventRec[];            // oldest first
  series: SeriesPoint[];         // per second, oldest first
  flows: FlowRec[];
  missed: number;                // packets the server skipped sending during floods
}

const MAX_PACKETS = 5000;
const MAX_EVENTS = 1000;
const MAX_HELD = 1000;
const HISTORY = 15 * 60;

let state: State = {
  conn: "connecting", error: null, lastUpdate: null, serverOffset: 0, source: null, started: null,
  stats: null, config: null, rules: [], packets: [], held: [], events: [], series: [], flows: [], missed: 0,
};
const listeners = new Set<() => void>();
const packetListeners = new Set<(p: PacketRec[]) => void>();

function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  listeners.forEach((l) => l());
}

export function getState() { return state; }

export function useStore<T>(selector: (s: State) => T): T {
  return useSyncExternalStore(
    (cb) => { listeners.add(cb); return () => listeners.delete(cb); },
    () => selector(state),
  );
}

/** Subscribe to packets as they arrive (used by the flow animation; no React re-render). */
export function onPackets(cb: (p: PacketRec[]) => void) {
  packetListeners.add(cb);
  return () => { packetListeners.delete(cb); };
}

function mergeSeries(old: SeriesPoint[], fresh: SeriesPoint[]): SeriesPoint[] {
  if (!fresh.length) return old;
  const byT = new Map(old.map((p) => [p.t, p]));
  for (const p of fresh) byT.set(p.t, p);
  const cutoff = fresh[fresh.length - 1].t - HISTORY;
  return [...byT.values()].filter((p) => p.t >= cutoff).sort((a, b) => a.t - b.t);
}

function mergeEvents(old: EventRec[], fresh: EventRec[]): EventRec[] {
  if (!fresh.length) return old;
  const byId = new Map(old.map((e) => [e.id, e]));
  for (const e of fresh) byId.set(e.id, e);
  const all = [...byId.values()].sort((a, b) => a.id - b.id);
  return all.slice(-MAX_EVENTS);
}

function applySnapshot(s: Snapshot) {
  set({
    source: s.source, started: s.started, stats: s.stats, config: s.config, rules: s.rules,
    packets: s.packets, held: s.held ?? s.packets.filter((p) => p.verdict === "DROP"), events: s.events, series: s.series, flows: s.flows,
    lastUpdate: s.now, serverOffset: s.now - Date.now() / 1000, error: null, conn: "live",
  });
}

function applyUpdate(u: Update) {
  // The first stream batch can repeat packets already in the snapshot: keep ids strictly increasing.
  const lastId = state.packets.length ? state.packets[state.packets.length - 1].id : 0;
  const fresh = u.packets.filter((p) => p.id > lastId);
  const packets = fresh.length ? state.packets.concat(fresh).slice(-MAX_PACKETS) : state.packets;
  let rules = state.rules;
  // The server sends the whole rule table once a second, so changes made elsewhere (another
  // tab, the API) appear here too. Unchanged rules keep their identity to avoid re-renders.
  if (u.rules) {
    const old = new Map(state.rules.map((r) => [r.id, r]));
    const next = u.rules.map((r) => {
      const o = old.get(r.id);
      return o && JSON.stringify(o) === JSON.stringify(r) ? o : r;
    });
    const same = next.length === state.rules.length && next.every((r, i) => r === state.rules[i]);
    if (!same) rules = next;
  }
  const freshHeld = fresh.filter((p) => p.verdict === "DROP");
  const held = freshHeld.length ? state.held.concat(freshHeld).slice(-MAX_HELD) : state.held;
  set({
    conn: "live", lastUpdate: u.now, held, serverOffset: u.now - Date.now() / 1000, stats: u.stats,
    packets, events: mergeEvents(state.events, u.events),
    series: u.series ? mergeSeries(state.series, u.series) : state.series,
    flows: u.flows ?? state.flows, config: u.config ?? state.config, rules,
    missed: state.missed + (u.dropped || 0),
  });
  if (fresh.length) packetListeners.forEach((l) => l(fresh));
}

let es: EventSource | null = null;
let retryTimer: number | undefined;

export async function refreshState() {
  const r = await fetch("/api/state", { cache: "no-store" });
  if (!r.ok) throw new Error(`server answered ${r.status}`);
  applySnapshot(await r.json());
}

export async function refreshRules() {
  const r = await fetch("/api/rules", { cache: "no-store" });
  if (r.ok) set({ rules: await r.json() });
}

export function connect() {
  clearTimeout(retryTimer);
  es?.close();
  refreshState()
    .then(() => {
      es = new EventSource("/api/stream");
      es.addEventListener("update", (e) => applyUpdate(JSON.parse((e as MessageEvent).data)));
      es.onopen = () => set({ conn: "live", error: null });
      es.onerror = () => {
        es?.close();
        set({ conn: "reconnecting" });
        retryTimer = window.setTimeout(connect, 2000);
      };
    })
    .catch((err: Error) => {
      set({ conn: state.lastUpdate ? "reconnecting" : "offline", error: err.message });
      retryTimer = window.setTimeout(connect, 3000);
    });
}

// ------------------------------------------------------------ requests
async function send<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", "X-PyWall": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `request failed (${r.status})`);
  return data as T;
}

export const api = {
  packet: async (id: number) => {
    const r = await fetch(`/api/packets/${id}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "could not load packet");
    return data;
  },
  flows: async (window: number) => {
    const r = await fetch(`/api/flows?window=${window}`, { cache: "no-store" });
    if (!r.ok) throw new Error("could not load traffic history");
    return r.json() as Promise<{ window: number; flows: FlowRec[]; series: SeriesPoint[] }>;
  },
  explain: (body: unknown) => send("POST", "/api/explain", body),
  createRule: (spec: unknown, position?: number) => send<{ id: number }>("POST", "/api/rules", { spec, position }),
  updateRule: (id: number, spec: unknown) => send<{ id: number }>("PUT", `/api/rules/${id}`, { spec }),
  deleteRule: (id: number) => send<{ id: number }>("DELETE", `/api/rules/${id}`),
  reorder: (ids: number[]) => send("POST", "/api/rules/order", { ids }),
  preview: (body: { op: string; spec?: unknown; id?: number; position?: number; ids?: number[] }) =>
    send<Preview>("POST", "/api/rules/preview", body),
  connections: async (limit = 500) => {
    const r = await fetch(`/api/connections?limit=${limit}`, { cache: "no-store" });
    if (!r.ok) throw new Error("could not load the connection table");
    return r.json() as Promise<ConnTable>;
  },
  sessions: async () => {
    const r = await fetch("/api/sessions", { cache: "no-store" });
    if (!r.ok) throw new Error("could not load saved sessions");
    return ((await r.json()) as { sessions: SessionRec[] }).sessions;
  },
  attack: (kind: string) => send<Attack>("POST", "/api/attack", { kind }),
  setIds: (body: Partial<IdsSettings>) => send<{ ids: IdsSettings }>("PUT", "/api/ids", body),
  ban: (src: string, seconds: number) => send("POST", "/api/bans", { src, seconds }),
  unban: (src: string) => send("DELETE", `/api/bans/${encodeURIComponent(src)}`),
};
