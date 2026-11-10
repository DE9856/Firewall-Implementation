import { useSyncExternalStore } from "react";

// Per-viewer display preferences, kept in this browser only.
const KEY = "pywall.prefs";
type Prefs = { animate: boolean; intro: boolean };
let prefs: Prefs = { animate: true, intro: true };
try { prefs = { ...prefs, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; } catch { /* storage unavailable */ }
const subs = new Set<() => void>();

export function setPref<K extends keyof Prefs>(k: K, v: Prefs[K]) {
  prefs = { ...prefs, [k]: v };
  try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch { /* ignore */ }
  subs.forEach((s) => s());
}
export function usePref<K extends keyof Prefs>(k: K): Prefs[K] {
  return useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => prefs[k]);
}
