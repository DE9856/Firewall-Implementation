import { useSyncExternalStore } from "react";

export type Section = "overview" | "traffic" | "connections" | "rules" | "analytics" | "events" | "settings";
export interface Route { section: Section; params: URLSearchParams; }

const SECTIONS: Section[] = ["overview", "traffic", "connections", "rules", "analytics", "events", "settings"];

function parse(): Route {
  const [path, query = ""] = window.location.hash.replace(/^#\/?/, "").split("?");
  const section = (SECTIONS.includes(path as Section) ? path : "overview") as Section;
  return { section, params: new URLSearchParams(query) };
}

let current = parse();
const subs = new Set<() => void>();
window.addEventListener("hashchange", () => { current = parse(); subs.forEach((s) => s()); });

export function useRoute(): Route {
  return useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => current);
}

export function href(section: Section, params?: Record<string, string | number | undefined | null>) {
  const q = new URLSearchParams();
  Object.entries(params ?? {}).forEach(([k, v]) => { if (v != null && v !== "") q.set(k, String(v)); });
  const qs = q.toString();
  return `#/${section}${qs ? `?${qs}` : ""}`;
}

export function go(section: Section, params?: Record<string, string | number | undefined | null>) {
  window.location.hash = href(section, params);
}

/** Change query params of the current section without adding history noise. */
export function setParams(patch: Record<string, string | number | undefined | null>) {
  const q = new URLSearchParams(current.params);
  Object.entries(patch).forEach(([k, v]) => (v == null || v === "" ? q.delete(k) : q.set(k, String(v))));
  const qs = q.toString();
  history.replaceState(null, "", `#/${current.section}${qs ? `?${qs}` : ""}`);
  current = parse();
  subs.forEach((s) => s());
}
