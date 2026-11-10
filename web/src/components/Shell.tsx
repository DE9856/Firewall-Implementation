import { useEffect, useState, type ReactNode } from "react";
import { useStore } from "../api/store";
import { clock } from "../lib/format";
import { href, type Section } from "../lib/router";
import { Icon, Mark } from "./Icon";
import "./shell.css";

const NAV: { id: Section; label: string; short: string }[] = [
  { id: "overview", label: "Overview", short: "Overview" },
  { id: "traffic", label: "Live traffic", short: "Traffic" },
  { id: "rules", label: "Firewall rules", short: "Rules" },
  { id: "analytics", label: "Analytics", short: "Analytics" },
  { id: "events", label: "Security events", short: "Events" },
];

export function Shell({ section, children }: { section: Section; children: ReactNode }) {
  const conn = useStore((s) => s.conn);
  const openEvents = useStore((s) => s.events.filter((e) => e.severity === "critical" && s.lastUpdate != null && s.lastUpdate - e.last < 300).length);
  return (
    <div className="shell">
      <nav className="rail" aria-label="Sections">
        <a className="rail-mark" href={href("overview")} aria-label="PyWall overview"><Mark /></a>
        {NAV.map((n) => (
          <a key={n.id} href={href(n.id)} className="rail-item" aria-current={section === n.id ? "page" : undefined}
            data-tip={n.label} aria-label={n.label}>
            <Icon name={n.id} />
            {n.id === "events" && openEvents > 0 && <span className="rail-count mono" aria-label={`${openEvents} IDS alerts in the last 5 minutes`}>{openEvents}</span>}
            <span className="rail-label">{n.short}</span>
          </a>
        ))}
        <div className="rail-foot">
          <a href={href("settings")} className="rail-item" aria-current={section === "settings" ? "page" : undefined} data-tip="Settings" aria-label="Settings">
            <Icon name="settings" /><span className="rail-label">Settings</span>
          </a>
          <span className={`conn-dot ${conn}`} data-tip={conn === "live" ? "Connected to PyWall" : conn === "connecting" ? "Connecting" : "Disconnected, retrying"} role="status" aria-label={`Connection: ${conn}`} />
        </div>
      </nav>
      <main className="canvas" id="main">{children}</main>
    </div>
  );
}

export function SourceBadge() {
  const source = useStore((s) => s.source);
  if (!source) return null;
  const cls = source.kind === "live" ? "allow" : source.kind === "simulated" ? "sim" : "";
  const word = source.kind === "live" ? (source.dryRun ? "Live, dry run: nothing dropped" : "Live packets")
    : source.kind === "simulated" ? "Simulated traffic" : "Capture replay";
  return <span className={`source ${cls}`} title={source.label}><i />{word}</span>;
}

function Freshness() {
  const conn = useStore((s) => s.conn);
  const last = useStore((s) => s.lastUpdate);
  const offset = useStore((s) => s.serverOffset);
  const [, tick] = useState(0);
  useEffect(() => { const t = setInterval(() => tick((n) => n + 1), 1000); return () => clearInterval(t); }, []);
  if (conn === "live" && last) return <span className="fresh">Updated {clock(last)}</span>;
  if (conn === "connecting") return <span className="fresh">Connecting to PyWall…</span>;
  const since = last ? Math.round(Date.now() / 1000 + offset - last) : null;
  return <span className="fresh stale" role="status">Disconnected{since != null ? `, last data ${since} s ago` : ""}. Retrying…</span>;
}

export function PageHeader({ title, finding, children }: { title: string; finding?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div className="page-title">
        <h1>{title}</h1>
        {finding && <p className="finding">{finding}</p>}
      </div>
      <div className="page-actions">{children}<SourceBadge /><Freshness /></div>
    </header>
  );
}
