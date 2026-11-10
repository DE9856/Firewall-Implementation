import { useEffect, useState, type FormEvent } from "react";
import { api, useStore } from "../../api/store";
import type { Ban, IdsSettings, SessionRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/Shell";
import { clock, duration, fmt } from "../../lib/format";
import { setPref, usePref } from "../../lib/prefs";
import { href } from "../../lib/router";
import "./settings.css";

export function Settings() {
  const source = useStore((s) => s.source);
  const config = useStore((s) => s.config);
  const stats = useStore((s) => s.stats);
  const started = useStore((s) => s.started);
  const conn = useStore((s) => s.conn);
  const animate = usePref("animate");
  const list = (v: string[] | undefined) => (v && v.length ? v.join(", ") : "none");

  return (
    <>
      <PageHeader title="Settings" finding="How this dashboard is connected, and the firewall configuration it is running." />
      <div className="set-grid">
        <section className="set-row">
          <div className="set-label"><h2>Connection</h2><p className="muted">The dashboard reads PyWall's own server on this machine. It updates four times a second.</p></div>
          <dl className="panel set-panel">
            <div><dt>Status</dt><dd>{conn === "live" ? "Connected" : conn === "connecting" ? "Connecting" : "Disconnected, retrying"}</dd></div>
            <div><dt>Traffic source</dt><dd>{source?.label ?? "—"}</dd></div>
            <div><dt>Server</dt><dd className="mono">{window.location.host}</dd></div>
            <div><dt>Running since</dt><dd className="mono">{started ? `${clock(started)} · ${duration(stats?.uptime ?? 0)}` : "—"}</dd></div>
            {source?.kind === "simulated" && <div><dt>About this source</dt><dd className="muted">Real IPv4 and IPv6 packets built in code and decided by the real engine; the traffic pattern is synthetic. Use Try an attack on the overview to launch one now. Run <span className="mono">sudo python3 pywall.py serve --source live</span> for kernel traffic.</dd></div>}
          </dl>
        </section>
        <section className="set-row">
          <div className="set-label"><h2>Firewall configuration</h2><p className="muted">Set in config/rules.json. Rules can be edited on the <a className="link" href={href("rules")}>rules page</a> and intrusion detection below; these settings change only in the file.</p></div>
          <dl className="panel set-panel">
            <div><dt>Default policy</dt><dd><span className={`verdict ${config?.defaultPolicy === "ACCEPT" ? "allow" : "block"}`}>{config?.defaultPolicy === "ACCEPT" ? "Allow" : "Drop"}</span> anything no rule matches</dd></div>
            <div><dt>Stateful</dt><dd>{config ? (config.stateful ? "On: replies to allowed connections skip the rules" : "Off") : "—"}</dd></div>
            <div><dt>Drop invalid</dt><dd>{config ? (config.dropInvalid ? "On: packets that belong to no connection are dropped" : "Off") : "—"}</dd></div>
            <div><dt>Local networks</dt><dd className="mono">{list(config?.localNetworks)}</dd></div>
            <div><dt>Whitelist</dt><dd className="mono">{list(config?.whitelist)}</dd></div>
            <div><dt>Blacklist</dt><dd className="mono">{list(config?.blacklist)}</dd></div>
          </dl>
        </section>
        <IdsSection />
        <BanSection />
        <HistorySection />
        <section className="set-row">
          <div className="set-label"><h2>Display</h2><p className="muted">Kept in this browser only.</p></div>
          <div className="panel set-panel">
            <div className="set-switch">
              <div><b>Animate packets on the overview</b><p className="muted">Moves one dot per real packet along its path. Turned off automatically when your system asks for reduced motion.</p></div>
              <button className="switch" role="switch" aria-checked={animate} aria-label="Animate packets" onClick={() => setPref("animate", !animate)} />
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

type Det = "syn_flood" | "port_scan" | "icmp_flood";
const DETECTORS: [Det, string, string, string][] = [
  ["syn_flood", "SYN flood", "connection requests (SYNs)", "Many half-open connections at once, to exhaust the server."],
  ["port_scan", "Port scan", "different ports", "One source knocking on many ports, looking for an open service."],
  ["icmp_flood", "Ping flood", "pings", "Echo requests fast enough to swamp the link."],
];

function IdsSection() {
  const config = useStore((s) => s.config);
  const readOnly = useStore((s) => !!s.source?.readOnly);
  const ids = config?.ids;
  const fromConfig = (): IdsSettings | null => ids ? {
    enabled: ids.enabled, block_seconds: ids.blockSeconds,
    syn_flood: { ...ids.synFlood }, port_scan: { ...ids.portScan }, icmp_flood: { ...ids.icmpFlood },
  } : null;
  const [draft, setDraft] = useState<IdsSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const form = draft ?? fromConfig();
  if (!form) return null;
  const dirty = draft != null && JSON.stringify(draft) !== JSON.stringify(fromConfig());
  const edit = (patch: Partial<IdsSettings>) => { setDraft({ ...form, ...patch }); setSaved(false); };
  const det = (k: Det, field: "threshold" | "window", v: string) => edit({ [k]: { ...form[k], [field]: Number(v) } } as Partial<IdsSettings>);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await api.setIds(form); setDraft(null); setSaved(true); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };

  return (
    <section className="set-row">
      <div className="set-label"><h2>Intrusion detection</h2>
        <p className="muted">Counted per source address, inbound only. Crossing a limit bans the source: every packet from it is dropped until the ban ends.</p>
        <p className="muted small">Lower limits catch attacks sooner but can ban busy, honest clients. {readOnly ? "Read-only demo: shown, not editable." : "Changes apply at once and are saved to config/rules.json."}</p>
      </div>
      <form className="panel set-panel" onSubmit={save}>
        <div className="set-switch">
          <div><b>Detection</b><p className="muted">When off, nothing is counted and no one is banned. Existing bans still run out.</p></div>
          <button type="button" className="switch" role="switch" aria-checked={form.enabled} aria-label="Intrusion detection" disabled={readOnly}
            onClick={() => edit({ enabled: !form.enabled })} />
        </div>
        {DETECTORS.map(([k, label, unit, what]) => (
          <div key={k} className="set-ids">
            <dt>{label}<span className="faint small">{what}</span></dt>
            <dd className="set-inline">
              <span>more than</span>
              <input className="input mono" type="number" min={1} value={form[k].threshold} disabled={readOnly || !form.enabled}
                onChange={(e) => det(k, "threshold", e.target.value)} aria-label={`${label}: threshold`} />
              <span>{unit} in</span>
              <input className="input mono" type="number" min={0.1} step={0.1} value={form[k].window} disabled={readOnly || !form.enabled}
                onChange={(e) => det(k, "window", e.target.value)} aria-label={`${label}: window in seconds`} />
              <span>s</span>
            </dd>
          </div>
        ))}
        <div className="set-ids">
          <dt>Ban length<span className="faint small">How long a detected source stays banned.</span></dt>
          <dd className="set-inline">
            <input className="input mono" type="number" min={1} value={form.block_seconds} disabled={readOnly}
              onChange={(e) => edit({ block_seconds: Number(e.target.value) })} aria-label="Ban length in seconds" /><span>s</span>
          </dd>
        </div>
        {!readOnly && (
          <div className="set-actions">
            <button className="btn primary small" type="submit" disabled={!dirty || busy}>{busy ? "Saving…" : "Save detection settings"}</button>
            {dirty && <button className="btn ghost small" type="button" onClick={() => { setDraft(null); setError(null); }}>Discard</button>}
            {saved && !dirty && <span className="muted small" role="status">Saved and applied.</span>}
            {error && <span className="set-error small" role="alert">Not saved: {error}</span>}
          </div>
        )}
      </form>
    </section>
  );
}

const NO_BANS: Ban[] = [];   // a stable empty value: a fresh [] per read makes useSyncExternalStore loop

function BanSection() {
  const bans = useStore((s) => s.config?.bans ?? NO_BANS);
  const readOnly = useStore((s) => !!s.source?.readOnly);
  const blockSeconds = useStore((s) => s.config?.ids.blockSeconds ?? 60);
  const [src, setSrc] = useState("");
  const [secs, setSecs] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const run = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key); setError(null);
    try { await fn(); return true; } catch (e) { setError((e as Error).message); return false; } finally { setBusy(null); }
  };
  const ban = async (e: FormEvent) => {
    e.preventDefault();
    if (await run("ban", () => api.ban(src.trim(), Number(secs) || blockSeconds))) { setSrc(""); setSecs(""); }
  };

  return (
    <section className="set-row">
      <div className="set-label"><h2>Banned sources</h2>
        <p className="muted">Sources the intrusion detector caught, plus any you ban by hand. A ban drops every packet from that address, before rules are checked.</p>
      </div>
      <div className="panel set-panel">
        {bans.length === 0 ? <div className="set-full"><p className="muted">Nobody is banned right now.</p></div> : bans.map((b) => (
          <div key={b.src} className="set-ban">
            <span className="mono">{b.src}</span>
            <span className="small">{b.manual ? "banned by hand" : b.reason}<span className="faint"> · {fmt(Math.round(b.remaining))} s left</span></span>
            {!readOnly && <button className="btn small" disabled={busy === b.src} onClick={() => run(b.src, () => api.unban(b.src))}>Lift ban</button>}
          </div>
        ))}
        {!readOnly && (
          <form className="set-banform" onSubmit={ban}>
            <label><span className="sr-only">Address to ban</span>
              <input className="input mono" value={src} onChange={(e) => setSrc(e.target.value)} placeholder="IPv4 or IPv6 address" /></label>
            <label className="set-inline"><span className="sr-only">Ban length in seconds</span>
              <input className="input mono" type="number" min={1} value={secs} onChange={(e) => setSecs(e.target.value)} placeholder={String(blockSeconds)} /><span>s</span></label>
            <button className="btn small" type="submit" disabled={!src.trim() || busy === "ban"}>Ban this address</button>
          </form>
        )}
        {error && <p className="set-error small" role="alert">{error}</p>}
      </div>
    </section>
  );
}

function HistorySection() {
  const history = useStore((s) => s.config?.history);
  const [sessions, setSessions] = useState<SessionRec[] | null>(null);
  useEffect(() => { if (history) api.sessions().then(setSessions).catch(() => setSessions([])); }, [history?.session]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <section className="set-row">
      <div className="set-label"><h2>History and exports</h2>
        <p className="muted">Events, blocked packets and per-second counts are saved as they happen, so a restart doesn't lose them. Totals such as packets checked start again with each session.</p>
      </div>
      <div className="panel set-panel">
        <div><dt>Saved to</dt><dd className="mono">{history ? history.path : "Not saved: started with --no-history, so this session lives in memory only."}</dd></div>
        {history && sessions && sessions.length > 0 && (
          <div><dt>Sessions</dt><dd>
            <ul className="set-sessions">
              {sessions.slice(0, 6).map((x) => (
                <li key={x.id}><span className="mono">{clock(x.started)}</span>
                  <span className="small muted">{new Date(x.started * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short" })}</span>
                  <span className="small ell">{x.current ? "this session" : x.source}</span>
                  <span className="small faint mono">{x.current ? "running" : x.ended ? duration(Math.round(x.ended - x.started)) : "—"}</span></li>
              ))}
            </ul>
          </dd></div>
        )}
        <div><dt>Download</dt><dd className="set-downloads">
          <a className="btn small" href="/api/export/report.md" download><Icon name="download" size={14} />Session report (Markdown)</a>
          <a className="btn small" href="/api/export/blocked.pcap" download><Icon name="download" size={14} />Blocked packets (.pcap)</a>
          <p className="muted small">The report summarises totals, attacks, the most-blocked sources and rule hits. The capture opens in Wireshark; it holds each packet's headers only, which is all PyWall keeps.</p>
        </dd></div>
      </div>
    </section>
  );
}
