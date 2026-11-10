import { useStore } from "../../api/store";
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
            {source?.kind === "simulated" && <div><dt>About this source</dt><dd className="muted">Real IPv4 packets built in code and decided by the real engine; the traffic pattern is synthetic. Run <span className="mono">sudo python3 pywall.py serve --source live</span> for kernel traffic.</dd></div>}
          </dl>
        </section>
        <section className="set-row">
          <div className="set-label"><h2>Firewall configuration</h2><p className="muted">Set in config/rules.json. Rules can be edited on the <a className="link" href={href("rules")}>rules page</a>; the settings below change only in the file.</p></div>
          <dl className="panel set-panel">
            <div><dt>Default policy</dt><dd><span className={`verdict ${config?.defaultPolicy === "ACCEPT" ? "allow" : "block"}`}>{config?.defaultPolicy === "ACCEPT" ? "Allow" : "Drop"}</span> anything no rule matches</dd></div>
            <div><dt>Stateful</dt><dd>{config ? (config.stateful ? "On: replies to allowed connections skip the rules" : "Off") : "—"}</dd></div>
            <div><dt>Drop invalid</dt><dd>{config ? (config.dropInvalid ? "On: packets that belong to no connection are dropped" : "Off") : "—"}</dd></div>
            <div><dt>Local networks</dt><dd className="mono">{list(config?.localNetworks)}</dd></div>
            <div><dt>Whitelist</dt><dd className="mono">{list(config?.whitelist)}</dd></div>
            <div><dt>Blacklist</dt><dd className="mono">{list(config?.blacklist)}</dd></div>
          </dl>
        </section>
        <section className="set-row">
          <div className="set-label"><h2>Intrusion detection</h2><p className="muted">Thresholds per source address. Crossing one bans the source.</p></div>
          <dl className="panel set-panel">
            <div><dt>Status</dt><dd>{config?.ids.enabled ? "On" : "Off"}</dd></div>
            <div><dt>SYN flood</dt><dd className="mono">more than {config?.ids.synFlood.threshold} SYNs in {config?.ids.synFlood.window} s</dd></div>
            <div><dt>Port scan</dt><dd className="mono">more than {config?.ids.portScan.threshold} ports in {config?.ids.portScan.window} s</dd></div>
            <div><dt>Ping flood</dt><dd className="mono">more than {config?.ids.icmpFlood.threshold} pings in {config?.ids.icmpFlood.window} s</dd></div>
            <div><dt>Ban length</dt><dd className="mono">{config?.ids.blockSeconds} s</dd></div>
            <div><dt>Active bans</dt><dd>{config?.bans.length ? config.bans.map((b) => <span key={b.src} className="ban"><span className="mono">{b.src}</span> {b.reason}, {fmt(Math.round(b.remaining))} s left</span>) : "None"}</dd></div>
          </dl>
        </section>
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
