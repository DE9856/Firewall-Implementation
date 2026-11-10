import { useMemo } from "react";
import { useStore } from "../../api/store";
import type { EventRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/Shell";
import { clock, duration, fmt } from "../../lib/format";
import { go, href, setParams, useRoute } from "../../lib/router";
import { EventRow, SEVERITY_LABEL, SevMark } from "./EventRow";
import "./events.css";

const KINDS: { id: string; label: string; kinds: EventRec["kind"][] }[] = [
  { id: "", label: "All", kinds: [] },
  { id: "ids", label: "IDS and bans", kinds: ["ids", "ban"] },
  { id: "rate", label: "Rate limits", kinds: ["rate"] },
  { id: "held", label: "Blocked traffic", kinds: ["invalid", "malformed", "blacklist", "rule"] },
  { id: "config", label: "Configuration", kinds: ["config", "system"] },
];

const WHAT: Record<EventRec["kind"], string> = {
  ids: "PyWall's intrusion detector counts inbound packets per source in a sliding window. Crossing a threshold bans the source: every packet from it is dropped at the ban list until the ban expires.",
  ban: "A source the IDS already banned kept sending. Each of these packets was dropped at the ban list without reaching the rules.",
  rate: "The matching rule allows only a limited rate per source (a token bucket). Packets beyond that rate were dropped; the bucket refills over time.",
  invalid: "These packets claimed to belong to a connection PyWall never saw open, such as a lone ACK or an unrequested reply. That is typical of spoofed or stray traffic, so connection tracking drops them.",
  malformed: "The bytes could not be parsed as an IPv4 packet, so they were dropped at the first stage.",
  blacklist: "The source address is on the configured blacklist, so its packets are dropped before any other check.",
  rule: "A rule in the rule table decided these packets. Drops are always recorded; allowed traffic is recorded only for rules with logging on.",
  config: "A change to the rule table, applied to the running firewall and saved to config/rules.json.",
  system: "A change in PyWall itself.",
};

function MinuteStrip({ events, now }: { events: EventRec[]; now: number }) {
  const minutes = useMemo(() => {
    const end = Math.floor(now / 60) * 60;
    const out = Array.from({ length: 15 }, (_, i) => ({ t: end - (14 - i) * 60, critical: 0, warning: 0, notice: 0, info: 0 }));
    for (const e of events) {
      const i = Math.floor((e.last - out[0].t) / 60);
      if (i >= 0 && i < 15) out[i][e.severity] += 1;
    }
    return out;
  }, [events, now]);
  const max = Math.max(1, ...minutes.map((m) => m.critical + m.warning + m.notice + m.info));
  return (
    <section className="panel strip" aria-label="Events per minute, last 15 minutes">
      <div className="panel-head"><h2>Last 15 minutes</h2>
        <div className="aside">{(["critical", "warning", "notice", "info"] as const).map((s) => <span key={s} className="key"><SevMark s={s} />{SEVERITY_LABEL[s]}</span>)}</div></div>
      <div className="strip-cols">
        {minutes.map((m) => {
          const n = m.critical + m.warning + m.notice + m.info;
          return (
            <div key={m.t} className="strip-col" title={`${clock(m.t).slice(0, 5)}: ${n} events`}>
              <div className="strip-stack" style={{ height: `${(n / max) * 100}%` }}>
                {(["critical", "warning", "notice", "info"] as const).map((s) => m[s] > 0 && <span key={s} className={`st ${s}`} style={{ flexGrow: m[s] }} />)}
              </div>
              <span className="mono faint">{clock(m.t).slice(0, 5)}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function Events() {
  const events = useStore((s) => s.events);
  const last = useStore((s) => s.lastUpdate) ?? Date.now() / 1000;
  const rules = useStore((s) => s.rules);
  const { params } = useRoute();
  const kind = params.get("kind") ?? "";
  const src = params.get("src") ?? "";
  const selected = Number(params.get("event")) || null;
  const filter = KINDS.find((k) => k.id === kind) ?? KINDS[0];

  const shown = useMemo(() => events.filter((e) => (!filter.kinds.length || filter.kinds.includes(e.kind)) && (!src || e.src === src)).slice().reverse(), [events, filter, src]);
  const groups = useMemo(() => {
    const g: { minute: number; items: EventRec[] }[] = [];
    for (const e of shown) {
      const m = Math.floor(e.last / 60) * 60;
      if (!g.length || g[g.length - 1].minute !== m) g.push({ minute: m, items: [] });
      g[g.length - 1].items.push(e);
    }
    return g;
  }, [shown]);
  const sel = events.find((e) => e.id === selected) ?? null;
  const attacks = events.filter((e) => e.kind === "ids" && e.severity === "critical").length;

  return (
    <>
      <PageHeader title="Security events"
        finding={`${fmt(events.length)} events this session, ${attacks} attack${attacks === 1 ? "" : "s"} detected. Repeats from one source within 10 s are grouped into one event.`} />
      <MinuteStrip events={events} now={last} />
      <div className="ev-toolbar">
        <div className="seg" role="group" aria-label="Event type">
          {KINDS.map((k) => <button key={k.id} aria-pressed={kind === k.id} onClick={() => setParams({ kind: k.id, event: "" })}>{k.label}</button>)}
        </div>
        {src && <button className="btn small" onClick={() => setParams({ src: "" })}>From <span className="mono">{src}</span> <Icon name="close" size={12} /></button>}
        <span className="muted small ev-total">{fmt(shown.length)} shown</span>
      </div>
      <div className={`ev-body${sel ? " with-panel" : ""}`}>
        <section className="panel timeline" aria-label="Event timeline, newest first">
          {groups.length === 0 && <p className="empty">{events.length ? "No events match this filter." : "No events yet. Drops, IDS alerts and rule changes appear here as they happen."}</p>}
          {groups.map((g) => (
            <div key={g.minute} className="tl-group">
              <h3 className="tl-minute mono">{clock(g.minute).slice(0, 5)}</h3>
              <ul className="event-list">{g.items.map((e) => <EventRow key={e.id} e={e} active={e.id === selected} onOpen={() => setParams({ event: e.id })} />)}</ul>
            </div>
          ))}
        </section>
        {sel && (
          <aside className="panel ev-panel" aria-label="Event details">
            <div className="panel-head">
              <div><h2>{sel.title}</h2><p className="muted small"><SevMark s={sel.severity} /> {SEVERITY_LABEL[sel.severity]}</p></div>
              <button className="btn ghost small" onClick={() => setParams({ event: "" })} aria-label="Close"><Icon name="close" size={14} /></button>
            </div>
            <div className="ev-pad">
              <p>{sel.detail}</p>
              <dl className="ev-facts">
                {sel.src && <div><dt>Source</dt><dd className="mono"><a className="link" href={href("events", { src: sel.src })}>{sel.src}</a></dd></div>}
                <div><dt>{sel.count > 1 ? "First seen" : "Time"}</dt><dd className="mono">{clock(sel.first)}</dd></div>
                {sel.count > 1 && <div><dt>Last seen</dt><dd className="mono">{clock(sel.last)} · over {duration(Math.round(sel.last - sel.first))}</dd></div>}
                <div><dt>Occurrences</dt><dd className="mono">{fmt(sel.count)}</dd></div>
              </dl>
              <h3>What this means</h3>
              <p className="muted">{WHAT[sel.kind]}</p>
              {sel.packets.length > 0 && (
                <>
                  <h3>Packets behind it</h3>
                  <div className="ev-packets">{sel.packets.slice(-12).map((id) => <button key={id} className="btn small mono" onClick={() => go("traffic", { packet: id })}>#{id}</button>)}</div>
                  {sel.count > sel.packets.length && <p className="faint small">Showing the latest {Math.min(12, sel.packets.length)} of {fmt(sel.count)}.</p>}
                </>
              )}
              {sel.kind === "config" && /Rule (\d+)/.test(sel.title) && rules.some((r) => r.id === Number(sel.title.match(/Rule (\d+)/)![1])) && (
                <a className="btn small" href={href("rules", { rule: sel.title.match(/Rule (\d+)/)![1] })}>Open the rule</a>
              )}
              {sel.src && <a className="btn small ghost" href={href("traffic", { q: sel.src })}>All packets from this source</a>}
            </div>
          </aside>
        )}
      </div>
    </>
  );
}
