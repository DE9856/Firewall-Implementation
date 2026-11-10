import type { Explanation, PacketDetail, PacketRec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { clock, endpoint, info } from "../../lib/format";
import { href } from "../../lib/router";
import type { Journey } from "./FlowMap";

const ORDER = ["parse", "whitelist", "blacklist", "ids_ban", "ids", "conntrack", "rule", "policy"] as const;

const NAME: Record<string, string> = {
  parse: "Parse", whitelist: "Lists", blacklist: "Lists", ids_ban: "Bans", ids: "IDS",
  conntrack: "State", rule: "Rules", policy: "Policy",
};

/** What a stage that let the packet carry on found, in plain words. */
function passText(stage: string, p: PacketRec, ex: Explanation | null): string {
  const exDetail = ex?.stages.find((s) => s.stage === stage)?.detail;
  switch (stage) {
    case "parse": return `Read the label: a valid ${p.proto.toUpperCase()} packet, ${p.len} bytes.`;
    case "blacklist": return "The sender is on neither the trusted nor the blocked list.";
    case "ids_ban": return "The sender is not banned.";
    case "ids": return p.dir === "in" ? "Below the attack-detection limits, so not an attack (yet)." : "Outgoing traffic is not checked for attacks.";
    case "conntrack": return "Not part of a conversation already going on, so the rules decide.";
    case "rule": return "No rule matched.";
    default: return exDetail ?? "Passed.";
  }
}

/** What the deciding stage concluded. */
function decideText(p: PacketRec): string {
  const verb = p.verdict === "ACCEPT" ? "Allowed" : "Blocked";
  switch (p.stage) {
    case "rule": return p.rateLimited
      ? `Blocked: rule ${p.rule} (${p.ruleName}) allows only a limited rate from each sender, and this one was over it.`
      : `${verb} by rule ${p.rule}: "${p.ruleName}".`;
    case "conntrack": return p.verdict === "ACCEPT"
      ? "Allowed: it is a reply in a conversation PyWall already allowed (the fast path; rules are skipped)."
      : "Blocked: it claims to belong to a conversation that never started, typical of spoofed or stray traffic.";
    case "ids_ban": return `Blocked: the sender was banned by the intrusion detector (${p.reason.split(": ").slice(1).join(": ")}).`;
    case "ids": return `Blocked: this packet tipped the sender over an attack limit: ${p.idsAlert ?? p.reason}. The sender is now banned for 60 seconds.`;
    case "blacklist": return "Blocked: the sender's network is on the blacklist.";
    case "whitelist": return "Allowed: the sender's network is on the whitelist.";
    case "policy": return `${verb} by the default policy: no rule matched, and everything else is ${p.verdict === "ACCEPT" ? "allowed" : "blocked"}.`;
    case "parse": return "Blocked: the bytes are not a valid IPv4 packet.";
    default: return `${verb}: ${p.reason}.`;
  }
}

export interface JStage { stage: string; verdict: string | null; text: string }

/** The stages the packet really went through, up to the one that decided it (from the packet's own record). */
export function buildStages(p: PacketRec, ex: Explanation | null): JStage[] {
  const out: JStage[] = [];
  for (const st of ORDER) {
    if (st === "whitelist" && p.stage !== "whitelist") continue;     // the two lists are shown as one stop
    const decided = st === p.stage;
    out.push({ stage: st, verdict: decided ? p.verdict : null, text: decided ? decideText(p) : passText(st, p, ex) });
    if (decided) break;
  }
  return out;
}

export function JourneyPanel({ detail, journey, step, speed, onPlayPause, onNext, onReplay, onAnother, onClose }: {
  detail: PacketDetail; journey: Journey; step: { step: number; done: boolean; onMap: boolean }; speed: number;
  onPlayPause: () => void; onNext: () => void; onReplay: () => void; onAnother: () => void; onClose: () => void;
}) {
  const p = detail.packet;
  const stages = journey.stages as JStage[];
  const blocked = p.verdict === "DROP";
  return (
    <div className="journey" aria-live="polite">
      <div className="panel-head">
        <div><h2>Packet <span className="mono">#{p.id}</span>'s journey</h2>
          <p className="muted small">{clock(p.t)} · {p.dir === "in" ? "coming in" : "going out"} · {p.service}</p></div>
        <button className="btn ghost small" onClick={onClose} aria-label="Close journey"><Icon name="close" size={14} /></button>
      </div>
      <p className="j-addr mono">{endpoint(p.src, p.sport)} → {endpoint(p.dst, p.dport)} <span className="faint">{p.proto.toUpperCase()} {info(p)}</span></p>
      {!step.onMap && <p className="j-note">This packet's path is not on the map right now (it may be older than the map's time window), so here is its trip stage by stage.</p>}
      <ol className="j-stages">
        {stages.map((s, i) => {
          // step k = the dot has reached stages 0..k-1; stage k-1 is where it is now
          const reached = !step.onMap || i < step.step;
          const isCurrent = step.onMap && !step.done && i === step.step - 1;
          const state = !reached ? (i === step.step ? "next" : "ahead") : s.verdict ? "decided" : isCurrent ? "current" : "passed";
          return (
            <li key={s.stage} className={`j-stage ${state}${s.verdict ? (s.verdict === "DROP" ? " block" : " allow") : ""}`}>
              <span className="j-name">{NAME[s.stage]}</span>
              <span className="j-text">{reached ? s.text : <span className="faint">…</span>}</span>
            </li>
          );
        })}
      </ol>
      {(step.done || !step.onMap) && (
        <p className={`j-result verdict ${blocked ? "block" : "allow"}`}>{blocked ? "Stopped. This packet never reached its destination." : "Delivered to its destination."}</p>
      )}
      <div className="j-controls">
        {step.onMap && <button className="btn small" onClick={onPlayPause}>{journey.playing ? "Pause" : "Play"}</button>}
        {step.onMap && <button className="btn small" onClick={onNext} disabled={step.done}>Next stage</button>}
        {step.onMap && <button className="btn small ghost" onClick={onReplay}>Replay</button>}
        <button className="btn small ghost" onClick={onAnother}>Another blocked packet</button>
      </div>
      <p className="faint small j-foot">
        Playing at {speed === 1 ? "normal speed" : `${speed}× speed`}; the dot pauses at every stage it passes.{" "}
        <a className="link" href={href("traffic", { packet: p.id })}>Full packet details</a>
      </p>
    </div>
  );
}
