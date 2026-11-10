import type { Action, PacketRec, RuleSpec, Stage } from "../api/types";

export const nf = new Intl.NumberFormat("en-US");
export const fmt = (n: number | null | undefined) => (n == null ? "—" : nf.format(n));

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function clock(t: number, ms = false): string {
  const d = new Date(t * 1000);
  const s = d.toLocaleTimeString("en-GB", { hour12: false });
  return ms ? `${s}.${String(d.getMilliseconds()).padStart(3, "0")}` : s;
}

export function ago(t: number, now: number): string {
  const s = Math.max(0, Math.round(now - t));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  return `${Math.floor(s / 3600)} h ago`;
}

export function duration(s: number): string {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

export const STAGE_LABEL: Record<Stage, string> = {
  parse: "Parse", whitelist: "Whitelist", blacklist: "Blacklist", ids_ban: "IDS ban list",
  ids: "IDS detectors", conntrack: "Connection tracking", rule: "Rule table", policy: "Default policy",
};

/** Stage names for use inside a sentence (keeps acronyms such as IDS intact). */
export const STAGE_IN_TEXT: Record<Stage, string> = {
  parse: "parser", whitelist: "whitelist", blacklist: "blacklist", ids_ban: "IDS ban list",
  ids: "IDS detectors", conntrack: "connection tracking", rule: "rule table", policy: "default policy",
};

export const STAGE_EXPLAIN: Record<Stage, string> = {
  parse: "The raw bytes are read as an IPv4 or IPv6 header and its TCP, UDP or ICMP header. Broken packets stop here.",
  whitelist: "Trusted networks are accepted at once and skip every other check.",
  blacklist: "Networks on the blacklist are dropped at once.",
  ids_ban: "Sources the intrusion detector banned recently are dropped until the ban expires.",
  ids: "Inbound packets are counted per source to catch SYN floods, port scans and ping floods.",
  conntrack: "Replies to allowed connections are accepted without checking rules. Packets that belong to no connection and cannot start one are dropped.",
  rule: "New traffic is compared with each rule from the top; the first rule that matches decides.",
  policy: "Anything no rule matched gets the default policy.",
};

export function endpoint(ip: string | null | undefined, port: number | null | undefined) {
  if (!ip) return "—";
  if (port == null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;   // IPv6 addresses are bracketed before a port
}

/** The verdict word for a packet: Allowed, Blocked or Rejected (blocked, and the sender was told). */
export function verdictWord(p: Pick<PacketRec, "verdict" | "reject">): string {
  return p.verdict === "ACCEPT" ? "Allowed" : p.reject ? "Rejected" : "Blocked";
}

export const ACTION_WORD: Record<Action, string> = { ACCEPT: "Allow", DROP: "Drop", REJECT: "Reject" };
export const actionTone = (a: Action | undefined) => (a === "ACCEPT" ? "allow" : "block");

const ICMP4: Record<number, string> = { 0: "echo reply", 3: "unreachable", 8: "echo request", 11: "time exceeded" };
const ICMP6: Record<number, string> = { 1: "unreachable", 2: "packet too big", 3: "time exceeded", 128: "echo request", 129: "echo reply",
  133: "router solicitation", 134: "router advert", 135: "neighbour solicitation", 136: "neighbour advert" };

export function info(p: PacketRec): string {
  if (p.proto === "tcp") return `[${p.flags || "."}]`;
  if (p.proto === "icmp" || p.proto === "icmpv6") {
    const k = p.proto === "icmpv6" ? ICMP6 : ICMP4;
    return `${k[p.icmpType ?? -1] ?? `type ${p.icmpType}`}`;
  }
  if (p.proto === "udp") return "datagram";
  return "unparseable";
}

export function decidedBy(p: PacketRec): string {
  if (p.stage === "rule" && p.rule != null) return p.rateLimited ? `rule ${p.rule} rate limit` : p.reject ? `rule ${p.rule}, sent ${p.reject}` : `rule ${p.rule}`;
  return STAGE_IN_TEXT[p.stage];
}

const list = (v: unknown): string[] =>
  v == null || v === "any" ? [] : (Array.isArray(v) ? v : [v]).map((x) => (x === "$LAN" ? "the local network" : String(x)));

/** A rule in one plain sentence, e.g. "Drops inbound TCP to port 22 from any source." */
export function ruleSentence(s: RuleSpec): string {
  const verb = s.action === "ACCEPT" ? "Allows" : s.action === "REJECT" ? "Rejects" : "Drops";
  const dir = s.direction === "in" ? "inbound " : s.direction === "out" ? "outbound " : "";
  const proto = s.protocol && s.protocol !== "any" ? `${s.protocol === "icmpv6" ? "ICMPv6" : s.protocol.toUpperCase()} ` : "";
  const what = `${dir}${proto}${(s.protocol === "icmp" || s.protocol === "icmpv6") && s.icmp_type != null ? `type ${s.icmp_type} ` : ""}traffic`;
  const parts = [`${verb} ${what.trim()}`];
  const dp = list(s.dst_port), sp = list(s.src_port), src = list(s.src), dst = list(s.dst);
  if (dp.length) parts.push(`to port${dp.length > 1 || dp[0].includes("-") ? "s" : ""} ${dp.join(", ")}`);
  if (sp.length) parts.push(`from source port ${sp.join(", ")}`);
  if (src.length) parts.push(`from ${src.join(", ")}`);
  if (dst.length) parts.push(`to ${dst.join(", ")}`);
  if (s.tcp_flags) parts.push(`with TCP flags ${s.tcp_flags}`);
  let out = parts.join(" ");
  if (!src.length && !dst.length && !dp.length && !sp.length && !s.tcp_flags && s.icmp_type == null) out += " of any kind";
  if (s.rate_limit) {
    const [n, unit] = s.rate_limit.split("/");
    const word = { s: "second", sec: "second", m: "minute", min: "minute", h: "hour" }[unit] ?? unit;
    out += `, up to ${n} per ${word} from each source`;
  }
  if (s.action === "REJECT") out += ", and tells the sender (TCP reset or ICMP error) so it fails at once";
  return out + ".";
}
