// Shapes returned by PyWall's server (firewall/monitor.py, firewall/server.py).

export type Verdict = "ACCEPT" | "DROP";
export type Action = "ACCEPT" | "DROP" | "REJECT";
export type Stage = "parse" | "whitelist" | "blacklist" | "ids_ban" | "ids" | "conntrack" | "rule" | "policy";
export type Direction = "in" | "out";

export interface PacketRec {
  id: number;
  t: number;               // unix seconds
  verdict: Verdict;
  reason: string;
  stage: Stage;
  dir: Direction | null;
  state: string | null;
  rule: number | null;
  ruleName: string | null;
  idsAlert: string | null;
  rateLimited: boolean;
  header: string;           // hex of the first 60 bytes
  src: string | null;
  dst: string | null;
  sport?: number | null;
  dport?: number | null;
  proto: string;
  len: number;
  ttl?: number;
  flags?: string;
  icmpType?: number | null;
  icmpCode?: number | null;
  service: string;
  v?: 4 | 6;                // IP version
  reject?: string;          // REJECT rule: the reply sent back, e.g. "TCP RST"
  replyHeader?: string;     // ... and its header bytes (hex)
}

export type Severity = "critical" | "warning" | "notice" | "info";

export interface EventRec {
  id: number;
  kind: "ids" | "ban" | "rate" | "invalid" | "malformed" | "blacklist" | "rule" | "config" | "system";
  severity: Severity;
  title: string;
  detail: string;
  src: string | null;
  first: number;
  last: number;
  count: number;
  packets: number[];
}

export interface Stats {
  total: number;
  accepted: number;
  dropped: number;
  bytes: number;
  rate: number;
  connections: number;
  bans: number;
  rules: number;
  rulesTotal: number;
  byStage: Partial<Record<Stage, number>>;
  fastPath: number;
  uptime: number;
  rejected?: number;
  ipv6?: number;
}

export interface RuleSpec {
  id?: number;
  name?: string;
  action: Action;
  direction?: "in" | "out" | "any";
  protocol?: "tcp" | "udp" | "icmp" | "icmpv6" | "any";
  src?: string | string[];
  dst?: string | string[];
  src_port?: number | string | (number | string)[];
  dst_port?: number | string | (number | string)[];
  icmp_type?: number;
  tcp_flags?: string;
  rate_limit?: string;
  log?: boolean;
  enabled?: boolean;
}

/** From the rule-table analysis: why this rule can never decide a packet. */
export interface Finding { kind: "shadowed" | "redundant" | "never"; by: number | null; message: string; }

export interface RuleRec {
  id: number;
  position: number;
  hits: number;
  enabled: boolean;
  spec: RuleSpec;
  finding?: Finding | null;
}

export interface Ban { src: string; reason: string; remaining: number; manual?: boolean; }

export interface IdsSettings {
  enabled: boolean;
  block_seconds: number;
  syn_flood: { threshold: number; window: number };
  port_scan: { threshold: number; window: number };
  icmp_flood: { threshold: number; window: number };
}

export interface ConfigInfo {
  defaultPolicy: Verdict;
  stateful: boolean;
  dropInvalid: boolean;
  localNetworks: string[];
  blacklist: string[];
  whitelist: string[];
  pickupOutbound?: boolean;
  history?: { path: string; session: number } | null;
  ids: {
    enabled: boolean;
    blockSeconds: number;
    synFlood: { threshold: number; window: number };
    portScan: { threshold: number; window: number };
    icmpFlood: { threshold: number; window: number };
  };
  bans: Ban[];
}

export interface FlowRec {
  src: string;
  group: "local" | "external";
  path: "fast" | "rules";
  service: string;
  verdict: Verdict;
  stage: Stage;
  dir: Direction;
  proto?: string;
  dst?: string;
  rule?: number | null;
  count: number;
  bytes: number;
}

export interface SeriesPoint {
  t: number;
  ACCEPT?: number;
  DROP?: number;
  bytes?: number;
  [key: string]: number | undefined;
}

export interface Source { kind: "simulated" | "pcap" | "live"; label: string; dryRun?: boolean; readOnly?: boolean; }

export interface Snapshot {
  source: Source;
  started: number;
  now: number;
  stats: Stats;
  config: ConfigInfo;
  rules: RuleRec[];
  packets: PacketRec[];
  held?: PacketRec[];
  events: EventRec[];
  series: SeriesPoint[];
  flows: FlowRec[];
}

export interface Update {
  now: number;
  packets: PacketRec[];
  dropped: number;
  events: EventRec[];
  stats: Stats;
  flows?: FlowRec[];
  series?: SeriesPoint[];
  config?: ConfigInfo;
  rules?: RuleRec[];
}

export interface ConnRec {
  key: string;
  proto: string;
  src: string;              // the side that opened the connection
  sport: number | null;
  dst: string;
  dport: number | null;
  state: string;            // SYN_SENT | ESTABLISHED | CLOSING | UDP | ICMP
  packets: number;
  replies: number;
  bytes: number;
  opened: number;
  lastSeen: number;
  timeout: number;
  expiresIn: number;
  outbound: boolean;
}
export interface ConnTable { total: number; states: Record<string, number>; connections: ConnRec[]; }

export interface PreviewGroup {
  src: string; dir: Direction; proto: string; port: number | null; service: string | null;
  before: Verdict; after: Verdict; beforeBy: number | null; afterBy: number | null;
  beforeAction: Action | "policy"; afterAction: Action | "policy"; count: number; packets: number[];
}
export interface Preview {
  checked: number; from: number | null; to: number | null; changed: number;
  nowBlocked: number; nowAllowed: number; otherRule: number;
  groups: PreviewGroup[]; moreGroups: number; findings: Record<string, Finding>;
}

export interface Attack { kind: string; src: string; packets: number; what: string; }
export interface SessionRec { id: number; started: number; ended: number | null; source: string; lastPacket: number; dropped: number; current: boolean; }

export interface HeaderField { name: string; offset: number; length: number; value: string | number; note: string; }
export interface HeaderLayer { layer: string; offset: number; length: number; fields: HeaderField[]; }

export interface Condition { field: string; rule: string | number; packet: string | number | null; ok: boolean; }
export interface ExplainStage { stage: Stage; outcome: "pass" | "match" | "skipped"; detail: string; verdict: Verdict | null; }
export interface Explanation {
  direction: Direction;
  stages: ExplainStage[];
  rules: { id: number; name: string; action: Verdict; enabled: boolean; matched: boolean; conditions: Condition[] }[];
  verdict: Verdict;
  stage: Stage;
  detail: string;
}

export interface PacketDetail { packet: PacketRec; layers: HeaderLayer[]; explain: Explanation | null; }
