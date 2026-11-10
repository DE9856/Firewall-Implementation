// Shapes returned by PyWall's server (firewall/monitor.py, firewall/server.py).

export type Verdict = "ACCEPT" | "DROP";
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
}

export interface RuleSpec {
  id?: number;
  name?: string;
  action: Verdict;
  direction?: "in" | "out" | "any";
  protocol?: "tcp" | "udp" | "icmp" | "any";
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

export interface RuleRec {
  id: number;
  position: number;
  hits: number;
  enabled: boolean;
  spec: RuleSpec;
}

export interface Ban { src: string; reason: string; remaining: number; }

export interface ConfigInfo {
  defaultPolicy: Verdict;
  stateful: boolean;
  dropInvalid: boolean;
  localNetworks: string[];
  blacklist: string[];
  whitelist: string[];
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
  rules?: { id: number; hits: number }[];
}

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
