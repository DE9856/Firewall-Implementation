import { useState, type FormEvent } from "react";
import { api, refreshRules } from "../../api/store";
import type { RuleRec, RuleSpec } from "../../api/types";
import { Icon } from "../../components/Icon";
import { ruleSentence } from "../../lib/format";

const join = (v: unknown) => (v == null ? "" : Array.isArray(v) ? v.join(", ") : String(v));
const split = (v: string): string | string[] | undefined => {
  const parts = v.split(",").map((x) => x.trim()).filter(Boolean);
  return parts.length === 0 ? undefined : parts.length === 1 ? parts[0] : parts;
};
const ports = (v: string) => {
  const s = split(v);
  const conv = (x: string) => (/^\d+$/.test(x) ? Number(x) : x);
  return s == null ? undefined : Array.isArray(s) ? s.map(conv) : conv(s);
};

export function RuleEditor({ rule, count, onDone }: { rule: RuleRec | null; count: number; onDone: (id: number | null) => void }) {
  const s = rule?.spec;
  const [f, setF] = useState({
    name: s?.name ?? "", action: s?.action ?? "DROP", direction: s?.direction ?? "in", protocol: s?.protocol ?? "tcp",
    src: join(s?.src), dst: join(s?.dst), src_port: join(s?.src_port), dst_port: join(s?.dst_port),
    icmp_type: s?.icmp_type != null ? String(s.icmp_type) : "", tcp_flags: s?.tcp_flags ?? "", rate_limit: s?.rate_limit ?? "",
    log: s?.log ?? false, enabled: s?.enabled ?? true, position: String(count + 1),
  });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const ported = f.protocol === "tcp" || f.protocol === "udp";

  const spec: RuleSpec = {
    name: f.name.trim() || undefined, action: f.action as RuleSpec["action"],
    direction: f.direction as RuleSpec["direction"], protocol: f.protocol === "any" ? undefined : (f.protocol as RuleSpec["protocol"]),
    src: split(f.src), dst: split(f.dst),
    src_port: ported ? ports(f.src_port) : undefined, dst_port: ported ? ports(f.dst_port) : undefined,
    icmp_type: f.protocol === "icmp" && f.icmp_type !== "" ? Number(f.icmp_type) : undefined,
    tcp_flags: f.protocol === "tcp" && f.tcp_flags.trim() ? f.tcp_flags.trim().toUpperCase() : undefined,
    rate_limit: f.rate_limit.trim() || undefined, log: f.log || undefined, enabled: f.enabled ? undefined : false,
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true); setError(null);
    try {
      const res = rule ? await api.updateRule(rule.id, spec) : await api.createRule(spec, Number(f.position));
      await refreshRules();
      onDone(res.id);
    } catch (err) { setError((err as Error).message); } finally { setSaving(false); }
  };

  return (
    <aside className="panel ru-panel" aria-label={rule ? `Edit rule ${rule.id}` : "New rule"}>
      <div className="panel-head">
        <h2>{rule ? `Edit rule ${rule.id}` : "New rule"}</h2>
        <button className="btn ghost small" onClick={() => onDone(rule?.id ?? null)} aria-label="Cancel"><Icon name="close" size={14} /></button>
      </div>
      <form className="ru-form" onSubmit={submit}>
        <label><span>Name</span><input className="input" value={f.name} onChange={set("name")} placeholder="Block Telnet from the internet" /></label>
        <fieldset><legend>Action</legend>
          <div className="seg">
            <button type="button" aria-pressed={f.action === "ACCEPT"} onClick={() => setF({ ...f, action: "ACCEPT" })}>Allow</button>
            <button type="button" aria-pressed={f.action === "DROP"} onClick={() => setF({ ...f, action: "DROP" })}>Drop</button>
          </div>
        </fieldset>
        <div className="two">
          <label><span>Direction</span>
            <select className="input" value={f.direction} onChange={set("direction")}>
              <option value="in">Inbound</option><option value="out">Outbound</option><option value="any">Either</option>
            </select></label>
          <label><span>Protocol</span>
            <select className="input" value={f.protocol} onChange={set("protocol")}>
              <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
            </select></label>
        </div>
        <div className="two">
          <label><span>Source</span><input className="input mono" value={f.src} onChange={set("src")} placeholder="any, $LAN, or 10.0.0.0/8" /></label>
          <label><span>Destination</span><input className="input mono" value={f.dst} onChange={set("dst")} placeholder="any" /></label>
        </div>
        {ported && (
          <div className="two">
            <label><span>Source ports</span><input className="input mono" value={f.src_port} onChange={set("src_port")} placeholder="any" /></label>
            <label><span>Destination ports</span><input className="input mono" value={f.dst_port} onChange={set("dst_port")} placeholder="22, 8000-8100" /></label>
          </div>
        )}
        {f.protocol === "icmp" && <label><span>ICMP type</span><input className="input mono" value={f.icmp_type} onChange={set("icmp_type")} placeholder="8 = echo request" inputMode="numeric" /></label>}
        {f.protocol === "tcp" && <label><span>TCP flags</span><input className="input mono" value={f.tcp_flags} onChange={set("tcp_flags")} placeholder="S!A = SYN set, ACK clear" /></label>}
        <label><span>Rate limit per source</span><input className="input mono" value={f.rate_limit} onChange={set("rate_limit")} placeholder="none, or 5/s, 60/m" /></label>
        <div className="checks">
          <label className="check"><input type="checkbox" checked={f.log} onChange={(e) => setF({ ...f, log: e.target.checked })} /> Log every match</label>
          <label className="check"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        </div>
        {!rule && (
          <label><span>Position</span>
            <select className="input" value={f.position} onChange={set("position")}>
              {Array.from({ length: count + 1 }, (_, i) => <option key={i} value={i + 1}>{i === count ? `${i + 1} (last)` : `${i + 1}${i === 0 ? " (checked first)" : ""}`}</option>)}
            </select></label>
        )}
        <div className="preview"><span className="muted small">This rule</span><p>{ruleSentence(spec)}</p></div>
        {error && <div className="error-box" role="alert">Not saved: {error}</div>}
        <div className="ru-actions">
          <button className="btn primary" type="submit" disabled={saving}>{saving ? "Saving…" : rule ? "Save rule" : "Add rule"}</button>
          <button className="btn ghost" type="button" onClick={() => onDone(rule?.id ?? null)}>Cancel</button>
          <span className="faint small">Saved to config/rules.json and applied at once.</span>
        </div>
      </form>
    </aside>
  );
}
