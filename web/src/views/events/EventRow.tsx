import type { EventRec } from "../../api/types";
import { clock } from "../../lib/format";
import "./events.css";

export const SEVERITY_LABEL = { critical: "Attack detected", warning: "Warning", notice: "Held traffic", info: "Information" } as const;

export function SevMark({ s }: { s: EventRec["severity"] }) {
  return <i className={`sev ${s}`} aria-label={SEVERITY_LABEL[s]} role="img" />;
}

export function EventRow({ e, compact, active, onOpen }: { e: EventRec; compact?: boolean; active?: boolean; onOpen: () => void }) {
  return (
    <li className={`ev-row${compact ? " compact" : ""}${active ? " active" : ""}`}>
      <button onClick={onOpen} aria-current={active || undefined}>
        <span className="mono faint ev-time">{clock(e.last)}</span>
        <SevMark s={e.severity} />
        <span className="ev-text">
          <span className="ev-title">{e.title}{e.count > 1 && <span className="ev-count mono"> ×{e.count}</span>}</span>
          <span className="ev-detail">{e.src && <span className="mono">{e.src} · </span>}{e.detail}</span>
        </span>
      </button>
    </li>
  );
}
