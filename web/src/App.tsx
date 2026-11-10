import { useEffect } from "react";
import { useStore } from "./api/store";
import { Shell } from "./components/Shell";
import { useRoute } from "./lib/router";
import { Analytics } from "./views/analytics/Analytics";
import { Events } from "./views/events/Events";
import { Overview } from "./views/overview/Overview";
import { Rules } from "./views/rules/Rules";
import { Settings } from "./views/settings/Settings";
import { Traffic } from "./views/traffic/Traffic";

const TITLES = { overview: "Overview", traffic: "Live traffic", rules: "Firewall rules", analytics: "Analytics", events: "Security events", settings: "Settings" };

export function App() {
  const { section } = useRoute();
  const conn = useStore((s) => s.conn);
  const error = useStore((s) => s.error);
  const hasData = useStore((s) => s.stats != null);
  useEffect(() => { document.title = `${TITLES[section]} · PyWall`; }, [section]);
  return (
    <Shell section={section}>
      {!hasData && conn === "offline" ? (
        <div className="panel offline">
          <h1>PyWall isn't reachable</h1>
          <p className="muted">The dashboard could not reach the firewall's server{error ? ` (${error})` : ""}. Start it with <code className="mono">python3 pywall.py serve</code>; this page reconnects by itself.</p>
        </div>
      ) : section === "overview" ? <Overview /> : section === "traffic" ? <Traffic /> : section === "rules" ? <Rules />
        : section === "analytics" ? <Analytics /> : section === "events" ? <Events /> : <Settings />}
    </Shell>
  );
}
