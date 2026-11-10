---
version: 1
slug: "web-src-app-tsx"
primary_target: "web/src/App.tsx"
related_targets: []
---

# PyWall console (web dashboard)

Scope: the whole dashboard SPA (Overview, Live Traffic, Firewall Rules, Analytics, Security Events, Settings). Mode: Operate.
Audience: examiner watching a demo first; students learning; operators in long sessions. Laptop and projector.
Task: see what the firewall is doing now, open any packet/stream/rule and understand why it was allowed or dropped; edit rules.
Proof/content: real PyWall data only (live NFQUEUE, pcap replay, or labelled simulated traffic). No invented events.
Constraints: pinned palette (charcoal; teal allowed; coral blocked; amber IDS/rate-limit; greys), sans + mono for packet metadata; reduced motion honoured; works offline (fonts bundled).

## Direction contract
THESIS: Every packet is addressed mail: read at the sorting frame, then forwarded to its destination or held in the bin of the stage that stopped it. Refuses the category default of a KPI-card grid over a line chart and an alerts table.
OWN-WORLD: Charcoal #141517 ground, graphite #1f2124 frame panels, divided figure strip; teal forwarded, coral + 45-degree hatch held, amber inspection; address labels as JetBrains Mono IPs and ports, postmark rings as verdict marks, pigeonhole columns for pipeline stages. Public Sans for words, four sizes, rank by weight and ink.
STORY: The viewer sees sources on the left converge into PyWall's real pipeline, watches forwarded streams continue to services and held streams drop into labelled bins, clicks any stream, bin or stage, and reads exactly which rule or detector decided and the packets behind it.
FIRST VIEWPORT: 56px icon rail (mark on top). Title row: "Overview", one-line finding, source badge right. Divided figure strip, lead figure largest. Below, flow map (about 70% width): sources left, sorting frame centre with stage columns, held bins beneath each stage with counts, destinations right; recent events column at right with "View all".
FORM: Sorting Office, candidate 6 of 7 on the grounded list (postal sorting office); seed:3b8a2a627d4e7932. Signature interaction: select a stream, stage or bin to highlight its path and filter the event/packet context; packets animate along real paths and stop in bins.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
