# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + TypeScript + Vite for the dashboard (user-approved 2026-11-10). The production build is committed under `firewall/web/` and served by PyWall's own standard-library HTTP server (`python3 pywall.py serve`), so running the dashboard needs no Node. Firewall core stays pure Python 3 (standard library; `NetfilterQueue` only for live mode).

## Users

One product, three audiences, demo first:

- **Examiner / class watching a demo** (primary): the student presents PyWall live or in a recorded video. The firewall's behaviour must be obvious at a glance, and every element must explain itself when clicked.
- **Students learning packet filtering**: explore on their own; they need field-level explanations of headers, rule conditions and why a verdict happened.
- **An operator monitoring a host**: long sessions watching real traffic; dense, scannable, nothing decorative.

Shown equally on a laptop (about 1366-1920 px) and on a classroom projector.

## Product Purpose

PyWall is a stateful packet-filtering firewall for Linux, built for a Computer Networks course. The dashboard makes its packet processing visible: where traffic comes from, how each packet moves through the decision pipeline, which rule or detector decided it, and what the firewall is doing right now. Success: a viewer can watch traffic, click any packet or stream, and understand exactly why it was allowed or dropped.

## Positioning

Every verdict on screen is explainable from PyWall's real, deterministic pipeline (parse → whitelist → blacklist/IDS bans → IDS inspection → connection tracking → first-match rules → default policy). The dashboard shows that pipeline as it is, not a generic security dashboard's abstractions.

## Operating Context

- Traffic sources: live kernel packets via netfilter NFQUEUE (root; usually the private veth lab network from `demo/live_demo.py`), replay of a pcap capture, or the built-in simulated traffic generator (real packets built in code, synthetic pattern).
- Runs on localhost; the presenter drives it from a laptop, sometimes projected.
- Companion artefacts: the project report (Claude Docs), the demo videos in `demo/`.

## Capabilities and Constraints

- IPv4 only; TCP, UDP, ICMP headers parsed from raw bytes. No Ethernet layer (NFQUEUE delivers from the IP header), no MAC addresses, no payload or application inspection, no GeoIP, no hostnames.
- Verdicts: ACCEPT or DROP only. There is no REJECT; "blocked" and "dropped" are the same thing.
- Rules: ordered (priority = position), first match wins; conditions are direction, protocol, src/dst CIDR, src/dst ports and ranges, ICMP type, TCP flags, per-source token-bucket rate limit, log flag. Default policy DROP.
- Connection tracking: NEW / ESTABLISHED / INVALID per 5-tuple, with timeouts; established traffic bypasses the rule table.
- IDS: SYN flood, port scan, ICMP flood per source, with a temporary ban (60 s default). "Suspicious" means only these detections or a rate-limit hit.
- Statistics are in memory for the running session; no persistent history.
- Rule editing (create, edit, delete, reorder, enable/disable) is being added (approved): validated with the existing rule validator, saved to `config/rules.json`, hot-swapped; each change is a configuration event.

## Brand Commitments

- Name: PyWall.
- User-specified visual constraints (binding): deep charcoal / near-black interface; restrained cyan/teal = allowed traffic, coral/red = blocked, amber = warnings (IDS / rate limit), neutral greys = secondary; clean sans-serif text with monospace for IP addresses, ports, protocols and packet metadata. Colour communicates real system state only.
- The overview's centrepiece is an organic, flowing network-flow visualization (curved, branching/converging streams, widths by volume, directional movement) reflecting PyWall's real topology. Inspired by, never copied from, the user's reference screenshots.
- Avoid: grids of rounded stat cards, purple gradients, glassmorphism, glowing borders, neon, oversized headings, generic SaaS templates, decorative charts, needless animation.

## Evidence on Hand

- Real firewall behaviour: `config/rules.json`, `demo/live_session.json` and `demo/live_firewall.log` (a recorded live run: 120 accepted, 122 dropped, port-scan and SYN-flood bans), `demo/sample.pcap`, the 73-packet simulation, 25 unit tests.
- No users, customers, testimonials or production deployments exist; none may be invented. Simulated traffic must always be labelled as simulated.

## Product Principles

1. Truth over spectacle: every number, stream and animation comes from a real decision or is visibly labelled as simulated.
2. Every verdict is explainable: any packet, stream or rule can be opened to show which stage decided and why.
3. Teach without slowing the operator: explanations live one click away, never in the way.
4. The pipeline is the product: the UI is organised around how PyWall actually processes a packet.
5. Never break the firewall for the dashboard: UI work must not change verdict logic.

## Accessibility & Inclusion

Honour `prefers-reduced-motion` throughout. Text contrast at least 4.5:1. Allowed and blocked are also distinguished by words/shape, not colour alone. Must remain legible on a projector.
