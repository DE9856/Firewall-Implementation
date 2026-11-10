---
name: PyWall
description: A packet-filter console read like a sorting office; every packet is addressed mail, forwarded or held in the bin of the stage that stopped it.
colors:
  ground: "#141517"
  surface: "#18191c"
  raised: "#1f2124"
  well: "#121315"
  border: "#25272b"
  rule: "#202226"
  control: "#3a3d42"
  text: "#f2f1ee"
  muted: "#a3a6ad"
  faint: "#8a8d94"
  select: "#f2f1ee"
  allow: "#3fb8a9"
  allow-ink: "#5fd0c1"
  allow-bg: "#15302c"
  block: "#ec6a5c"
  block-ink: "#f4897d"
  block-bg: "#3a1d1b"
  warn: "#e0a43a"
  warn-ink: "#ecb95a"
  warn-bg: "#33280f"
  transit: "#34373c"
  idle: "#2c2f34"
typography:
  title:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  section:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 600
  body:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  small:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 400
  figure:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "22px"
    fontWeight: 500
    lineHeight: 1.15
    fontFeature: "tnum"
  figure-lead:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "28px"
    fontWeight: 500
    lineHeight: 1.15
    fontFeature: "tnum"
  data:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "12px"
    fontWeight: 400
    fontFeature: "tnum"
rounded:
  pill: "4px"
  base: "6px"
spacing:
  gap: "20px"
  pad: "28px"
  panel-x: "18px"
  rail: "56px"
  control-h: "32px"
  control-h-small: "26px"
  row: "34px"
components:
  button:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.base}"
    padding: "0 12px"
    height: "{spacing.control-h}"
  button-hover:
    backgroundColor: "{colors.raised}"
  button-primary:
    backgroundColor: "{colors.text}"
    textColor: "{colors.ground}"
    rounded: "{rounded.base}"
    padding: "0 12px"
    height: "{spacing.control-h}"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.block-ink}"
    rounded: "{rounded.base}"
    height: "{spacing.control-h}"
  button-danger-hover:
    backgroundColor: "{colors.block-bg}"
  input:
    backgroundColor: "{colors.well}"
    textColor: "{colors.text}"
    rounded: "{rounded.base}"
    padding: "0 10px"
    height: "{spacing.control-h}"
  pill:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.muted}"
    rounded: "{rounded.pill}"
    padding: "0 7px"
    height: "20px"
  pill-allow:
    backgroundColor: "{colors.allow-bg}"
    textColor: "{colors.allow-ink}"
  pill-block:
    backgroundColor: "{colors.block-bg}"
    textColor: "{colors.block-ink}"
  pill-warn:
    backgroundColor: "{colors.warn-bg}"
    textColor: "{colors.warn-ink}"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.base}"
  rail:
    backgroundColor: "{colors.ground}"
    width: "{spacing.rail}"
---

# Design System: PyWall

## Overview

**Creative North Star: "The Sorting Office"**

Every packet is addressed mail. Sources arrive on the left, are read at a sorting frame that has one pigeonhole column per real pipeline stage (Parse, Lists, Bans, IDS, State, Rules, Policy), and either continue to their service on the right or drop into the bin of the stage that held them. The console is built for an examiner on a projector, a student learning, and an operator in a long session, so it is dense but calm: charcoal steps for structure, colour reserved for state, and every figure traceable to the packets behind it.

The ground is near-black charcoal and panels are slightly lighter charcoal with no border and no shadow. Words are set in Public Sans and ranked by weight and ink, not by size; addresses, ports, timestamps and counts are set in JetBrains Mono like labels on an envelope. Selection is never a fill or a glow: it is a single 1px ink line. Verdicts always carry a shape as well as a colour, so the console reads the same in greyscale.

The category default, a KPI-card grid over a line chart and an alerts table, is the explicit anti-reference. The figures are one divided strip, and the hero is a flow map of real traffic.

**Key Characteristics:**
- Charcoal tonal layering; no borders on panels, no shadows at rest.
- Colour means state only: teal forwarded, coral held, amber IDS and rate limits.
- Shape plus colour for every verdict: ring, 45-degree hatch, diamond, hollow circle.
- Mono for every network value; sans for every word.
- Selection is a 1px ink line.
- Motion is state feedback and real packet dots, nothing else.

## Colors

A charcoal ground with three state hues, each with a stroke, a readable ink and a pale pill background.

### Primary
- **Forwarding Teal** (allow / allow-ink / allow-bg): forwarded packets, accepted ribbons, service nodes, the allowed verdict ring, live switches, the brand mark and the text caret. Ink is used for teal text; the dark background pairs with ink in pills.

### Secondary
- **Held Coral** (block / block-ink / block-bg): held (dropped) traffic only. Held ribbons, bin fills, the hatch mark, held counts, the danger button.

### Tertiary
- **Inspection Amber** (warn / warn-ink / warn-bg): IDS detections, bans and rate limits only. The diamond mark, IDS figures, the event-count badge on the rail.

### Neutral
- **Charcoal Ground** (ground): page and rail background.
- **Graphite Surface** (surface): panels.
- **Raised Graphite** (raised): hover rows, the sorting frame, skeletons, default pills.
- **Well** (well): inputs, code chips, previews, sunken tracks.
- **Border and Rule** (border, rule): figure-strip dividers and table heads (border); row separators, rail edge, inspector section breaks (rule).
- **Control Edge** (control): 1px outlines of buttons and inputs, the off switch.
- **Paper Ink** (text): primary text and the selection line (select is the same value).
- **Muted and Faint** (muted 7.3:1, faint 5.2:1 on surface): secondary labels, then timestamps and placeholders.
- **Transit and Idle** (transit, idle): undecided traffic in the flow map and inactive connection guides.

### Named Rules
**The Colour Is State Rule.** Teal, coral and amber appear only where they mean forwarded, held, or inspected. Nothing decorative is tinted.

**The Neutral Witness Rule.** Status that is not a verdict stays grey: the disconnected stamp is a grey dot and paper ink, and the simulated and capture-replay source badges are grey. Only a live packet source shows teal, because live capture is the forwarding path working.

## Typography

**Body Font:** Public Sans (with system-ui, sans-serif), weights 400, 500, 600, 700.
**Mono Font:** JetBrains Mono (with ui-monospace, monospace), weights 400, 500.
Both are self-hosted through @fontsource so the console works offline. Tabular numerals are on globally.

**Character:** A plain civic sans for sentences and a workmanlike mono for anything a packet carries; the pair reads like a printed form with typed addresses.

### Hierarchy
- **Title** (600, 24px, 1.2, -0.01em): the page name, one per view.
- **Section** (600, 16px): panel headings and the large verdict in the inspector.
- **Body** (400, 13px, 1.5): rows, explanations, flow-map labels; sub-headings inside panels use 600 at 13px.
- **Small** (400, 12px): column heads, figure labels, panel asides, timestamps, legends.
- **Figure** (mono 500, 22px) and **Lead Figure** (mono 500, 28px): the figure strip; units sit beside them in sans 13px muted.
- **Data** (mono 400, 12-13px): IPs, ports, hex, counts in tables and the map.

### Named Rules
**The Envelope Rule.** Addresses, ports, protocols, timestamps, byte offsets and counts are always mono; labels and sentences are never mono. This is a user requirement, not decoration.

**The Rank By Ink Rule.** Hierarchy comes from weight (400, 500, 600) and ink (text, muted, faint), not from new sizes. Uppercase labels and tracked-out caps are not part of the system.

## Layout

A fixed 56px icon rail on the left, then a canvas padded 22px top and 28px sides with a 20px gap between blocks. Panel content is inset 18px horizontally; panel heads are 48px minimum. Controls are 32px tall (26px small), list rows about 30-34px.

Every view opens with the same page header: title, a one-line finding in muted 14px beneath it stating what the data says right now, and on the right the source badge and the freshness stamp ("Updated 13:00:26"). Overview continues with the divided figure strip, then the flow map (fluid) beside a 340px side column of recent events and the pipeline key. Traffic and Rules use a list beside a 440px inspector.

Breakpoints: at 1180px side columns and inspectors stack under their list and the figure strip becomes four across; at 760px the rail becomes a 60px bottom bar with labels, the header stacks, the figure strip becomes two across with the lead figure spanning, and the flow map scrolls sideways inside its panel, starting at the pipeline.

## Elevation & Depth

Flat at rest. Depth is tonal: ground, then surface panels, then raised hover and frame, with the well sunk below for inputs. There are no panel borders and no resting shadows.

### Shadow Vocabulary
- **Float** (`box-shadow: 0 12px 32px rgba(0,0,0,0.45), 0 2px 6px rgba(0,0,0,0.3)`): only for transient overlays that float above data, i.e. rail tooltips and chart or flow-map hover tips.

### Named Rules
**The Flat Desk Rule.** Anything that stays on screen sits flat; only a tooltip that follows the pointer may cast a shadow.

## Shapes

One base radius (6px) for panels, buttons, inputs, tips and the sorting frame; 4px for pills and small chips; 2-3px for swatches, skeleton bars and bar tracks. Lines are 1px. The figure strip is one rounded panel cut by 1px dividers, not separate cards. The brand mark is a postmark: a teal outer ring, a dashed inner ring and a centre dot.

## Components

### Selection mark
The system's one move. A selection is a 1px paper-ink line: under a segmented option, exactly as wide as its label; to the right of the active rail icon (under it in the bottom bar); as an inset left edge on a selected table row or event; as the focus outline (1px, 2px offset); as an underline on a selected flow-map node or stage header. Never a coloured fill.

### Verdict and severity marks
Shape plus colour plus word, always. A 9px mark precedes the word.
- **Allowed:** teal 2px ring.
- **Held:** coral square with 2px radius filled with a 45-degree hatch.
- **IDS / ban / rate limit:** amber diamond (filled for critical, outlined for warning).
- **Information:** grey 1.5px hollow circle.
The same hatch fills held legend swatches, chart segments, event-strip stacks, and flow-map bins and ribbons.

### Buttons
- **Shape:** base radius (6px), 32px tall, 1px control-coloured outline on transparent.
- **Primary:** paper-ink fill with charcoal text, weight 600. One per context.
- **Danger:** coral ink text with a dark coral outline; hover fills block-bg.
- **Ghost / small:** no outline; 26px small variant at 12px.
- **Hover / Active:** raised fill and lighter edge at 150ms; press scales to 0.97.

### Segmented control
Plain muted words 14px apart; the pressed one turns paper ink with the 1px line beneath it. Optional mono count after the word.

### Pills
20px, 4px radius, 12px weight 500. Neutral grey by default; allow, block and warn use their pale background with ink text.

### Inputs / Fields
Well background, 1px control edge, 6px radius, 32px. Focus turns the edge paper ink with no glow. Selects use a muted chevron. Toggle switch: 30 by 18, teal when on.

### Navigation
The 56px rail holds the postmark mark on top, icon items (40px, muted grey, raised on hover, tooltip to the right), an amber count badge on Events, settings and a connection dot at the foot (teal live, hollow grey when reconnecting). Under 760px it becomes a fixed bottom bar with icon plus 11px label.

### Page header
Title, finding line, then right-aligned source badge (dot plus word: "Live packets", "Simulated traffic", "Capture replay") and freshness stamp in faint 12px.

### Figure strip
One panel divided by 1px border lines into seven cells; the lead figure (packets processed) takes 1.35 shares and the 28px size, the rest 22px. Label above in small muted; values coloured only when they are a state count (forwarded teal, held coral, bans amber). Each cell links to its view.

### Flow map (signature)
- Sources on the left as grey bars with mono address and a sub-line (zone, count, held count in coral); services on the right as teal bars with name and mono port.
- A raised sorting frame in the centre with one column per pipeline stage, labelled above; column lines are cut through the streams so the stages read as pigeonholes.
- Inside the frame layers re-sort by outcome: forwarded layers on top run straight out; held layers sit beneath in reverse stage order and turn down into the outlined bin under the stage that dropped them, with a mono count below. Nothing crosses.
- One shared width scale for every ribbon, layer and bin on the map, so widths are comparable everywhere.
- Undecided traffic is transit grey, forwarded is teal, held is the coral hatch; idle connections are dotted guides.
- Dots are real packets sampled from the live stream (about 100 per second at most), white until their stage decides, then teal or coral; held dots fade in the bin.
- Clicking a source, service, stage or bin selects it, dims the rest, and filters the side panel; a legend line under the map names every encoding.

### Inspector and panels
Panels are surface-coloured blocks with a 48px head (16px 600 title, muted aside on the right). Inspectors stack sections separated by 1px rules with 13px 600 sub-heads; fact lists are two-column grids (label muted, value mono). Ranked lists put a 2-3px bar under each row, the leader in paper ink.

### States
- **Loading:** raised skeleton bars at the size of the content they replace.
- **Empty:** a dashed-outline frame inside the panel with one sentence saying what will appear.
- **Error:** shown inside the block that failed, with what still works and a recovery link; never a page-level takeover.
- **Disconnected:** stale figures and map dim to 45% opacity over 200ms, and the freshness stamp becomes a neutral grey dot with "Disconnected, last data N s ago. Retrying…" in paper ink.

### Motion
State changes run 150-250ms on a strong ease-out (cubic-bezier(0.23, 1, 0.32, 1)). The only continuous motion is the packet dots, which can be paused and are not drawn when prefers-reduced-motion is set; reduced motion also zeroes every transition.

## Do's and Don'ts

### Do:
- **Do** mark selection with the 1px paper-ink line and nothing else.
- **Do** pair every verdict colour with its shape and word: ring, hatch, diamond, hollow circle.
- **Do** set every address, port, timestamp and count in JetBrains Mono, and every word in Public Sans.
- **Do** open each view with title, finding line, source badge and freshness stamp.
- **Do** use one width scale across a flow map and draw only real sampled packets.
- **Do** put loading, empty and error states inside the block they belong to.
- **Do** keep state transitions between 150 and 250ms and honour prefers-reduced-motion.

### Don't:
- **Don't** use teal, coral or amber for anything that is not forwarded, held, or inspected; keep the source badge (except live) and the disconnected stamp grey.
- **Don't** add borders or shadows to panels; only floating tips use the float shadow.
- **Don't** build a KPI-card grid; figures live in one divided strip with the lead largest.
- **Don't** introduce uppercase eyebrows, kickers or tracked caps above headings.
- **Don't** animate anything except state feedback and packet dots.
