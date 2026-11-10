#!/usr/bin/env python3
"""Record the PyWall demo videos, drawn as a Fedora Ptyxis terminal window.

    python3 demo/record_demo.py                                # -> demo/pywall_demo.mp4
    python3 demo/record_demo.py --live demo/live_session.json  # -> demo/pywall_live_demo.mp4

Default mode really executes every command (with FORCE_COLOR=1, so programs
emit the same ANSI colours they show in a terminal) and replays the captured
output. --live replays a session recorded as root by demo/live_demo.py.
Output is paced slower than real time so it can be read.

The look follows Ptyxis 50 on Fedora 44: dark libadwaita header bar, the
"GNOME" palette (dark), Adwaita Mono / Adwaita Sans, the default Fedora
bash-color-prompt (bold green user@host and directory) and a blinking block
cursor. Needs Pillow and ffmpeg (libx264).
"""

from __future__ import annotations

import getpass
import json
import os
import random
import re
import socket
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from firewall.colors import Painter, colour_log_message  # noqa: E402

OUT_VIDEO = ROOT / "demo" / "pywall_demo.mp4"
OUT_LIVE = ROOT / "demo" / "pywall_live_demo.mp4"
OUT_TEXT = ROOT / "demo" / "demo_transcript.txt"

W, H, FPS = 1280, 720, 20
FONT_PX, TITLE_PX = 15, 15
HEADER, PAD = 46, 10


def hexrgb(h: str) -> tuple:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


# Ptyxis "GNOME" palette, [Dark] section (as shipped in ptyxis-50)
BG, FG = hexrgb("#1c1c1f"), hexrgb("#ffffff")
TITLE_BG, TITLE_FG = hexrgb("#2e2e32"), hexrgb("#ffffff")
ANSI = [hexrgb(c) for c in (
    "#241f31", "#c01c28", "#2ec27e", "#f5c211", "#1e78e4", "#9841bb", "#0ab9dc", "#c0bfbc",
    "#5e5c64", "#ed333b", "#57e389", "#f8e45c", "#51a1ff", "#c061cb", "#4fd2fd", "#f6f5f4")]
HEADER_SHADE = (18, 18, 20)
BUTTON_BG = (67, 67, 71)          # libadwaita circular close button on the dark header bar


def blend(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


# --------------------------------------------------------------------- fonts
def _find(name: str) -> str | None:
    for base in ("/usr/share/fonts", "/usr/local/share/fonts", str(Path.home() / ".local/share/fonts")):
        for dirpath, _, files in os.walk(base):
            if name in files:
                return os.path.join(dirpath, name)
    return None


def _mono(bold=False):
    path = _find("AdwaitaMono-Bold.ttf" if bold else "AdwaitaMono-Regular.ttf") or \
        _find("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf")
    return ImageFont.truetype(path, FONT_PX)


def _sans(size, weight="Regular"):
    path = _find("AdwaitaSans-Regular.ttf")
    if not path:
        return _mono(weight != "Regular")
    f = ImageFont.truetype(path, size)
    try:
        f.set_variation_by_name(weight)
    except Exception:
        pass
    return f


MONO, MONO_BOLD = _mono(), _mono(True)
TITLE_FONT = _sans(TITLE_PX, "Bold")
CW = MONO.getlength("M")
_asc, _desc = MONO.getmetrics()
LH = _asc + _desc + 1
COLS = int((W - 2 * PAD) // CW)
ROWS = int((H - HEADER - 2 * PAD) // LH)

USER = getpass.getuser()
HOSTNAME = socket.gethostname().split(".")[0]
HOME = str(Path.home())
CWD = str(ROOT).replace(HOME, "~", 1) if str(ROOT).startswith(HOME) else str(ROOT)
WINDOW_TITLE = f"{USER}@{HOSTNAME}:{CWD}"

# --------------------------------------------------------------------- ANSI
SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESC_RE = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-ln-z]")


class Style:
    def __init__(self):
        self.fg, self.bold, self.dim = None, False, False

    def apply(self, params: str):
        codes = [int(c) for c in params.split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.fg, self.bold, self.dim = None, False, False
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.dim = True
            elif c == 22:
                self.bold = self.dim = False
            elif 30 <= c <= 37:
                self.fg = ANSI[c - 30]
            elif 90 <= c <= 97:
                self.fg = ANSI[c - 90 + 8]
            elif c == 39:
                self.fg = None
            elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                self.fg = ANSI[codes[i + 2]] if codes[i + 2] < 16 else None
                i += 2
            i += 1

    def colour(self):
        c = self.fg or FG
        return blend(c, BG, 0.45) if self.dim else c


def parse_ansi(line: str, style: Style) -> list[tuple[str, tuple, bool]]:
    line = OTHER_ESC_RE.sub("", line).replace("\t", "    ").replace("\r", "")
    segs, pos = [], 0
    for m in SGR_RE.finditer(line):
        if m.start() > pos:
            segs.append((line[pos:m.start()], style.colour(), style.bold))
        style.apply(m.group(1))
        pos = m.end()
    if pos < len(line):
        segs.append((line[pos:], style.colour(), style.bold))
    return segs


def strip_ansi(s: str) -> str:
    return OTHER_ESC_RE.sub("", SGR_RE.sub("", s))


def prompt_segments():
    green = ANSI[2]
    return [(f"{USER}@{HOSTNAME}", green, True), (":", FG, False), (CWD, green, True), ("$ ", FG, False)]


# --------------------------------------------------------------------- window
def draw_window(d: ImageDraw.ImageDraw):
    d.rectangle([0, 0, W, HEADER], fill=TITLE_BG)
    d.line([0, HEADER, W, HEADER], fill=HEADER_SHADE)
    cy = HEADER // 2
    # left: new-tab split button ("+" and a menu arrow)
    d.line([24, cy, 38, cy], fill=TITLE_FG, width=2)
    d.line([31, cy - 7, 31, cy + 7], fill=TITLE_FG, width=2)
    d.line([50, cy - 2, 54, cy + 2], fill=TITLE_FG, width=2)
    d.line([54, cy + 2, 58, cy - 2], fill=TITLE_FG, width=2)
    # centre: window title (set by the shell prompt)
    tw = TITLE_FONT.getlength(WINDOW_TITLE)
    d.text(((W - tw) / 2, cy - TITLE_PX * 0.62), WINDOW_TITLE, font=TITLE_FONT, fill=TITLE_FG)
    # right: main menu, close
    x = W - 82
    for dy in (-5, 0, 5):
        d.line([x - 7, cy + dy, x + 7, cy + dy], fill=TITLE_FG, width=2)
    x = W - 30
    d.ellipse([x - 12, cy - 12, x + 12, cy + 12], fill=BUTTON_BG)
    d.line([x - 4, cy - 4, x + 4, cy + 4], fill=TITLE_FG, width=2)
    d.line([x - 4, cy + 4, x + 4, cy - 4], fill=TITLE_FG, width=2)


# --------------------------------------------------------------------- terminal
class Terminal:
    def __init__(self, encoder):
        self.enc = encoder
        self.lines: list[list[tuple]] = []
        self.frames = 0
        self.cursor_visible = True
        self._prompt_start = 0
        self.rng = random.Random(7)

    # -- buffer -------------------------------------------------------------
    @staticmethod
    def _wrap(segs):
        rows, cur, n = [], [], 0
        for text, colour, bold in segs:
            while text:
                room = COLS - n
                part, text = text[:room], text[room:]
                cur.append((part, colour, bold))
                n += len(part)
                if n >= COLS:
                    rows.append(cur)
                    cur, n = [], 0
        if cur or not rows:
            rows.append(cur)
        return rows

    def add(self, segs):
        self.lines.extend(self._wrap(segs))
        if len(self.lines) > 400:
            self.lines = self.lines[-ROWS:]

    def add_text(self, text: str, colour=FG, bold=False):
        self.add([(text, colour, bold)])

    def clear(self):
        self.lines = []

    def new_prompt(self):
        self._prompt_start = len(self.lines)
        self.add(prompt_segments())

    def _set_prompt_text(self, text):
        del self.lines[self._prompt_start:]
        self.add(prompt_segments() + [(text, FG, False)])

    # -- drawing ------------------------------------------------------------
    def render(self, cursor_on: bool) -> bytes:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        draw_window(d)
        visible = self.lines[-ROWS:]
        y0 = HEADER + PAD
        for row, segs in enumerate(visible):
            x, y = PAD, y0 + row * LH
            for text, colour, bold in segs:
                d.text((x, y), text, font=MONO_BOLD if bold else MONO, fill=colour)
                x += CW * len(text)
        if cursor_on and self.cursor_visible and visible:
            row = len(visible) - 1
            col = sum(len(t) for t, _, _ in visible[-1])
            cx, cy = PAD + col * CW, y0 + row * LH
            d.rectangle([cx, cy, cx + CW - 1, cy + LH - 1], fill=FG)
        return img.tobytes()

    def _emit(self, frame: bytes):
        self.enc.stdin.write(frame)
        self.frames += 1

    def show(self, seconds: float):
        """Hold the screen, blinking the cursor like VTE (0.6 s on / 0.6 s off)."""
        cache = {}
        for _ in range(max(1, round(seconds * FPS))):
            on = (self.frames // round(0.6 * FPS)) % 2 == 0
            if on not in cache:
                cache[on] = self.render(on)
            self._emit(cache[on])

    def type(self, text: str, cps: float = 22):
        """Type at the current prompt, at a slightly uneven human pace."""
        budget = 0.0
        for i in range(1, len(text) + 1):
            budget += self.rng.uniform(0.6, 1.4) / cps
            if text[i - 1] == " ":
                budget += 0.03
            if budget >= 1 / FPS or i == len(text):
                self._set_prompt_text(text[:i])
                frame = self.render(True)
                for _ in range(max(1, round(budget * FPS))):
                    self._emit(frame)
                budget = 0.0

    def enter(self):
        self.show(0.35)
        self.cursor_visible = False

    def done(self, hold: float):
        self.cursor_visible = True
        self.new_prompt()
        self.show(hold)

    def comment(self, text: str, cps: float = 40):
        self.type(f"# {text}", cps=cps)
        self.enter()
        self.done(0.3)

    def section(self, heading: str):
        self.clear()                     # Ctrl+L between sections
        self.new_prompt()
        self.show(0.4)
        self.comment(heading, cps=30)


def title_card(enc, lines, seconds):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    big, small = _sans(40, "Bold"), _sans(21)
    y = H / 2 - 28 * len(lines)
    for i, (text, colour) in enumerate(lines):
        f = big if i == 0 else small
        d.text(((W - f.getlength(text)) / 2, y), text, font=f, fill=colour)
        y += 68 if i == 0 else 38
    frame = img.tobytes()
    for _ in range(round(seconds * FPS)):
        enc.stdin.write(frame)


def encoder(path: Path) -> subprocess.Popen:
    if subprocess.run(["ffmpeg", "-version"], capture_output=True).returncode != 0:
        sys.exit("ffmpeg not found")
    return subprocess.Popen(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
         "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
         "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
         "-movflags", "+faststart", str(path)],
        stdin=subprocess.PIPE)


# =========================================================== demo 1: offline
# (heading, [ ("say", comment) | ("run", shown command, real command or None, line delay, hold regex) ])
STEPS = [
    ("1/6  Project layout", [
        ("say", "PyWall: a stateful packet-filtering firewall in Python"),
        ("run", "ls firewall config tests demo",
         f"ls --color=always -C -T 0 -w {COLS} firewall config tests demo", 0.05, None),
    ]),
    ("2/6  Validate and list the rule set", [
        ("say", "rules are checked top to bottom, first match wins, default policy is DROP"),
        ("run", "python3 pywall.py check", None, 0.09, None),
    ]),
    ("3/6  Bad rules are rejected at load time", [
        ("say", "a rule with an impossible port number is caught before any traffic is filtered"),
        ("run", "python3 pywall.py -c demo/bad_rules.json check", None, 0.05, None),
    ]),
    ("4/6  Attack and traffic simulation (73 real IPv4 packets)", [
        ("say", "normal traffic, spoofed packets, rate limiting, a port scan and a SYN flood"),
        ("run", "python3 pywall.py simulate", None, 0.075, r"IDS:|Simulation:|rate limit exceeded"),
    ]),
    ("5/6  Replaying a packet capture (pcap)", [
        ("say", "write the traffic to a Wireshark-compatible capture, then replay it through the firewall"),
        ("run", "python3 demo/make_sample_pcap.py demo/sample.pcap", None, 0.05, None),
        ("run", "python3 pywall.py pcap demo/sample.pcap", None, 0.06, r"IDS ALERT|Accepted:"),
    ]),
    ("6/6  Unit tests", [
        ("run", "python3 -m unittest discover -s tests -t . -v", None, 0.06, r"^OK|^Ran "),
    ]),
]


def run_cmd(cmd: str) -> str:
    env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": str(COLS), "TERM": "xterm-256color"}
    env.pop("NO_COLOR", None)
    res = subprocess.run(cmd, shell=True, cwd=ROOT, env=env, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return res.stdout.rstrip("\n")


def main_offline() -> int:
    enc = encoder(OUT_VIDEO)
    transcript, results = [], {}
    title_card(enc, [("PyWall", FG), ("A stateful packet-filtering firewall in Python", ANSI[7]),
                     ("Computer Networks project: Firewall Implementation", ANSI[8])], 3.5)
    term = Terminal(enc)
    for heading, actions in STEPS:
        term.section(heading)
        for action in actions:
            if action[0] == "say":
                term.comment(action[1])
                continue
            _, shown, real, delay, hold = action
            output = run_cmd(real or shown)
            transcript.append(f"$ {shown}\n{strip_ansi(output)}\n")
            results[shown] = strip_ansi(output)
            term.type(shown)
            term.enter()
            style = Style()
            for line in output.splitlines():
                term.add(parse_ansi(line, style))
                term.show(delay)
                if hold and re.search(hold, strip_ansi(line)):
                    term.show(1.0)
            term.done(2.2)
            print(f"recorded: {shown}", file=sys.stderr)

    sim = re.search(r"Simulation: (\d+) passed, (\d+) failed", results.get("python3 pywall.py simulate", ""))
    test_out = results.get("python3 -m unittest discover -s tests -t . -v", "")
    tests = re.search(r"Ran (\d+) tests", test_out)
    tests_ok = test_out.rstrip().endswith("OK")
    summary = [("Demo complete", FG)]
    if sim:
        summary.append((f"Simulation: {sim.group(1)} packets passed, {sim.group(2)} failed",
                        ANSI[10] if sim.group(2) == "0" else ANSI[9]))
    if tests:
        summary.append((f"Unit tests: {tests.group(1)} run, {'all passed' if tests_ok else 'FAILURES'}",
                        ANSI[10] if tests_ok else ANSI[9]))
    summary.append(("Live mode on real packets: see pywall_live_demo.mp4", ANSI[8]))
    title_card(enc, summary, 5)
    enc.stdin.close()
    enc.wait()
    OUT_TEXT.write_text("\n".join(transcript))
    print(f"wrote {OUT_VIDEO.relative_to(ROOT)} ({term.frames / FPS + 8.5:.0f} s) and {OUT_TEXT.relative_to(ROOT)}")
    return 0 if enc.returncode == 0 else 1


# =========================================================== demo 2: live
PAINT = Painter(True)
NOTE = blend(ANSI[8], FG, 0.25)
FW_CMD = "sudo python3 pywall.py -v --log demo/live_firewall.log live --interface pw-host"


def condense(lines: list[str], keep_head=2, min_run=5) -> list[str]:
    """Shorten runs of consecutive log lines with the same verdict and reason."""
    def key(line):
        m = re.match(r"^\S+\s+(ACCEPT|DROP)\s+(.+?)  (\S.*)$", line)
        return (m.group(1), m.group(3)) if m else None
    out, i = [], 0
    while i < len(lines):
        k, j = key(lines[i]), i + 1
        while k and j < len(lines) and key(lines[j]) == k:
            j += 1
        run = lines[i:j]
        if len(run) >= min_run:
            out += run[:keep_head] + [f"... {len(run) - keep_head - 1} more {k[0]} lines: {k[1]}", run[-1]]
        else:
            out += run
        i = j
    return out


def fw_line_segments(line: str):
    """A PyWall log line coloured exactly as PyWall's terminal formatter does it.
    Lines starting with "(+" or "..." are summaries added for the video."""
    if line.startswith(("(+", "...")):
        return [("  " + line, NOTE, False)]
    m = re.match(r"^(\d\d:\d\d:\d\d)  (.*)$", line)
    if not m:
        return parse_ansi(colour_log_message(line, PAINT), Style())
    ts, msg = m.groups()
    return parse_ansi(f"{PAINT(ts, 'grey')}  {colour_log_message(msg, PAINT)}", Style())


def shown_command(item) -> str:
    cmd = item["cmd"]
    if item["who"] == "attacker":
        return f"sudo ip netns exec pywall-atk {cmd}"
    return re.sub(r"(^|; )iptables", r"\1sudo iptables", cmd)


def main_live(session_path: Path) -> int:
    data = json.loads(session_path.read_text())
    enc = encoder(OUT_LIVE)
    title_card(enc, [("PyWall: live mode", FG),
                     ("Filtering real packets through Linux netfilter (NFQUEUE)", ANSI[7]),
                     (f"Session recorded {data.get('recorded', '')} on a private veth test network", ANSI[8])], 4)
    term = Terminal(enc)
    for sec in data["sections"]:
        term.section(sec["title"])
        for item in sec["items"]:
            if item["type"] == "say":
                term.comment(item["text"])
                continue
            cmd = item["cmd"]
            out_lines = item["output"].splitlines()
            if cmd.startswith("kill -INT"):          # bring the background firewall back and stop it
                term.type("fg")
                term.enter()
                term.add_text(FW_CMD)
                term.show(1.0)
                term.add_text("^C")
                term.show(0.5)
            else:
                term.type(shown_command(item))
                term.enter()
            if "live --interface" in cmd:            # the firewall started as a background job
                if out_lines:
                    term.add(fw_line_segments(out_lines[0]))
                extra = out_lines[1:]
                if extra:
                    multicast = all("ACCEPT" in l and re.search(r"-> 2(24|39)\.", l) for l in extra)
                    what = "this machine's own mDNS/SSDP multicast, all ACCEPT" if multicast else "see log"
                    term.add_text(f"  (+ {len(extra)} log lines: {what})", NOTE)
                term.show(0.5)
            else:
                style = Style()
                for line in out_lines:
                    term.add(parse_ansi(line, style))
                    term.show(0.06)
            for line in condense(item["fw"]):         # background job output interleaves
                term.add(fw_line_segments(line))
                term.show(0.15)
                if re.search(r"IDS|DROP|^\.\.\. ", line):
                    term.show(0.6)
            term.done(2.0 if item["fw"] else 1.4)

    alltext = strip_ansi("\n".join(i.get("output", "") for s in data["sections"] for i in s["items"]))
    stats = re.search(r"Accepted: (\d+)\s+Dropped: (\d+)", alltext)
    alerts = re.findall(r"^  (\S+): (port scan|SYN flood)", alltext, flags=re.M)
    summary = [("Live demo complete" if data.get("complete") else "Live demo (incomplete run)", FG)]
    if stats:
        summary.append((f"PyWall report: {stats.group(1)} packets accepted, {stats.group(2)} dropped", ANSI[10]))
    for ip, kind in alerts:
        summary.append((f"IDS banned {ip} for a {kind}", ANSI[11]))
    if "no NFQUEUE hooks left" in alltext:
        summary.append(("iptables hooks removed and test network deleted afterwards", ANSI[8]))
    title_card(enc, summary, 5)
    enc.stdin.close()
    enc.wait()
    print(f"wrote {OUT_LIVE.relative_to(ROOT)} ({term.frames / FPS + 9:.0f} s)")
    return 0 if enc.returncode == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--live":
        sys.exit(main_live(Path(sys.argv[2])))
    sys.exit(main_offline())
