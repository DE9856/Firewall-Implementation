"""ANSI colour output for terminals.

Colour is on when stdout is a terminal, off when it is piped or redirected.
NO_COLOR=1 always disables it and FORCE_COLOR=1 always enables it
(see https://no-color.org and https://force-color.org).
"""

from __future__ import annotations

import os
import re
import sys

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
          "magenta": "35", "cyan": "36", "grey": "90", "bright_red": "91", "bright_green": "92",
          "bright_yellow": "93", "bright_blue": "94", "bright_cyan": "96"}


def colour_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        return f"\033[{';'.join(_CODES[s] for s in styles)}m{text}\033[0m"

    def verdict(self, v: str, width: int = 6) -> str:
        styles = {"ACCEPT": ("bold", "green"), "DROP": ("bold", "red"), "REJECT": ("bold", "red")}.get(v.strip(), ())
        return self(f"{v:<{width}}", *styles)


paint = Painter(colour_enabled())

_LOG_RE = re.compile(r"^(ACCEPT|DROP)(\s+)(.*?)(\s{2,}|\s(?=\S+$))(.*)$")


def colour_log_message(msg: str, p: Painter = paint, warning: bool = False) -> str:
    """Colour one firewall log message: the verdict word, and IDS reasons."""
    if warning or msg.startswith("IDS ALERT"):
        return p(msg, "bold", "yellow")
    m = _LOG_RE.match(msg)
    if not m:
        return msg
    verdict, gap, summary, gap2, reason = m.groups()
    reason = p(reason, "yellow") if "IDS" in reason else reason
    return p(verdict, "bold", "green" if verdict == "ACCEPT" else "red") + gap + summary + gap2 + reason
