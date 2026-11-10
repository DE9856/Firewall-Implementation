"""Session history on disk (SQLite, standard library), so the dashboard's
events, blocked packets and per-second counters survive a restart.

Each run of `pywall.py serve` is a session. On start, the recent past is
loaded back (events, blocked packets, the last 15 minutes of counters), and
packet and event numbers continue from where the last session stopped so they
stay unique. Totals such as "packets checked" stay per session. Rows older
than KEEP_DAYS are pruned at start-up.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger("firewall")
KEEP_DAYS = 7
SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, started REAL, ended REAL, source TEXT,
                                     packets INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events   (id INTEGER PRIMARY KEY, session INTEGER, last REAL, data TEXT);
CREATE TABLE IF NOT EXISTS packets  (id INTEGER PRIMARY KEY, session INTEGER, t REAL, data TEXT);
CREATE TABLE IF NOT EXISTS seconds  (t INTEGER, session INTEGER, data TEXT, PRIMARY KEY (t, session));
"""


class History:
    def __init__(self, path: str | Path, source_label: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock, self.db:
            self.db.executescript(SCHEMA)
            cutoff = time.time() - KEEP_DAYS * 86400
            for table, col in (("events", "last"), ("packets", "t"), ("seconds", "t"), ("sessions", "started")):
                self.db.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
            self.session = self.db.execute("INSERT INTO sessions (started, source) VALUES (?, ?)",
                                           (time.time(), source_label)).lastrowid
        _give_back(self.path)

    # ---------------------------------------------------------------- read
    def load(self, history_seconds: int, max_events: int, max_packets: int) -> dict:
        now = time.time()
        with self.lock:
            q = self.db.execute
            events = [json.loads(d) for (d,) in q("SELECT data FROM events WHERE session != ? ORDER BY id DESC LIMIT ?",
                                                  (self.session, max_events))][::-1]
            packets = [json.loads(d) for (d,) in q("SELECT data FROM packets WHERE session != ? ORDER BY id DESC LIMIT ?",
                                                   (self.session, max_packets))][::-1]
            seconds: dict[int, dict] = {}
            for t, d in q("SELECT t, data FROM seconds WHERE t >= ? AND session != ?", (int(now) - history_seconds, self.session)):
                c = seconds.setdefault(t, {})
                for k, v in json.loads(d).items():
                    c[k] = c.get(k, 0) + v
            max_packet = q("SELECT MAX(id) FROM packets").fetchone()[0] or 0
            max_event = q("SELECT MAX(id) FROM events").fetchone()[0] or 0
            last_seq = q("SELECT MAX(packets) FROM sessions").fetchone()[0] or 0
        return {"events": events, "packets": packets, "seconds": seconds,
                "maxPacket": max(max_packet, last_seq), "maxEvent": max_event}

    def sessions(self, limit: int = 20) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT id, started, ended, source, packets, dropped FROM sessions "
                                   "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": i, "started": s, "ended": e, "source": src, "lastPacket": p, "dropped": d, "current": i == self.session}
                for i, s, e, src, p, d in rows]

    # --------------------------------------------------------------- write
    def save(self, events: list[dict], packets: list[dict], seconds: dict[int, dict], last_packet: int, dropped: int) -> None:
        """Write one batch (called from the dashboard's broadcast loop, about once a second)."""
        try:
            with self.lock, self.db:
                self.db.executemany("INSERT OR REPLACE INTO events (id, session, last, data) VALUES (?, ?, ?, ?)",
                                    [(e["id"], self.session, e["last"], json.dumps(e)) for e in events])
                self.db.executemany("INSERT OR REPLACE INTO packets (id, session, t, data) VALUES (?, ?, ?, ?)",
                                    [(p["id"], self.session, p["t"], json.dumps(p)) for p in packets])
                self.db.executemany("INSERT OR REPLACE INTO seconds (t, session, data) VALUES (?, ?, ?)",
                                    [(t, self.session, json.dumps(c)) for t, c in seconds.items()])
                self.db.execute("UPDATE sessions SET ended = ?, packets = ?, dropped = ? WHERE id = ?",
                                (time.time(), last_packet, dropped, self.session))
        except sqlite3.Error as exc:         # history is a convenience: never break the firewall over it
            log.warning("could not save history to %s: %s", self.path, exc)


def _give_back(path: Path) -> None:
    """Live mode runs as root: leave the history owned by the project's user, not root."""
    if os.geteuid() != 0:
        return
    st = path.parent.parent.stat()
    for p in (path.parent, path, Path(f"{path}-journal")):
        if p.exists():
            os.chown(p, st.st_uid, st.st_gid)
