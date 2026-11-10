"""Simulated traffic source for the dashboard (no root needed).

Builds real IPv4 packets (valid headers and checksums) and feeds them through the
real Firewall in real time: normal sessions (outbound HTTPS and DNS, web visitors,
LAN SSH, pings) plus recurring attack episodes (port scan, SYN flood, spoofed
ACKs, blocked ports, a blacklisted source, ping bursts, a malformed packet).

The packets and verdicts are real; the traffic pattern is synthetic, and the
dashboard labels this source as "Simulated traffic" everywhere.
"""

from __future__ import annotations

import heapq
import ipaddress
import itertools
import random
import threading
import time

from .packet import ACK, FIN, PSH, SYN, build_icmp, build_tcp, build_udp

WEB_SERVERS = ["142.250.183.14", "151.101.1.69", "104.16.132.229", "13.107.42.14", "140.82.112.3"]
VISITORS = ["81.2.69.142", "88.198.24.108", "37.120.188.4", "49.36.120.11", "102.89.34.7", "45.33.32.156"]
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]
SCANNERS = ["203.0.113.66", "203.0.113.87"]
FLOODERS = ["198.51.100.77", "198.51.100.23"]
BLACKLISTED = "185.220.101.5"


class TrafficGenerator:
    def __init__(self, fw, seed: int | None = None, speed: float = 1.0):
        self.fw = fw
        self.rng = random.Random(seed)
        self.speed = speed
        nets = fw.cfg.local_networks or [ipaddress.ip_network("192.168.1.0/24")]
        hosts = list(itertools.islice(nets[0].hosts(), 30))
        self.host = str(hosts[9]) if len(hosts) > 9 else str(hosts[0])      # e.g. 192.168.1.10
        self.lan_peer = str(hosts[24]) if len(hosts) > 24 else self.host
        self.queue: list = []
        self.counter = itertools.count()
        self.stop = threading.Event()

    # --------------------------------------------------------------- queue
    def at(self, delay: float, raw: bytes, direction: str) -> None:
        heapq.heappush(self.queue, (time.time() + delay / self.speed, next(self.counter), raw, direction))

    def run(self) -> None:
        next_session = time.time()
        next_episode = next_session + 6 / self.speed       # a few seconds of normal traffic first
        episodes = itertools.cycle([self.port_scan, self.syn_flood, self.spoofed, self.blocked_ports,
                                    self.ping_burst, self.blacklisted, self.ssh_attempts, self.malformed])
        while not self.stop.is_set():
            now = time.time()
            if now >= next_session:
                self.rng.choice([self.https, self.https, self.https, self.dns, self.dns,
                                 self.visitor, self.visitor, self.lan_ssh, self.ping])()
                next_session = now + self.rng.uniform(0.08, 0.35) / self.speed
            if now >= next_episode:
                next(episodes)()
                next_episode = now + self.rng.uniform(14, 24) / self.speed
            while self.queue and self.queue[0][0] <= now:
                _, _, raw, direction = heapq.heappop(self.queue)
                with self.fw.lock:
                    self.fw.process(raw, direction)
            time.sleep(0.01)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, daemon=True, name="traffic")
        t.start()
        return t

    def port(self) -> int:
        return self.rng.randint(40000, 60999)

    # ------------------------------------------------------- normal traffic
    def tcp_session(self, client, server, cport, sport, client_dir, server_dir, exchanges, t0=0.0):
        rtt = self.rng.uniform(0.01, 0.08)
        t = t0
        self.at(t, build_tcp(client, server, cport, sport, SYN), client_dir)
        t += rtt
        self.at(t, build_tcp(server, client, sport, cport, SYN | ACK), server_dir)
        t += 0.002
        self.at(t, build_tcp(client, server, cport, sport, ACK), client_dir)
        for _ in range(exchanges):
            t += self.rng.uniform(0.01, 0.12)
            self.at(t, build_tcp(client, server, cport, sport, PSH | ACK, b"x" * self.rng.randint(40, 600)), client_dir)
            t += rtt
            self.at(t, build_tcp(server, client, sport, cport, PSH | ACK, b"y" * self.rng.randint(200, 1400)), server_dir)
        t += 0.05
        self.at(t, build_tcp(client, server, cport, sport, FIN | ACK), client_dir)
        t += rtt
        self.at(t, build_tcp(server, client, sport, cport, FIN | ACK), server_dir)

    def https(self):
        self.tcp_session(self.host, self.rng.choice(WEB_SERVERS), self.port(), 443, "out", "in",
                         self.rng.randint(2, 7))

    def dns(self):
        server, p = self.rng.choice(DNS_SERVERS), self.port()
        self.at(0, build_udp(self.host, server, p, 53, b"q" * 30), "out")
        self.at(self.rng.uniform(0.01, 0.05), build_udp(server, self.host, 53, p, b"a" * 90), "in")

    def visitor(self):
        self.tcp_session(self.rng.choice(VISITORS), self.host, self.port(), 80, "in", "out",
                         self.rng.randint(1, 4))

    def lan_ssh(self):
        self.tcp_session(self.lan_peer, self.host, self.port(), 22, "in", "out", self.rng.randint(2, 6))

    def ping(self):
        src = self.rng.choice(VISITORS)
        self.at(0, build_icmp(src, self.host, 8), "in")
        self.at(0.02, build_icmp(self.host, src, 0), "out")

    # ------------------------------------------------------------- episodes
    def port_scan(self):
        src, base = self.rng.choice(SCANNERS), self.rng.choice([1, 20, 1000])
        for i, dport in enumerate(range(base, base + 30)):
            self.at(i * 0.04, build_tcp(src, self.host, 50000 + i, dport, SYN), "in")

    def syn_flood(self):
        src = self.rng.choice(FLOODERS)
        for i in range(40):
            self.at(i * 0.012, build_tcp(src, self.host, 20000 + i, 80, SYN), "in")

    def spoofed(self):
        src = self.rng.choice(VISITORS)
        for i in range(3):
            self.at(i * 0.3, build_tcp(src, self.host, 443, self.port(), ACK), "in")
        self.at(1.0, build_icmp(src, self.host, 0), "in")

    def blocked_ports(self):
        src = self.rng.choice(VISITORS)
        for i, dport in enumerate((3389, 445, 139)):
            self.at(i * 0.5, build_tcp(src, self.host, self.port(), dport, SYN), "in")
        self.at(1.6, build_tcp(self.host, self.rng.choice(WEB_SERVERS), self.port(), 23, SYN), "out")

    def ping_burst(self):
        src = self.rng.choice(VISITORS)
        for i in range(9):
            self.at(i * 0.11, build_icmp(src, self.host, 8), "in")

    def blacklisted(self):
        for i in range(3):
            self.at(i * 0.4, build_tcp(BLACKLISTED, self.host, self.port(), 80, SYN), "in")

    def ssh_attempts(self):
        src = self.rng.choice(VISITORS)
        for i in range(4):
            self.at(i * 0.7, build_tcp(src, self.host, self.port(), 22, SYN), "in")

    def malformed(self):
        self.at(0, b"\x45\x00\x00", "in")
