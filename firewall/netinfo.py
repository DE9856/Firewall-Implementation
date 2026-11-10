"""Find the network a live demo runs on: the interface carrying the default
route and the IPv4 subnets on it. Uses the `ip` command (iproute2)."""

from __future__ import annotations

import ipaddress
import json
import subprocess


def _ip_json(*args: str):
    out = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, check=True).stdout
    return json.loads(out or "[]")


def default_interface() -> str | None:
    """The interface used to reach the internet (or the first route if offline)."""
    try:
        route = _ip_json("route", "get", "1.1.1.1")
        if route and route[0].get("dev"):
            return route[0]["dev"]
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass
    try:
        for r in _ip_json("-4", "route"):
            if r.get("dst") == "default" and r.get("dev"):
                return r["dev"]
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass
    return None


def interface_networks(dev: str) -> list[str]:
    """IPv4 subnets on `dev`, e.g. ["10.42.0.0/24"]."""
    try:
        data = _ip_json("-4", "addr", "show", "dev", dev)
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return []
    nets = []
    for link in data:
        for a in link.get("addr_info", []):
            if a.get("family") == "inet":
                nets.append(str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False)))
    return nets


def interface_addresses(dev: str) -> list[str]:
    try:
        data = _ip_json("-4", "addr", "show", "dev", dev)
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return []
    return [a["local"] for link in data for a in link.get("addr_info", []) if a.get("family") == "inet"]
