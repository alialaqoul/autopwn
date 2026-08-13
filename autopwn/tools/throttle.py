# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Scan-intensity throttling — keep discovery gentle so it never freezes a
fragile target (ICS/OT devices, old management appliances, embedded network
gear). One source of truth for nmap timing, the native connect-scanner's
concurrency, and masscan's packet rate.

The default is **polite**: rate-limited, few retransmits, bounded per-host time —
thorough but easy on the target. Bump to ``aggressive`` only on hosts you know
can take it.
"""
from __future__ import annotations

DEFAULT_INTENSITY = "polite"
INTENSITIES = ("sneaky", "polite", "normal", "aggressive")

# nmap timing + safety flags per intensity. Lower rate / fewer retries / a host
# timeout are what stop a scan from flooding (and freezing) a fragile stack.
NMAP_TIMING: dict[str, list[str]] = {
    "sneaky":     ["-T1", "--max-retries", "1", "--max-rate", "50",
                   "--scan-delay", "100ms", "--host-timeout", "30m"],
    "polite":     ["-T2", "--max-retries", "2", "--max-rate", "150",
                   "--host-timeout", "20m"],
    "normal":     ["-T3", "--max-retries", "2", "--host-timeout", "30m"],
    "aggressive": ["-T4"],
}
# native TCP connect-scanner: concurrent sockets + per-port timeout.
NATIVE_WORKERS: dict[str, int] = {"sneaky": 4, "polite": 12, "normal": 32, "aggressive": 100}
NATIVE_TIMEOUT: dict[str, float] = {"sneaky": 1.5, "polite": 1.0, "normal": 0.6, "aggressive": 0.5}
# masscan packets/sec.
MASSCAN_RATE: dict[str, int] = {"sneaky": 50, "polite": 200, "normal": 1000, "aggressive": 5000}


def norm(intensity: str | None) -> str:
    return intensity if intensity in NMAP_TIMING else DEFAULT_INTENSITY


def nmap_timing(intensity: str | None) -> list[str]:
    return list(NMAP_TIMING[norm(intensity)])


def native_workers(intensity: str | None) -> int:
    return NATIVE_WORKERS[norm(intensity)]


def native_timeout(intensity: str | None) -> float:
    return NATIVE_TIMEOUT[norm(intensity)]


def masscan_rate(intensity: str | None) -> int:
    return MASSCAN_RATE[norm(intensity)]
