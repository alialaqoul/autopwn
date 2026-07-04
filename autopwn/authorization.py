# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Authorization scope enforcement.

Nothing in Autopwn is allowed to touch a target unless that target is inside the
loaded scope. This is the single chokepoint every tool passes through. The scope
understands single IPs, CIDR ranges, and hostnames, both as *rules* and as
*targets* — so you can authorize (and scan) a whole CIDR. Scope can also be
edited and saved back to disk, which the interactive menu uses to add/remove
allow/deny entries on the fly.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import date
from pathlib import Path
from typing import Optional

import yaml


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""


class Scope:
    def __init__(self, engagement: str = "", allow: Optional[list[str]] = None,
                 deny: Optional[list[str]] = None, expires: Optional[str] = None,
                 authorized_by: str = "", **_ignored):
        self.engagement = engagement
        self.authorized_by = authorized_by
        self.expires = expires
        self.allow = list(allow or [])
        self.deny = list(deny or [])
        self._path: Optional[Path] = None

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeError(
                f"No scope file at {path}. Copy scope.example.yaml to scope.yaml "
                "and define the targets you are authorized to test."
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        scope = cls(**data)
        scope._path = path
        scope._check_expiry()
        return scope

    def _check_expiry(self) -> None:
        if self.expires:
            if date.fromisoformat(str(self.expires)) < date.today():
                raise ScopeError(
                    f"Scope '{self.engagement}' expired on {self.expires}. "
                    "Renew authorization before continuing."
                )

    # -- persistence --------------------------------------------------------

    def save(self, path: str | Path | None = None) -> Path:
        path = Path(path or self._path or "scope.yaml")
        data = {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "expires": self.expires,
            "allow": self.allow,
            "deny": self.deny,
        }
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        self._path = path
        return path

    def add_allow(self, entry: str) -> bool:
        entry = entry.strip()
        if not entry or entry in self.allow:
            return False
        self.allow.append(entry)
        self.save()
        return True

    def add_deny(self, entry: str) -> bool:
        entry = entry.strip()
        if not entry or entry in self.deny:
            return False
        self.deny.append(entry)
        self.save()
        return True

    def remove_allow(self, entry: str) -> bool:
        if entry in self.allow:
            self.allow.remove(entry)
            self.save()
            return True
        return False

    def remove_deny(self, entry: str) -> bool:
        if entry in self.deny:
            self.deny.remove(entry)
            self.save()
            return True
        return False

    # -- matching helpers ---------------------------------------------------

    @staticmethod
    def _resolve(target: str) -> list[str]:
        """Return the IPs a hostname maps to (itself if already an IP)."""
        if not target or not target.strip():
            return []
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass
        try:
            _, _, ips = socket.gethostbyname_ex(target)
            return ips or []
        except (socket.gaierror, socket.herror, OSError, UnicodeError):
            # DNS failure, blank/invalid name, etc. — treat as unresolvable.
            return []

    @staticmethod
    def _as_network(value: str):
        """Return an ip_network for an IP or CIDR string, else None."""
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _in_rule(ip: str, rule: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        rnet = Scope._as_network(rule)
        if rnet is not None:
            try:
                return addr in rnet
            except TypeError:
                return False
        return ip in Scope._resolve(rule)  # rule is a hostname

    def _net_matches_rules(self, net, rules: list[str]) -> bool:
        for rule in rules:
            rnet = self._as_network(rule)
            if rnet is None:
                continue
            try:
                if net.version == rnet.version and net.subnet_of(rnet):
                    return True
            except (TypeError, ValueError):
                continue
        return False

    # -- the gate -----------------------------------------------------------

    def is_denied(self, target: str) -> bool:
        """True only if the *entire* target is denied.

        A deny entry that merely falls *inside* a larger target range does not
        deny the whole range — it becomes a per-host exclusion (see
        ``excludes_within``). This lets you scan a CIDR while carving out hosts.
        """
        if target in self.deny:
            return True
        net = self._as_network(target)
        if net is not None:
            # denied only if the whole target sits within a deny rule
            return self._net_matches_rules(net, self.deny)
        for ip in self._resolve(target):
            for rule in self.deny:
                if self._in_rule(ip, rule):
                    return True
        return False

    def excludes_within(self, target: str) -> list[str]:
        """Deny entries that fall inside *target* — to skip during a range scan."""
        net = self._as_network(target)
        if net is None:
            return []
        out = []
        for rule in self.deny:
            rnet = self._as_network(rule)
            if rnet is not None and net.version == rnet.version \
                    and rnet.subnet_of(net):
                out.append(rule)
        return out

    def is_allowed(self, target: str) -> bool:
        try:
            self.authorize(target)
            return True
        except ScopeError:
            return False

    def authorize(self, target: str) -> None:
        """Raise ScopeError unless *target* is in scope. The only public gate."""
        if not target or not target.strip():
            raise ScopeError("No target given.")
        if self.is_denied(target):
            raise ScopeError(f"Target '{target}' is denied by scope.")

        if target in self.allow:
            return

        net = self._as_network(target)  # single IP or CIDR
        if net is not None:
            if self._net_matches_rules(net, self.allow):
                return
            raise ScopeError(
                f"Target '{target}' is NOT in the authorized scope "
                f"'{self.engagement}'. Add it to the allow list to proceed."
            )

        # hostname (or an nmap range we can't parse as a network)
        ips = self._resolve(target)
        if not ips:
            raise ScopeError(
                f"Cannot resolve '{target}' and it is not a literal allow entry."
            )
        for ip in ips:
            for rule in self.allow:
                if self._in_rule(ip, rule):
                    return
        raise ScopeError(
            f"Target '{target}' is NOT in the authorized scope "
            f"'{self.engagement}'. Add it to the allow list to proceed."
        )

    def summary(self) -> str:
        return (f"Engagement: {self.engagement} | authorized_by: "
                f"{self.authorized_by or 'n/a'} | expires: {self.expires or 'n/a'} "
                f"| allow={len(self.allow)} deny={len(self.deny)}")
