"""Step 6: automated mitigation via iptables. Dry-run by default. Needs root when ENFORCE=True.

Two actions:
  * block_domain: drop outbound DNS packets whose payload contains the domain (iptables hex-string match on the wire-format name)
  * block_source: drop all outbound DNS (port 53) from an infected host
"""
import re
import subprocess
import time

import config

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class Mitigator:
    def __init__(self, storage, enforce=config.ENFORCE):
        self.storage, self.enforce = storage, enforce
        self.blocked = {}  # (kind, target) -> expiry epoch (0 = permanent)

    def _run(self, args):
        if not self.enforce:
            print("[DRY-RUN] " + " ".join(args))
            return True
        # list-form args (no shell) + validated inputs => no command injection
        return subprocess.run(args, capture_output=True).returncode == 0

    def _rules(self, kind, target, op):
        if kind == "domain":
            # DNS wire format = length-prefixed labels ending in 0x00, e.g. evil.com -> |04|evil|03|com|00|
            wire = b"".join(bytes([len(l)]) + l.encode() for l in target.split(".")) + b"\x00"
            return ["iptables", op, "FORWARD", "-p", "udp", "--dport", "53", "-m", "string",
                    "--algo", "bm", "--hex-string", "|" + wire.hex() + "|", "-j", "DROP"]
        return ["iptables", op, "FORWARD", "-s", target, "-p", "udp", "--dport", "53", "-j", "DROP"]

    def mitigate(self, ts, src_ip, domain):
        """Returns a short description of the action taken (for the alert)."""
        if domain in config.WHITELIST_DOMAINS or src_ip in config.WHITELIST_IPS:
            return "whitelisted-no-action"
        if not (DOMAIN_RE.match(domain) and IP_RE.match(src_ip)):
            return "invalid-target-skipped"
        kind, target = "domain", domain
        if (kind, target) in self.blocked:
            return "already-blocked"
        if not self._run(self._rules(kind, target, "-I")):
            return "block-failed"
        exp = ts + config.BLOCK_TTL_SECONDS if config.BLOCK_TTL_SECONDS else 0
        self.blocked[(kind, target)] = exp
        self.storage.log_block(ts, kind, target, not self.enforce, exp)
        return f"blocked-domain{'(dry-run)' if not self.enforce else ''}"

    def expire(self, now=None):
        now = now or time.time()
        for (kind, target), exp in list(self.blocked.items()):
            if exp and now >= exp:
                self._run(self._rules(kind, target, "-D"))
                self.storage.deactivate_block(kind, target)
                del self.blocked[(kind, target)]
