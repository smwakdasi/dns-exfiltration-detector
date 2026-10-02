"""Step 3: DNS parsing helpers + feature extraction with per-source sliding windows."""
import math
import statistics
from collections import Counter, defaultdict, deque

import config
from models import DNSEvent, Features

# Minimal multi-part public suffix list. For production use the `tldextract` package.
TWO_LEVEL_SUFFIXES = {"co.ke", "ac.ke", "go.ke", "or.ke", "co.uk", "ac.uk", "com.au", "co.za", "com.ng"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def split_domain(fqdn: str):
    """Return (subdomain, parent). 'a.b.evil.com' -> ('a.b', 'evil.com')."""
    labels = fqdn.lower().rstrip(".").split(".")
    take = 3 if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 2
    if len(labels) <= take:
        return "", ".".join(labels)
    return ".".join(labels[:-take]), ".".join(labels[-take:])


class FeatureExtractor:
    def __init__(self, window=config.WINDOW_SECONDS):
        self.window = window
        self.history = defaultdict(deque)  # src_ip -> deque[(ts, parent, sub, qtype)]

    def _evict(self, dq, now):
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

    def extract(self, ev: DNSEvent) -> Features:
        sub, parent = split_domain(ev.fqdn)
        dq = self.history[ev.src_ip]
        dq.append((ev.ts, parent, sub, ev.qtype))
        self._evict(dq, ev.ts)

        labels = ev.fqdn.rstrip(".").split(".")
        unique_subs = len({s for _, p, s, _ in dq if p == parent and s})
        susp = sum(1 for *_, q in dq if q in config.SUSPICIOUS_QTYPES)

        # Beaconing: regular gaps between queries to the same parent domain
        times = [t for t, p, *_ in dq if p == parent]
        cv = -1.0
        if len(times) >= config.BEACON_MIN_QUERIES:
            gaps = [b - a for a, b in zip(times, times[1:])]
            mean = statistics.mean(gaps)
            cv = statistics.pstdev(gaps) / mean if mean > 0 else -1.0

        return Features(
            fqdn=ev.fqdn, parent=parent, subdomain=sub,
            fqdn_len=len(ev.fqdn),
            max_label_len=max(len(l) for l in labels),
            subdomain_count=len(sub.split(".")) if sub else 0,
            entropy=round(shannon_entropy(sub.replace(".", "")), 3),
            qtype=ev.qtype, rate=len(dq), unique_subs=unique_subs,
            susp_qtype_ratio=round(susp / len(dq), 3), beacon_cv=round(cv, 3),
        )
