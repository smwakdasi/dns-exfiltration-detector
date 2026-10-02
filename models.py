from dataclasses import dataclass, field


@dataclass
class DNSEvent:
    """One parsed DNS query (output of capture/parser)."""
    ts: float
    src_ip: str
    fqdn: str
    qtype: str


@dataclass
class Features:
    fqdn: str
    parent: str            # registered domain, e.g. attacker.com
    subdomain: str         # everything left of parent
    fqdn_len: int
    max_label_len: int
    subdomain_count: int
    entropy: float
    qtype: str
    rate: int              # queries from src in window
    unique_subs: int       # distinct subdomains of `parent` from src in window
    susp_qtype_ratio: float
    beacon_cv: float       # -1 if not enough data


@dataclass
class Verdict:
    score: int
    suspicious: bool
    reasons: list = field(default_factory=list)
