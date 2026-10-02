"""Step 4: explainable rule-based scoring. Each triggered rule adds points AND a human-readable reason."""
import config
from models import Features, Verdict

# (rule name, weight). Weights sum > 100 on purpose; score is capped at 100.
W = {"entropy": 30, "label_len": 15, "fqdn_len": 10, "depth": 10,
     "rate": 15, "unique_subs": 25, "qtype": 10, "beacon": 10}


def evaluate(f: Features) -> Verdict:
    score, why = 0, []

    def hit(key, text):
        nonlocal score
        score += W[key]
        why.append(text)

    # Short sub-domains (e.g. 'www', 'mail') have unreliable entropy, so require some length
    if len(f.subdomain) >= 10 and f.entropy > config.ENTROPY_THRESHOLD:
        hit("entropy", f"High entropy {f.entropy} > {config.ENTROPY_THRESHOLD} (encoded-looking subdomain)")
    if f.max_label_len > config.LABEL_LEN_THRESHOLD:
        hit("label_len", f"Very long label ({f.max_label_len} chars)")
    if f.fqdn_len > config.FQDN_LEN_THRESHOLD:
        hit("fqdn_len", f"Long FQDN ({f.fqdn_len} chars)")
    if f.subdomain_count > config.SUBDOMAIN_COUNT_THRESHOLD:
        hit("depth", f"Deep subdomain nesting ({f.subdomain_count} labels)")
    if f.rate > config.RATE_THRESHOLD:
        hit("rate", f"High query rate ({f.rate} in {config.WINDOW_SECONDS}s)")
    if f.unique_subs > config.UNIQUE_SUBDOMAINS_THRESHOLD:
        hit("unique_subs", f"{f.unique_subs} unique subdomains of {f.parent} (data chunks?)")
    if f.susp_qtype_ratio > config.QTYPE_RATIO_THRESHOLD and f.rate >= 10:
        hit("qtype", f"{int(f.susp_qtype_ratio*100)}% of queries are TXT/NULL/CNAME/MX")
    if 0 <= f.beacon_cv < config.BEACON_CV_THRESHOLD:
        hit("beacon", f"Regular timing (CV={f.beacon_cv}) suggests beaconing")

    score = min(score, 100)
    return Verdict(score=score, suspicious=score >= config.ALERT_SCORE, reasons=why)
