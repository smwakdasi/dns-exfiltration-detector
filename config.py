"""Central configuration. Tune thresholds here after studying your own baseline traffic."""

DB_PATH = "dnsguard.db"
LOG_PATH = "alerts.log"

# --- Detection thresholds (Chapter 3: explainable, rule-based) ---
ENTROPY_THRESHOLD = 3.5        # Shannon entropy of subdomain part (bits/char)
LABEL_LEN_THRESHOLD = 30       # longest single label
FQDN_LEN_THRESHOLD = 60        # whole name length
SUBDOMAIN_COUNT_THRESHOLD = 4  # labels below the registered domain
RATE_THRESHOLD = 60            # queries / WINDOW_SECONDS from one source
UNIQUE_SUBDOMAINS_THRESHOLD = 40  # distinct subdomains of ONE parent domain in window
SUSPICIOUS_QTYPES = {"TXT", "NULL", "CNAME", "MX"}
QTYPE_RATIO_THRESHOLD = 0.6    # share of suspicious qtypes in window
BEACON_CV_THRESHOLD = 0.15     # coefficient of variation of inter-arrival time (regular = beaconing)
BEACON_MIN_QUERIES = 10

WINDOW_SECONDS = 60

# Score (0-100) at/above which a query is flagged and mitigated
ALERT_SCORE = 50

# --- Mitigation ---
ENFORCE = False                # False = dry-run: log what WOULD be blocked
BLOCK_TTL_SECONDS = 3600       # auto-unblock after this long (0 = permanent)
WHITELIST_DOMAINS = {"google.com", "microsoft.com", "windows.com", "ubuntu.com",
                     "cloudflare.com", "amazonaws.com", "akamai.net", "apple.com"}
WHITELIST_IPS = {"127.0.0.1"}  # never block these sources (add gateway, admin PC, resolver)

# --- Capture ---
INTERFACE = None               # None = scapy default; e.g. "eth0"
