"""Step 8: LAB test-traffic generator (use only on your isolated test network).

Produces labelled synthetic DNS query events:
  benign : human-like browsing to popular-looking names
  tunnel : base32 chunks of random dummy bytes as subdomains of a lab domain you own/control

  python3 gen_traffic.py --pcap test.pcap          # write a pcap (needs scapy) -> main.py --pcap test.pcap
  python3 gen_traffic.py --send 192.168.56.10      # live queries to YOUR lab resolver (needs scapy)
"""
import argparse
import base64
import os
import random
import time
from models import DNSEvent

BENIGN = ["www.google.com", "mail.google.com", "accounts.google.com", "www.strathmore.edu", "portal.strathmore.edu",
          "youtube.com", "i.ytimg.com", "fonts.gstatic.com", "update.microsoft.com", "www.bbc.co.uk",
          "api.github.com", "cdn.jsdelivr.net", "ocsp.digicert.com", "www.wikipedia.org", "clients4.google.com",
          "archive.ubuntu.com", "www.nation.africa", "www.linkedin.com", "static.xx.fbcdn.net", "web.whatsapp.com"]
TUNNEL_DOMAIN = "lab-tunnel.example.com"


def benign_events(n, src="10.0.0.5", t0=0.0):
    t = t0
    for _ in range(n):
        t += random.expovariate(1 / 2.5)                 # ~1 query / 2.5s, irregular
        yield DNSEvent(t, src, random.choice(BENIGN), random.choice(["A", "A", "A", "AAAA"])), False


def tunnel_events(n, src="10.0.0.9", t0=0.0, gap=0.3, qtype="TXT"):
    t = t0
    for _ in range(n):
        t += gap
        chunk = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()   # 48 chars of dummy data
        yield DNSEvent(t, src, f"{chunk[:30]}.{chunk[30:]}.{TUNNEL_DOMAIN}", qtype), True


def mixed(n_benign=300, n_tunnel=200, seed=1):
    random.seed(seed)
    evs = list(benign_events(n_benign)) + list(tunnel_events(n_tunnel, t0=10))
    return sorted(evs, key=lambda x: x[0].ts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap")
    ap.add_argument("--send", help="lab resolver IP")
    a = ap.parse_args()
    from scapy.all import IP, UDP, DNS, DNSQR, send, wrpcap
    pkts = []
    for ev, _ in mixed():
        p = IP(src=ev.src_ip, dst=a.send or "10.0.0.1") / UDP(sport=random.randint(20000, 60000), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=ev.fqdn, qtype=ev.qtype))
        p.time = ev.ts
        if a.send:
            send(p, verbose=0); time.sleep(0.05)
        pkts.append(p)
    if a.pcap:
        wrpcap(a.pcap, pkts)
        print(f"wrote {len(pkts)} packets to {a.pcap}")
