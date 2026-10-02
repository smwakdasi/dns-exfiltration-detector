"""Step 2: live or offline DNS capture with Scapy. The only module that needs scapy/root."""
from models import DNSEvent

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}


def _to_event(pkt):
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
        return None
    if pkt[DNS].qr != 0:           # only queries, not responses
        return None
    q = pkt[DNSQR]
    name = q.qname.decode(errors="ignore").rstrip(".").lower()
    return DNSEvent(ts=float(pkt.time), src_ip=pkt[IP].src, fqdn=name, qtype=QTYPES.get(q.qtype, str(q.qtype)))


def sniff_live(callback, iface=None):
    from scapy.all import sniff
    def _h(pkt):
        ev = _to_event(pkt)
        if ev:
            callback(ev)
    sniff(filter="udp port 53", prn=_h, store=False, iface=iface)


def read_pcap(path, callback):
    from scapy.all import PcapReader
    with PcapReader(path) as r:
        for pkt in r:
            ev = _to_event(pkt)
            if ev:
                callback(ev)
