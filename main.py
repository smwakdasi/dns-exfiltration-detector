"""Run the system.   sudo python3 main.py --iface eth0 [--enforce]     |     python3 main.py --pcap test.pcap"""
import argparse
import capture
import config
from pipeline import Pipeline

ap = argparse.ArgumentParser()
ap.add_argument("--iface", default=config.INTERFACE)
ap.add_argument("--pcap", help="analyse an existing capture instead of sniffing live")
ap.add_argument("--enforce", action="store_true", help="really apply iptables rules (needs root)")
a = ap.parse_args()

p = Pipeline(enforce=a.enforce)
print(f"DNS-Guard running | enforce={a.enforce} | source={'pcap ' + a.pcap if a.pcap else 'live'}")
if a.pcap:
    capture.read_pcap(a.pcap, p.process)
else:
    capture.sniff_live(p.process, a.iface)
