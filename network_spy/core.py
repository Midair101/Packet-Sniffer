#!/usr/bin/env python3
"""
Network Spy — Packet Sniffer + Privacy Monitor

Features:
- List interfaces and capture packets on the selected interface
- Show src IP, dst IP, protocol
- Heuristic detection of unencrypted/plaintext traffic (HTTP, FTP, SMTP, DNS, etc.)
- Alert (console message + beep) when unencrypted payload is detected

Run as administrator and have Npcap/WinPcap installed on Windows.
"""

import argparse
import re
import sys
import time
import json
from datetime import datetime

try:
    # scapy is required for packet capture
    from scapy.all import sniff, get_if_list
    from scapy.layers.inet import IP, TCP, UDP
except Exception as e:
    print("Scapy is required. Install it with: pip install scapy")
    raise

# Windows beep fallback
try:
    import winsound
    def beep():
        winsound.Beep(1000, 200)
except Exception:
    def beep():
        print("\a", end='')  # terminal bell

# Known plaintext service ports (simple heuristic)
PLAINTEXT_PORTS = {80, 21, 20, 23, 25, 110, 143, 53}  # HTTP, FTP, TELNET, SMTP, POP3, IMAP, DNS
ENCRYPTED_PORTS = {443, 993, 995, 22, 465}  # HTTPS, IMAPS, POP3S, SSH, SMTP over TLS

# Common HTTP methods to detect plaintext HTTP payload
HTTP_METHODS = [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS"]

# Patterns for sensitive data (simple regexes)
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CREDIT_CARD_RE = re.compile(rb"\b(?:\d[ -]*?){13,16}\b")

LOG_FILE = None


def is_printable_ascii(b: bytes, threshold=0.8) -> bool:
    if not b:
        return False
    printable = sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13))
    return (printable / len(b)) >= threshold


def looks_like_tls(payload: bytes) -> bool:
    # TLS record starts with 0x16 0x03 (Handshake, TLS version)
    return len(payload) > 2 and payload[0] == 0x16 and payload[1] == 0x03


def detect_unencrypted(pkt) -> tuple[bool, str]:
    """Return (is_unencrypted, reason)"""
    # Only check IP packets with TCP/UDP carrying payload
    if IP not in pkt:
        return (False, "no IP")
    ip = pkt[IP]
    sport = None
    dport = None
    payload = b""
    proto = "?"
    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        payload = bytes(pkt[TCP].payload)
        # TLS check
        if looks_like_tls(payload):
            return (False, "TLS-like")
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        payload = bytes(pkt[UDP].payload)

    # Check by port, prefer known service names
    if (sport in PLAINTEXT_PORTS) or (dport in PLAINTEXT_PORTS):
        # Prefer to label HTTP explicitly when port 80 is involved
        if sport == 80 or dport == 80:
            return (True, "http-plaintext")
        return (True, f"plaintext-port {sport or dport}")
    if (sport in ENCRYPTED_PORTS) or (dport in ENCRYPTED_PORTS):
        return (False, "encrypted-port")

    # Heuristics on payload bytes
    if payload:
        # HTTP detection
        for m in HTTP_METHODS:
            if payload.startswith(m + b" ") or b"HTTP/" in payload:
                return (True, "http-plaintext")
        # Detect email-like or credit-card-like strings in payload
        if EMAIL_RE.search(payload) or CREDIT_CARD_RE.search(payload):
            return (True, "sensitive-data-in-plaintext")
        # If payload looks mostly printable ASCII and not TLS, treat as unencrypted
        if is_printable_ascii(payload) and not looks_like_tls(payload):
            return (True, "printable-ascii")

    return (False, "no-indicators")


def format_pkt_summary(pkt):
    ip = pkt[IP]
    proto = None
    sport = dport = "?"
    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        proto = str(ip.proto)
    return f"{ip.src}:{sport} -> {ip.dst}:{dport} ({proto})"


def handle_packet(pkt):
    now = datetime.now().isoformat(timespec='seconds')
    if IP not in pkt:
        return
    summary = format_pkt_summary(pkt)

    unenc, reason = detect_unencrypted(pkt)
    if unenc:
        message = f"[ALERT {now}] Unencrypted traffic detected: {summary} — reason: {reason}"
        print("\n" + "!"*3 + " ALERT " + "!"*3)
        print(message)
        print("!"*22)
        beep()
        # Log to file if enabled
        if LOG_FILE:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps({"time": now, "summary": summary, "reason": reason}) + "\n")
    else:
        # Print light info
        print(f"{now} - {summary} - ok ({reason})")


def choose_interface(name=None):
    if name:
        return name
    ifaces = get_if_list()
    print("Available interfaces:")
    for i, itf in enumerate(ifaces, 1):
        print(f"  {i}) {itf}")
    sel = input("Choose interface number or name (default 1): ")
    if not sel:
        return ifaces[0]
    try:
        idx = int(sel)
        return ifaces[idx - 1]
    except Exception:
        return sel


def main():
    global LOG_FILE
    parser = argparse.ArgumentParser(description="Network Spy — Packet Sniffer + Privacy Monitor")
    parser.add_argument('-i', '--interface', help='Interface name to capture on')
    parser.add_argument('-t', '--timeout', type=int, default=0, help='Capture duration in seconds (0 = forever)')
    parser.add_argument('-l', '--log', help='Enable logging alerts to file')
    parser.add_argument('--filter', help='BPF filter to pass to sniff()')
    args = parser.parse_args()

    if args.log:
        LOG_FILE = args.log
        print(f"Logging alerts to {LOG_FILE}")

    iface = choose_interface(args.interface)
    print(f"Starting capture on {iface}. Press Ctrl-C to stop.")

    try:
        sniff(iface=iface, prn=handle_packet, store=0, timeout=(args.timeout or None), filter=args.filter)
    except RuntimeError as e:
        # Some Windows setups don't have WinPcap/Npcap available; fall back to L3 socket
        msg = str(e).lower()
        if 'winpcap is not installed' in msg or 'no libpcap provider' in msg:
            print("WinPcap/Npcap not available; falling back to layer-3 capture (no link-layer headers).")
            try:
                from scapy.all import conf
                sniff(iface=iface, prn=handle_packet, store=0, timeout=(args.timeout or None), filter=args.filter, L2socket=conf.L3socket)
            except Exception as e2:
                print("Fallback to L3 socket failed:", e2)
                sys.exit(1)
        else:
            print("RuntimeError during sniff:", e)
            sys.exit(1)
    except PermissionError:
        print("Permission denied. On Windows, run as Administrator and ensure Npcap is installed.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")


if __name__ == '__main__':
    main()
