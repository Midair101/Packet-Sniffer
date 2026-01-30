 HEAD
# Network Spy — Packet Sniffer + Privacy Monitor 🔧

A simple educational packet sniffer that monitors your network and *alerts* when devices send likely unencrypted/plaintext data.

> ⚠️ Legal & Ethical Notice: Only run this on networks and devices you own or are explicitly authorized to monitor.

## Features
- Capture packets on a chosen interface (uses Scapy)
- Prints `src:port -> dst:port` with protocol
- Heuristic detection for unencrypted traffic (HTTP, FTP, plain DNS, printable payloads)
- Alerts with a beep and optional logging when plaintext/sensitive data is detected

## Quick start (Windows)
1. Install Npcap: https://nmap.org/npcap/ (required for packet capture).
2. Open an Administrator command prompt.
3. Create a virtual env (optional): `python -m venv .venv && .venv\Scripts\activate`
4. Install dependencies: `pip install -r requirements.txt` (or `pip install scapy`)
5. Run: `python network_spy.py -i <ifacename> -l alerts.log`

## Running tests
If you installed `pytest` (it's in `requirements.txt`), run:

```bash
python -m pytest -q
```

Notes:
- If `pytest` fails to import `network_spy`, run from the project root with the root on PYTHONPATH (PowerShell):

```powershell
$env:PYTHONPATH = (Get-Location).Path; pytest -q
```

- For a developer-friendly one-time setup, install the package in editable mode so imports work without environment tweaks:

```bash
# create a minimal pyproject.toml or setup.cfg, then:
pip install -e .
```

The test suite includes synthetic packet tests to validate the detection heuristics.

## How detection works (simple heuristics)
- Flags common plaintext service ports (80, 21, 23, 25, 110, 143, 53)
- Recognizes HTTP methods and `HTTP/` in payload
- Treats mostly-printable ASCII payloads as potential plaintext
- Detects TLS-like payloads and treats them as encrypted
- Searches payload for sensitive patterns (email addresses, numbers that look like credit cards)

## Limitations & notes
- This is an educational tool, not a robust IDS/IPS.
- Encrypted traffic is not guaranteed to be recognized correctly by port-only heuristics.
- On Wi‑Fi, you may not see other clients' traffic unless the interface is in monitor mode and your NIC/driver supports it.

## Extending
- Add deeper TLS parsing (look for TLS handshake fields)
- Integrate with system notifications or a UI
- Save full packet captures when alerts occur

## Troubleshooting ⚠️
- Permission denied: On Windows, run the script from an **Administrator** command prompt and ensure **Npcap** is installed (https://nmap.org/npcap/).
- No interfaces listed: Your NIC may not support the requested capture mode; try running without monitor mode or check `get_if_list()` output.
- Not seeing other Wi‑Fi clients: To capture other clients' traffic you typically need monitor mode which depends on your Wi‑Fi adapter and driver.

---



# Packet-Sniffer
 0edc8de4fc9ff12c90084fced49f515edcd0eee3
