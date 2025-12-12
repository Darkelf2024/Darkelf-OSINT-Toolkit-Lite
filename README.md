# Darkelf Toolkit — Refactored (Lite)

Darkelf Toolkit Refactored — Lite is a streamlined, terminal-first OSINT toolkit inspired by the original Darkelf project.  
This refactor focuses on safer defaults, clear UX, modular components, enforced stealth via Tor, and an optional post‑quantum (Kyber) vault for protecting short secrets.

This repository contains a compact CLI program (Python) that:
- routes network traffic through Tor by default (stealth mode enabled),
- provides quick OSINT primitives (search/dork, fetch, indicator extraction),
- includes an optional Kyber-based vault (requires liboqs + python-oqs),
- uses Rich for a nicer terminal UX.

Important: This tool is for ethical OSINT / research only. Use it only on systems and data you are authorized to access. See the Security & Legal section below.

---

## Quick TL;DR

Install dependencies, start Tor on `127.0.0.1:9052`, then run:

```bash
python "Darkelf CLI TL OSINT Tool Kit Lite.py"
```

The CLI enforces Tor routing and basic stealth by default. If you want the Kyber vault features, install liboqs and the Python binding (`oqs`).

---

## Features

- Enforced Tor routing for network requests (SOCKS5 `127.0.0.1:9052`)
- DuckDuckGo onion & clearnet dork/search helper
- Safe fetch (strips scripts/styles; tracks and blocks known trackers)
- Indicator extraction (emails, domains, IPs, hashes, usernames, phones)
- Kyber (post-quantum) vault: generate keypair, encrypt, decrypt (optional)
- Human-friendly TUI with Rich (panels, tables, prompts)
- Lightweight logging to `darkelf_activity.log`

---

## Requirements

- Python 3.9+
- System tor (Tor daemon) — required for stealth/Tor routing
- Recommended Python packages (install via pip):

```bash
pip install -r requirements.txt
```

If you do not have a requirements file, these packages are required/used:

- rich
- requests
- beautifulsoup4
- tldextract
- phonenumbers
- pysocks (for requests SOCKS support)
- oqs (optional — required for Kyber vault)

Install core deps:

```bash
pip install rich requests beautifulsoup4 tldextract phonenumbers pysocks
```

Vault (optional):

- liboqs — native library (see liboqs docs)
- python-oqs binding (pip package `oqs`) — only if you want PQ vault support

---

## Tor: Install & Start

Tor must be running and listening on a SOCKS port for the CLI to route traffic.

Linux (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install tor
sudo systemctl start tor
# If you want to use port 9052 instead of default 9050 you can run tor manually:
tor --SocksPort 9052
```

macOS (Homebrew):

```bash
brew install tor
brew services start tor
# or for manual run:
tor --SocksPort 9052
```

Windows:

- Install Tor Expert Bundle or run Tor Browser and configure/proxy appropriately.
- Ensure a SOCKS proxy is reachable at `127.0.0.1:9052` (update the script if your port differs).

Verify Tor (example):

```bash
curl --socks5-hostname 127.0.0.1:9052 https://check.torproject.org/api/ip
```

If this returns an IP and `anonymous` details, Tor is available.

---

## Getting started

1. Ensure Tor is running (see above).
2. Ensure Python dependencies are installed.
3. Run the CLI:

```bash
python "Darkelf CLI TL OSINT Tool Kit copy.py"
```

Note: the script enforces Tor (SOCKS proxy `127.0.0.1:9052`) and prints a banner showing Stealth: ON.

---

## Typical workflow (examples)

- Quick scan (email / username / phone / domain / url)
  - Choose `scan` from the menu and enter the target.
  - The CLI extracts indicators locally and runs a DuckDuckGo search (via Tor).

- Dorking
  - Choose `dork`, supply a query (e.g. `"joe@example.com" site:pastebin.com`), pick Onion Lite when prompted (default true).
  - Optionally preview page content (fetched via Tor).

- Fetch & preview
  - Choose `fetch`, enter a URL — the CLI fetches content via Tor, strips scripts/styles, and shows a safe preview.

- Indicators
  - Choose `indicators` to view counts and export extracted indicators to JSON.

---

## Kyber Vault (optional)

The vault uses liboqs + python-oqs to perform a Kyber KEM encapsulation to store small plaintexts.

Prereqs:
- Install liboqs (follow liboqs build/install instructions).
- Install Python binding:

```bash
pip install oqs
```

Vault usage (from CLI):
1. Select `vault` from the menu.
2. `generate` — creates `vault/kyber_pub.bin` and `vault/kyber_priv.bin`.
3. `encrypt` — provide a line of plaintext and the program writes `vault/vault_<timestamp>.dat`.
4. `decrypt` — pick a vault file to decrypt (requires the private key present).

Programmatic notes:
- Vault files are simple container format `v1||<ct_b64>||<key_b64>||<token_b64>`.
- The private key file is stored under `vault/kyber_priv.bin`. Protect it appropriately (file permissions, encrypted storage, etc.).

---

## Configuration

- Default SOCKS proxy: `socks5h://127.0.0.1:9052`
  - If your Tor listens on a different port, either:
    - set up a local socket forwarding, or
    - edit the script where proxies are created (search for `socks5h://127.0.0.1:9052`) and replace with your port.
- Safe tracker blocklist: `self.safe_blocklist` — change if needed.

---

## Security & Legal

- Use this toolkit only for lawful, authorized OSINT and research tasks.
- Tor provides network-level anonymity but does NOT remove legal/ethical obligations.
- The Kyber vault depends on liboqs/oqs; ensure you verify and secure generated private keys.
- The script writes logs to `darkelf_activity.log` and vault files to `vault/` — do not leave sensitive files on disk if you cannot secure them.
- The original Darkelf project had strong anti-forensics and self-wipe features; this refactor intentionally disables aggressive destructive behavior from the interactive path. Secure wipe helpers are intentionally gated and require explicit operator confirmation.

---

## Troubleshooting

- "Tor not reachable" or timeout errors:
  - Confirm Tor is running and bound to the configured port.
  - Confirm `pysocks` is installed so `requests` can use `socks5h://`.
- "Vault unavailable":
  - Make sure `liboqs` is installed and `pip install oqs` succeeded.
  - Running `python -c "import oqs; print(oqs.__version__)"` should succeed.
- Network fetch returns empty or parsing errors:
  - Some sites block Tor exit nodes or present anti-bot challenges. Use the onion DuckDuckGo Lite endpoint where appropriate.

---

## Contributing

Contributions welcome. Suggested workflow:
1. Fork the repo.
2. Add/modify code in a feature branch.
3. Open a PR with a clear description and tests if applicable.

Please avoid adding destructive anti-forensics code paths without clear opt-in flags and safeguards.

---

## License

LGPL-3.0-or-later — see LICENSE file in this repository.

---

## Contact / Attribution

Refactor by: Darkelf2024  
Original author / inspiration: Dr. Kevin Moore and the Darkelf project.

If you'd like, I can:
- add a sample `requirements.txt`,
- provide a small systemd service example to run Tor on a non-default port (9052),
- or add a simple `config.yaml` to externalize the SOCKS port and other settings.

Which would you prefer next?
