# Darkelf Toolkit --- Refactored (Lite)

Darkelf Toolkit Refactored --- Lite is a streamlined, terminal-first
OSINT toolkit inspired by the original Darkelf project.\
This refactor focuses on safer defaults, clear UX, modular components,
enforced stealth via Tor, and structured export handling.

This repository contains a compact CLI program (Python) that:

-   routes network traffic through Tor by default (stealth mode
    enabled),
-   provides OSINT primitives (search/dork, fetch, indicator
    extraction),
-   includes WHOIS and DNS lookup capabilities,
-   exports reports and lookup results to a dedicated Documents/Darkelf
    folder,
-   uses Rich for a clean terminal UX.

Important: This tool is for ethical OSINT / research only. Use it only
on systems and data you are authorized to access. See the Security &
Legal section below.

------------------------------------------------------------------------

## Quick TL;DR

Install dependencies, start Tor on `127.0.0.1:9052`, then run:

``` bash
python "Darkelf CLI TL OSINT Tool Kit Lite.py"
```

The CLI enforces Tor routing and basic stealth by default.

------------------------------------------------------------------------

## Features

-   Enforced Tor routing for network requests (SOCKS5 `127.0.0.1:9052`)
-   DuckDuckGo onion & clearnet dork/search helper
-   Safe fetch (strips scripts/styles; blocks known trackers)
-   Indicator extraction:
    -   emails
    -   domains
    -   IPs
    -   hashes
    -   usernames
    -   phone numbers
-   WHOIS lookups:
    -   domain WHOIS
    -   IP WHOIS
-   DNS lookups:
    -   A, AAAA, MX, TXT, NS, CNAME, SOA
    -   reverse DNS (PTR)
    -   bulk DNS / reverse DNS from extracted indicators
-   Structured exports:
    -   WHOIS results
    -   DNS results
    -   Bulk lookup results
    -   Indicator exports
    -   Scribe reports
-   Exports saved to:\
    `~/Documents/Darkelf/`
-   Lightweight logging to `darkelf_activity.log`

------------------------------------------------------------------------

## Requirements

-   Python 3.9+
-   System tor (Tor daemon) --- required for stealth/Tor routing

Install Python dependencies:

``` bash
pip install -r requirements.txt
```

If installing manually, required packages are:

``` bash
pip install rich requests beautifulsoup4 tldextract phonenumbers dnspython python-whois stem psutil pysocks
```

Important: - Do NOT install the `whois` package. - Use `python-whois`.

------------------------------------------------------------------------

## Tor: Install & Start

Tor must be running and listening on a SOCKS port for the CLI to route
traffic.

Linux (Debian/Ubuntu):

``` bash
sudo apt update
sudo apt install tor
sudo systemctl start tor
```

If you want to use port 9052 instead of default 9050:

``` bash
tor --SocksPort 9052
```

macOS (Homebrew):

``` bash
brew install tor
brew services start tor
```

Windows:

-   Install Tor Expert Bundle or run Tor Browser.
-   Ensure a SOCKS proxy is reachable at `127.0.0.1:9052`.
-   Update the script if your Tor port differs.

Verify Tor:

``` bash
curl --socks5-hostname 127.0.0.1:9052 https://check.torproject.org/api/ip
```

------------------------------------------------------------------------

## Getting Started

1.  Ensure Tor is running.
2.  Install Python dependencies.
3.  Run the CLI:

``` bash
python "Darkelf CLI TL OSINT Tool Kit copy.py"
```

The banner will display:

    Stealth: ON · Tor: enabled · DNS: available · WHOIS: available

------------------------------------------------------------------------

## Typical Workflow

### Scan

-   Choose `scan`
-   Enter an email, username, phone, domain, or URL
-   The CLI extracts indicators and performs a Tor-routed search

### Dork

-   Choose `dork`
-   Enter a raw search query
-   Optionally use DuckDuckGo Onion Lite
-   Preview content via Tor

### Fetch

-   Choose `fetch`
-   Enter a URL
-   The CLI safely fetches and strips scripts/styles

### Indicators

-   Choose `indicators`
-   View counts
-   Export to JSON

### WHOIS / DNS

Choose `whois/dns`:

-   Domain WHOIS
-   IP WHOIS
-   DNS record queries
-   Reverse DNS
-   Bulk lookups from extracted indicators

All exports are saved automatically to:

    ~/Documents/Darkelf/

------------------------------------------------------------------------

## Scribe (Optional AI Drafting)

If Ollama is installed locally, you can use:

-   `scribe` --- draft structured OSINT reports
-   Export to JSON or Markdown
-   View reports in the local PWA viewer

Ollama must be installed separately:

https://ollama.com/

------------------------------------------------------------------------

## Configuration

Default SOCKS proxy:

    socks5h://127.0.0.1:9052

If your Tor uses another port: - Edit proxy configuration inside the
script.

Safe tracker blocklist: - Modify `self.safe_blocklist` if needed.

------------------------------------------------------------------------

## Security & Legal

-   Use only for lawful, authorized OSINT research.
-   Tor provides network-level anonymity but does not remove legal
    responsibility.
-   WHOIS and DNS queries may still reveal activity to upstream
    providers.
-   Exports are stored under `~/Documents/Darkelf/`.
-   Logs are written to `darkelf_activity.log`.

No destructive anti-forensics features are enabled in this Lite
refactor.

------------------------------------------------------------------------

## Troubleshooting

Tor not reachable: - Confirm Tor is running. - Confirm correct SOCKS
port. - Ensure `pysocks` is installed.

WHOIS errors: - Ensure `python-whois` is installed. - Remove incorrect
`whois` package if present.

DNS errors: - Ensure `dnspython` is installed.

------------------------------------------------------------------------

## Contributing

Contributions welcome.

-   Fork the repo
-   Create a feature branch
-   Submit a PR with clear description

Avoid adding destructive or unsafe features without explicit safeguards.

------------------------------------------------------------------------

## License

LGPL-3.0-or-later --- see LICENSE file.

------------------------------------------------------------------------

## Attribution

Refactor by: Darkelf2024\
Original inspiration: Dr. Kevin Moore and the Darkelf project.
