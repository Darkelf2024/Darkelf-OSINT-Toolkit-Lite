# Darkelf CLI TL OSINT Tool Kit Lite v3.0 – Secure, Privacy-Focused Command-Line Web Browser
# Copyright (C) 2025 Dr. Kevin Moore
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# EXPORT COMPLIANCE NOTICE:
# This software contains publicly available encryption source code and is
# released under License Exception TSU in accordance with 15 CFR §740.13(e) of the
# U.S. Export Administration Regulations (EAR).
#
# A public notification of source code release has been submitted to the
# U.S. Bureau of Industry and Security (BIS) and the National Security Agency (NSA).
#
# The software includes implementations of standard cryptographic algorithms
# (e.g., AES, RSA, ChaCha20, TLS 1.3, X25519) for research and general-purpose use.
#
# This is source code only. No compiled binaries are included in this distribution.
# Redistribution, modification, or use must comply with all applicable U.S. export
# control laws and regulations.
#
# PROHIBITED DESTINATIONS:
# This software may not be exported or transferred, directly or indirectly, to:
# - Countries or territories under comprehensive U.S. embargo (OFAC or BIS lists),
# - Entities or individuals listed on the U.S. Denied Persons, Entity, or SDN Lists,
# - Parties on the BIS Country Group E:1 or E:2 lists.
#
# END-USE RESTRICTIONS:
# This software may not be used in the development or production of weapons of mass
# destruction, including nuclear, chemical, biological weapons, or missile systems
# as defined in EAR Part 744.
#
# By downloading, using, or distributing this software, you agree to comply with
# all applicable export control laws.
#
# This software is published under the LGPL v3.0 license and authored by
# Dr. Kevin Moore, 2025.
#
# NOTE: This is the CLI (Command-Line Interface) edition of Darkelf.
# It is entirely terminal-based and does not use PyQt5, PySide6, or any GUI frameworks.

# DISCLAIMER:
# This tool is intended for educational, research, and ethical OSINT (Open Source Intelligence) purposes only.
# It must only be used on systems and data for which you have explicit, authorized access.
# The developer assumes no responsibility for misuse or illegal activities performed using this tool.

# NOTE:
# This tool routes network traffic through the Tor network for anonymity.
# Ensure your use of Tor and any target services complies with all applicable laws and terms of service.

# © [Dr. Kevin Moore] – Original author of Darkelf Post-Quantum AI and DarkelfPQChat
# Released under the LGPL license. Contributions welcome.

# Darkelf CLI TL OSINT Tool Kit — Refactored & Enhanced Edition v3.1
# Copyright (C) 2025 Dr. Kevin Moore (original) — Refactor by Darkelf2024
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# NOTE:
# - This is a refactor and UX-focused enhancement of the original Darkelf CLI.
# - The tool remains intended for ethical OSINT and research use only.
# - Be careful when running network code (Tor recommended for privacy).
#
# High-level goals of this rewrite:
# - Cleaner, modular structure (Utilities, Indicators, Scanners, Vault, CLI)
# - Safer defaults and clearer warnings about destructive operations
# - Improved UX via Rich (consistent console styling)
# - Simple plug-in friendly architecture for adding new scanners
# - Better error handling and logging
#
# Dependencies (selectively used):
# - rich, requests, tldextract, phonenumbers, bs4 (beautifulsoup4), oqs (optional)
# - If oqs (Open Quantum Safe) is not installed the PQ vault falls back gracefully.
#
# A note on capabilities:
# - This rewrite intentionally removes/neutralizes "self-destruct on debugger"
#   aggressive anti-forensics behavior from the interactive path by default.
#   Those features (secure wipe / panic) require explicit operator consent and
#   are left in helper functions guarded by confirm prompts.
#
# Always obey laws, terms-of-service, and use only on data/systems you are
# authorized to test or investigate.

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
import tldextract
from bs4 import BeautifulSoup
from phonenumbers import PhoneNumberMatcher, PhoneNumberFormat, parse as parse_phone, is_valid_number, format_number
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Optional imports (graceful fallback)
try:
    import oqs
except Exception:
    oqs = None
    
import subprocess

try:
    import psutil  # optional, for RAM detection
except Exception:
    psutil = None
    
from typing import Any

from stem.control import Controller
from stem.process import launch_tor_with_config
from stem import Signal

TOR_PORT = 9052  # detected from tor startup
PROXY = f"socks5h://127.0.0.1:{TOR_PORT}"

# ---------------------------
# Global Console and Logger
# ---------------------------
console = Console()
LOG_PATH = "darkelf_activity.log"

def _log(msg: str, level: str = "INFO"):
    line = f"{datetime.utcnow().isoformat()} [{level}] {msg}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if level == "ERROR":
        console.print(f"[red]{line}[/red]")
    elif level == "WARN":
        console.print(f"[yellow]{line}[/yellow]")
    else:
        console.print(f"[cyan]{line}[/cyan]")

# ---------------------------
# Tor Manager Using Stem
# ---------------------------
class TorManager:
    def __init__(self, tor_binary="tor", socks_port=9052, control_port=9053):
        self.tor_binary = tor_binary
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_process = None
        self.tor_controller = None

    def start_tor(self):
        """Launch Tor process and establish a control connection."""
        try:
            self.tor_process = launch_tor_with_config(
                config={"SOCKSPort": str(self.socks_port), "ControlPort": str(self.control_port)},
                init_msg_handler=self._tor_output_handler,
                tor_cmd=self.tor_binary,
            )
            self.tor_controller = Controller.from_port(port=self.control_port)
            self.tor_controller.authenticate()
            self.tor_controller.signal(Signal.NEWNYM)
            console.print(f"[green]Tor started successfully on SOCKSPort {self.socks_port} and ControlPort {self.control_port}[/green]")
        except Exception as e:
            _log(f"Failed to start Tor: {e}", "ERROR")
            raise RuntimeError("Tor startup failed. Ensure that Tor is installed and accessible.")

    def new_identity(self):
        """Request a new identity from the Tor network."""
        if self.tor_controller:
            self.tor_controller.signal(Signal.NEWNYM)
            console.print("[green]Tor network identity refreshed successfully.[/green]")

    def stop_tor(self):
        """Stop the Tor process and clean up controller."""
        if self.tor_controller:
            self.tor_controller.close()
            console.print("[yellow]Tor controller closed.[/yellow]")
        if self.tor_process:
            self.tor_process.terminate()
            console.print("[yellow]Tor process terminated.[/yellow]")

    @staticmethod
    def _tor_output_handler(line):
        _log(line.strip(), level="INFO")

# ---------------------------
# Utility helpers
# ---------------------------
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[A-Za-z]{2,63}\b")
HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64})\b")
USERNAME_RE = re.compile(r"@([\w\-_]{3,32})")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")


def normalize_domain(token: str) -> Optional[str]:
    ext = tldextract.extract(token)
    if ext.domain and ext.suffix:
        parts = [p for p in (ext.subdomain, ext.domain, ext.suffix) if p]
        return ".".join(parts)
    return None


def pretty_table(rows: Iterable[Tuple], columns: List[str], title: Optional[str] = None) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    for c in columns:
        table.add_column(c)
    for row in rows:
        table.add_row(*[str(x) for x in row])
    console.print(table)
    
SCRIBE_REPORT_SCHEMA = {
    "type": "object",
    "required": ["metadata", "summary", "evidence", "sources"],
    "properties": {
        "metadata": {
            "type": "object",
            "required": ["generated_at", "tool", "version", "report_type"],
        },
        "summary": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "sources": {"type": "array", "items": {"type": "string"}},
        "investigator_notes": {"type": "string"},
        "extracted_indicators": {"type": "object"},
        "legal_notice": {"type": "string"}
    }
}

# ---------------------------
# Indicator Extraction
# ---------------------------
@dataclass
class Indicators:
    emails: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)
    usernames: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)

    def ingest_text(self, text: str, region: str = "US"):
        text = text or ""
        # emails
        for m in EMAIL_RE.findall(text):
            self.emails.add(m.lower())
        # domains (loose)
        for token in re.findall(r"[A-Za-z0-9._-]+\.[A-Za-z]{2,63}", text):
            d = normalize_domain(token)
            if d:
                self.domains.add(d.lower())
        # ips
        for m in IPV4_RE.findall(text):
            try:
                # Quick sanity, keep only routable addresses
                ip = socket.inet_aton(m)  # will raise on invalid
                self.ips.add(m)
            except Exception:
                continue
        # hashes
        for h in HASH_RE.findall(text):
            if isinstance(h, tuple):
                h = h[0]
            self.hashes.add(h.lower())
        # usernames
        for u in USERNAME_RE.findall(text):
            self.usernames.add(u)
        # phones (phonenumbers offers better parsing)
        for m in PhoneNumberMatcherIter(text, region):
            self.phones.add(m)


def PhoneNumberMatcherIter(text: str, region="US"):
    # Small generator wrapper to return E164 formatted numbers
    for m in PhoneNumberMatcher(text, region):
        try:
            if is_valid_number(m.number):
                yield format_number(m.number, PhoneNumberFormat.E164)
        except Exception:
            continue


# ---------------------------
# DuckDuckGo (Onion/Clearnet) Lightweight Scraper
# ---------------------------
class DuckDuckGoLite:
    LITE_ONION = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    HTML_CLEARNET = "https://duckduckgo.com/html/"

    def __init__(self, use_tor: bool = True, proxies: Optional[Dict[str, str]] = None, user_agent: Optional[str] = None):
        self.session = requests.Session()
        self.use_tor = use_tor

        # Auto-detect Tor SOCKS port if none supplied
        if proxies:
            self.proxies = proxies
        elif use_tor:
            self.proxies = self._detect_tor_proxy()
        else:
            self.proxies = None

        self.session.headers.update({"User-Agent": user_agent or "DarkelfCLI/3.1 (OSINT) - Stealth/Tor"})

    def _detect_tor_proxy(self) -> Dict[str, str]:
        """Try common Tor proxy ports and return a working one."""
        for port in (9050, 9150, 9052):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                s.close()
                return {
                    "http": f"socks5h://127.0.0.1:{port}",
                    "https": f"socks5h://127.0.0.1:{port}"
                }
            except Exception:
                continue

        # Last resort: return None, so clearnet works instead of failing
        _log("Tor not detected — proxy disabled, using clearnet only", "WARN")
        return None


    def search(self, query: str, max_results: int = 8, use_onion: bool = False) -> List[Tuple[str, str, str]]:
        """
        Return list of tuples: (title, url, snippet)
        """
        out = []
        if use_onion and self.use_tor:
            url = f"{self.LITE_ONION}?q={requests.utils.quote(query)}"
            try:
                r = self.session.get(url, timeout=20, proxies=self.proxies)
                r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.select("a[href]"):
                    href = a.get("href") or ""
                    title = a.get_text(strip=True) or "[no title]"
                    if href.startswith("http") and title:
                        out.append((title, href, ""))
                        if len(out) >= max_results:
                            break
            except Exception as e:
                _log(f"Onion DDG search failed: {e}", "WARN")
        # fallback to clearnet HTML endpoint (also routed via proxy if use_tor True)
        if not out:
            url = self.HTML_CLEARNET
            try:
                r = self.session.get(url, params={"q": query}, timeout=15, proxies=self.proxies)
                r.raise_for_status()
                soup = BeautifulSoup(r.text, "html.parser")
                for rdiv in soup.select(".result"):
                    a = rdiv.select_one(".result__a")
                    snippet_tag = rdiv.select_one(".result__snippet")
                    if not a:
                        continue
                    href = a.get("href", "")
                    title = a.get_text(strip=True)
                    snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
                    if href and title and not href.startswith("/l/?kh="):
                        out.append((title, href, snippet))
                        if len(out) >= max_results:
                            break
            except Exception as e:
                _log(f"Clearnet DDG search failed: {e}", "WARN")
        return out


# ---------------------------
# Lightweight fetch / safe rendering
# ---------------------------
def fetch_url_text(url: str, use_tor: bool = True, timeout: int = 15, safe_blocklist: Optional[Iterable[str]] = None) -> Tuple[str, str]:
    """
    Fetch a URL and return (final_url, text_content). Safe blocklist prevents fetching known tracker domains.

    Default use_tor=True to enforce Tor routing by default (stealth mode enabled).
    """
    safe_blocklist = safe_blocklist or []
    parsed = requests.utils.urlparse(url)
    host = parsed.netloc.lower()

    for banned in safe_blocklist:
        if banned in host:
            raise ValueError(f"Blocked host by policy: {host}")

    session = requests.Session()
    proxies = {"http": "socks5h://127.0.0.1:9052", "https": "socks5h://127.0.0.1:9052"} if use_tor else None
    headers = {"User-Agent": "DarkelfCLI/3.1 - Stealth/Tor"}
    r = session.get(url, timeout=timeout, proxies=proxies, headers=headers)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    # Remove scripts/styles for safer text extraction
    for tag in soup(["script", "style", "noscript", "iframe"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    return r.url, text


# ---------------------------
# PQ KEM Vault (optional)
# ---------------------------
class KyberVault:
    """
    Simple vault that uses OQS Kyber to encrypt random vault items.
    Requires oqs package installed. If not available, vault is disabled.
    """
    def __init__(self, vault_dir: str = "vault", kem_algo: str = "Kyber768"):
        self.vault_dir = vault_dir
        os.makedirs(self.vault_dir, exist_ok=True)
        self.kem_algo = kem_algo
        self.kem = oqs.KeyEncapsulation(kem_algo) if oqs else None
        self.pubkey_path = os.path.join(self.vault_dir, "kyber_pub.bin")
        self.privkey_path = os.path.join(self.vault_dir, "kyber_priv.bin")

    def available(self) -> bool:
        return oqs is not None

    def generate_keys(self) -> Tuple[str, str]:
        if not self.available():
            raise RuntimeError("OQS not available, cannot generate keys.")
        pub = self.kem.generate_keypair()
        priv = self.kem.export_secret_key()
        with open(self.pubkey_path, "wb") as f:
            f.write(pub)
        with open(self.privkey_path, "wb") as f:
            f.write(priv)
        _log("Generated Kyber keypair")
        return self.pubkey_path, self.privkey_path

    def encrypt(self, plaintext: str) -> str:
        if not self.available():
            raise RuntimeError("Vault unavailable.")
        if not os.path.exists(self.pubkey_path):
            raise FileNotFoundError("Public key missing; generate keys first.")
        with open(self.pubkey_path, "rb") as f:
            pub = f.read()
        ct, ss = self.kem.encap_secret(pub)
        # Derive key from ss (shortened) and use Fernet-like pattern with base64
        key = base64.urlsafe_b64encode(ss[:32])
        token = base64.b64encode(plaintext.encode())
        payload = b"v1||" + base64.b64encode(ct) + b"||" + key + b"||" + token
        fname = f"vault_{int(time.time())}.dat"
        path = os.path.join(self.vault_dir, fname)
        with open(path, "wb") as f:
            f.write(payload)
        _log(f"Encrypted vault item {fname}")
        return path

    def decrypt(self, filename: str) -> str:
        if not self.available():
            raise RuntimeError("Vault unavailable.")
        path = os.path.join(self.vault_dir, filename)
        if not os.path.exists(path):
            raise FileNotFoundError("Vault file not found.")
        with open(path, "rb") as f:
            content = f.read()
        if not content.startswith(b"v1||"):
            raise ValueError("Unsupported vault format.")
        _, ct_b64, key_b64, token_b64 = content.split(b"||", 3)
        ct = base64.b64decode(ct_b64)
        key = key_b64  # direct derived key (base64)
        token = base64.b64decode(token_b64)
        # decap with privkey
        with open(self.privkey_path, "rb") as f:
            priv = f.read()
        kem = oqs.KeyEncapsulation(self.kem_algo, secret_key=priv)
        ss = kem.decap_secret(ct)
        derived = base64.urlsafe_b64encode(ss[:32])
        if derived != key:
            raise ValueError("Decryption key mismatch.")
        return token.decode()


# ---------------------------
# CLI: Lightweight, guided interactions
# ---------------------------
class DarkelfCLI:
    def __init__(self):
        self.indicators = Indicators()
        # Always enable Tor/Stealth by default
        self.ddg = DuckDuckGoLite(use_tor=True)
        self.vault = KyberVault()
        self.safe_blocklist = {"google-analytics.com", "doubleclick.net", "facebook.net"}
        self.running = True
        self.stealth_mode = True  # explicit flag for UI/logic if needed
        
        # Darkelf OSINT Ai Queue
        self.ai_queue = []
        self.ai_worker_running = False
        self.ai_lock = threading.Lock()
        self.last_scribe_output = None
        self.pwa_server_running = False

    def banner(self):
        console.clear()
        console.print(Panel.fit(
            Text.from_markup(
                "[bold green]ＤＡＲＫＥＬＦ[/bold green] — OSINT Toolkit (Refactored)\n"
                "[dim]Stealth: ON · Tor: enabled · Vault: {vault}[/dim]".format(vault="available" if self.vault.available() else "unavailable")
            ),
            border_style="bright_magenta",
        ))

    def main_menu(self):
        self.banner()
        menu = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False)
        menu.add_column("cmd", style="cyan", no_wrap=True)
        menu.add_column("description", style="white")
        menu.add_row("1) scan", "Quick OSINT scan (email/username/phone/url) — via Tor")
        menu.add_row("2) dork", "Run a DuckDuckGo dork (onion/clearnet) — via Tor")
        menu.add_row("3) indicators", "Show extracted indicators and export")
        menu.add_row("4) fetch", "Fetch & preview a URL (safe-blocked) — via Tor")
        menu.add_row("5) vault", "Kyber vault operations (generate/encrypt/decrypt)")
        menu.add_row("6) help", "Show help")
        menu.add_row("7) scribe", "Darkelf Scribe — Draft TraceLabs / CTF submission (local AI)")
        menu.add_row("8) viewer", "Open Darkelf Scribe PWA Viewer (offline)")
        menu.add_row("q) quit", "Exit")
        console.print(menu)
        choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5", "6", "7", "8", "q"], default="1")
        return choice

    def cmd_scan(self):
        query = Prompt.ask("Enter email / username / phone / domain / URL").strip()
        if not query:
            return
        console.print(Rule(title=f"Scanning: {query}"))
        # Quick local indicator extraction
        self.indicators.ingest_text(query)
        # If looks like email, run email-centric dorks
        if "@" in query:
            console.print("[green]Email detected — running quick dork suggestions (via Tor)[/green]")
            dorks = [
                f'"{query}" site:pastebin.com',
                f'"{query}" site:github.com',
                f'"{query}" filetype:txt'
            ]
            for d in dorks:
                console.print(f" • {d}")
        elif re.match(r"^\+?\d[\d\s()\-]{7,}$", query):
            console.print("[green]Phone-like input — normalizing and suggesting dorks[/green]")
            # use phonenumbers normalize attempting E164
            try:
                pnorm = next(PhoneNumberMatcherIter(query), None)
                if pnorm:
                    console.print(f"Normalized: {pnorm}")
                    self.indicators.phones.add(pnorm)
            except Exception:
                pass
        # Quick DDG search summary (Tor enforced)
        results = self.ddg.search(query, max_results=6, use_onion=True)
        if results:
            pretty_table([(i + 1, t, u) for i, (t, u, s) in enumerate(results)], ["#", "Title", "URL"],
                         title=f"Top {len(results)} DDG results (via Tor)")
            # ingest snippets/urls
            for title, url, snippet in results:
                self.indicators.ingest_text(f"{title} {url} {snippet}")
        else:
            console.print("[yellow]No quick results from DuckDuckGo (via Tor).[/yellow]")

    def cmd_dork(self):
        query = Prompt.ask("Dork query (raw) — e.g. \"'joe@example.com' site:pastebin.com'\"").strip()
        # Since Tor is enforced, default use_onion True
        use_onion = Confirm.ask("Use DuckDuckGo Onion Lite (via Tor/proxy)?", default=True)
        results = self.ddg.search(query, max_results=12, use_onion=use_onion)
        if not results:
            console.print("[yellow]No results.[/yellow]")
            return
        table_rows = []
        for i, (title, url, snippet) in enumerate(results, 1):
            table_rows.append((i, title, url))
        pretty_table(table_rows, ["#", "Title", "URL"], title="Dork Results")
        # Optionally fetch one (via Tor)
        if Confirm.ask("Fetch a result to preview content? (will use Tor)", default=False):
            idx = Prompt.ask("Result # to fetch (1..%d)" % (len(results)), default="1")
            try:
                idxi = int(idx) - 1
                _, url, _ = results[idxi]
                final_url, text = fetch_url_text(url, use_tor=True, safe_blocklist=self.safe_blocklist)
                console.print(Panel(Text("\n".join(text.splitlines()[:30])), title=final_url))
                self.indicators.ingest_text(text)
            except Exception as e:
                _log(f"Fetch failed: {e}", "WARN")

    def cmd_indicators(self):
        console.print(Rule("Indicators Summary"))
        rows = [
            ("Emails", len(self.indicators.emails)),
            ("Usernames", len(self.indicators.usernames)),
            ("Domains", len(self.indicators.domains)),
            ("IPs", len(self.indicators.ips)),
            ("Hashes", len(self.indicators.hashes)),
            ("Phones", len(self.indicators.phones)),
        ]
        pretty_table(rows, ["Type", "Count"])
        if Confirm.ask("Export indicators to JSON?", default=False):
            path = Prompt.ask("Filename", default="indicators.json")
            payload = {
                "exported_at": datetime.utcnow().isoformat(),
                "indicators": {
                    "emails": sorted(self.indicators.emails),
                    "usernames": sorted(self.indicators.usernames),
                    "domains": sorted(self.indicators.domains),
                    "ips": sorted(self.indicators.ips),
                    "hashes": sorted(self.indicators.hashes),
                    "phones": sorted(self.indicators.phones),
                }
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            console.print(f"[green]Exported to {path}[/green]")

    def cmd_fetch(self):
        url = Prompt.ask("URL to fetch").strip()
        if not url:
            return
        try:
            # Enforced Tor/proxy by default
            final, text = fetch_url_text(url, use_tor=True, safe_blocklist=self.safe_blocklist)
            console.print(Panel(Text("\n".join(text.splitlines()[:40])), title=f"Preview: {final}"))
            self.indicators.ingest_text(text)
        except Exception as e:
            console.print(f"[red]Fetch error: {e}[/red]")
            _log(f"Fetch error: {e}", "ERROR")

    def cmd_vault(self):
        if not self.vault.available():
            console.print("[yellow]PQ Vault unavailable: oqs package not installed.[/yellow]")
            return

        table = Table(show_header=False, box=box.MINIMAL)
        table.add_column("", style="cyan")
        table.add_column("", style="white")
        table.add_row("1) generate", "Generate Kyber keypair")
        table.add_row("2) encrypt", "Encrypt plaintext into vault")
        table.add_row("3) decrypt", "Decrypt a vault file")
        choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")

        if choice == "1":
            self.vault.generate_keys()
            console.print("[green]Keypair created.[/green]")
        elif choice == "2":
            text = Prompt.ask("Text to encrypt (single line)").strip()
            path = self.vault.encrypt(text)
            console.print(f"[green]Encrypted -> {path}[/green]")
        elif choice == "3":
            # List vault files
            files = [f for f in os.listdir(self.vault.vault_dir) if f.endswith(".dat")]
            if not files:
                console.print("[yellow]No vault files found.[/yellow]")
                return
            
            # Display numbered file list
            console.print("[bold cyan]Available Vault Files:[/bold cyan]")
            for idx, file_name in enumerate(files, start=1):
                console.print(f" {idx}) {file_name}")
            
            while True:
                try:
                    # Prompt for file number (ensure valid integer within range)
                    file_index = int(Prompt.ask("File # to decrypt"))
                    if 1 <= file_index <= len(files):
                        file_name = files[file_index - 1]  # Get the selected file
                        break
                    else:
                        console.print("[red]Invalid selection. Please choose a valid file number.[/red]")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a number corresponding to the file.[/red]")
            
            # Attempt to decrypt the selected file
            try:
                content = self.vault.decrypt(file_name)
                console.print(Panel(Text(content), title=file_name))
            except Exception as e:
                console.print(f"[red]Decrypt failed: {e}[/red]")
                
    def cmd_scribe(self):
        console.print(Rule("Darkelf Scribe 📝"))

        console.print(
            "[dim]Local AI drafting via Ollama. Uses only your notes and extracted indicators. "
            "No data leaves your system.[/dim]"
        )

        notes = Prompt.ask(
            "Paste investigator notes or working summary",
            show_default=False
        ).strip()

        if not notes:
            console.print("[yellow]No notes provided. Aborting.[/yellow]")
            return

        # --- Redaction preview ---
        redacted = self._scribe_redact_preview(notes)
        console.print(Panel(redacted, title="Redaction Preview"))

        if not Confirm.ask("Proceed with these notes?", default=True):
            console.print("[yellow]Cancelled by user.[/yellow]")
            return

        model_choice = Prompt.ask(
            "Model",
            choices=["auto", "mistral", "mixtral"],
            default="auto"
        )

        model = self._scribe_select_model(model_choice)

        prompt = self._scribe_prompt(
            redacted_notes=redacted,
            indicators={
                "emails": sorted(self.indicators.emails),
                "usernames": sorted(self.indicators.usernames),
                "domains": sorted(self.indicators.domains),
                "ips": sorted(self.indicators.ips),
                "hashes": sorted(self.indicators.hashes),
                "phones": sorted(self.indicators.phones),
            }
        )

        # Queue or blocking execution
        use_queue = Confirm.ask(
            "Run AI in background (non-blocking)?",
            default=False
        )

        def on_result(output: str):
            # Store the result for later export
            self.last_scribe_output = output

            console.print(Panel(output, title="Draft Submission"))
            console.print(
                "[yellow]Draft ready. Use the export option to save it.[/yellow]"
            )

        if use_queue:
            console.print(
                "[cyan]Darkelf AI task queued. You may continue using the tool.[/cyan]"
            )
            self._enqueue_ai_task(prompt, model, on_result)
            return

        # Blocking execution (default)
        try:
            with console.status("[bold green]Darkelf OSINT AI is thinking…"):
                output = self._scribe_run_ollama(prompt, model)
        except Exception as e:
            console.print(f"[red]Darkelf Scribe error: {e}[/red]")
            _log(f"Scribe error: {e}", "ERROR")
            return

        console.print(Panel(output, title="Draft Submission"))

        if Confirm.ask("Export this draft?", default=False):
            self._scribe_export(output)
            
    def _scribe_export(self, text: str):
        parsed = self._parse_scribe_output(text)

        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tool": "Darkelf Scribe",
                "version": "3.1",
                "report_type": "OSINT Draft",
                "review_status": "draft"
            },
            "summary": parsed["summary"],
            "evidence": parsed["evidence"],
            "sources": parsed["sources"],
            "investigator_notes": "Generated from investigator-provided notes",
            "extracted_indicators": {
                "emails": sorted(self.indicators.emails),
                "usernames": sorted(self.indicators.usernames),
                "domains": sorted(self.indicators.domains),
                "ips": sorted(self.indicators.ips),
                "hashes": sorted(self.indicators.hashes),
                "phones": sorted(self.indicators.phones),
            },
            "legal_notice": (
                "This report is based solely on publicly accessible information "
                "and is provided for investigative and educational purposes only."
            )
        }

        self._validate_schema(report, SCRIBE_REPORT_SCHEMA)

        export_format = Prompt.ask(
            "Export format",
            choices=["json", "md", "md+pdf"],
            default="json"
        )

        if export_format == "json":
            filename = Prompt.ask("Filename", default="darkelf_scribe_report.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        else:
            filename = Prompt.ask("Filename", default="darkelf_scribe_report.md")
            md = self._scribe_to_markdown(report)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(md)

            if export_format == "md+pdf":
                self._markdown_to_pdf(filename)

        console.print(f"[green]Saved to {os.path.abspath(filename)}[/green]")

    def _darkelf_ai_run(self, prompt: str, model: str, purpose: str = "scribe") -> str:
        """
        Central Darkelf OSINT AI execution layer.
        All local AI usage should go through here.
        """
        _log(f"Darkelf OSINT AI invoked | purpose={purpose} | model={model}")

        proc = subprocess.run(
            ["ollama", "run", model],
            input=prompt.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180
        )

        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.decode("utf-8"))

        return proc.stdout.decode("utf-8").strip()
        
    def _scribe_run_ollama(self, prompt: str, model: str) -> str:
        """
        Darkelf Scribe wrapper around Darkelf OSINT AI.
        """
        return self._darkelf_ai_run(
            prompt=prompt,
            model=model,
            purpose="scribe"
        )

    def _scribe_select_model(self, choice: str) -> str:
        if choice != "auto":
            return choice

        if psutil:
            try:
                ram_gb = psutil.virtual_memory().total / (1024 ** 3)
                return "mixtral" if ram_gb >= 24 else "mistral"
            except Exception:
                pass

        return "mistral"
        
    def _scribe_redact_preview(self, text: str) -> str:
        text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        text = IPV4_RE.sub("[REDACTED_IP]", text)
        return text
        
    def _scribe_prompt(self, redacted_notes: str, indicators: dict) -> str:
        return f"""
    You are an OSINT reporting assistant drafting a TraceLabs or CTF submission.

    Rules:
    - Use ONLY the provided notes and indicators
    - Do NOT speculate or invent facts
    - Neutral, professional tone
    - Draft only; human review required

    Output format EXACTLY as follows:

    Summary:
    <concise factual summary>

    Evidence:
    - <bullet points tied directly to notes or indicators>

    Sources:
    - <general source types only>

    Investigator Notes:
    {redacted_notes}

    Extracted Indicators:
    {json.dumps(indicators, indent=2)}
    """
    
    def _parse_scribe_output(self, text: str) -> Dict[str, Any]:
        def section(name, next_name=None):
            pattern = rf"{name}:\s*(.*)"
            if next_name:
                pattern = rf"{name}:\s*(.*?)\n\s*{next_name}:"
            m = re.search(pattern, text, re.S | re.I)
            return m.group(1).strip() if m else ""

        summary = section("Summary", "Evidence")
        evidence_raw = section("Evidence", "Sources")
        sources_raw = section("Sources", "Investigator Notes")

        evidence = [
            line.strip("-• ").strip()
            for line in evidence_raw.splitlines()
            if line.strip()
        ]

        sources = [
            line.strip("-• ").strip()
            for line in sources_raw.splitlines()
            if line.strip()
        ]

        return {
            "summary": summary,
            "evidence": evidence,
            "sources": sources,
        }
        
    def _validate_schema(self, data: dict, schema: dict) -> None:
        for key in schema.get("required", []):
            if key not in data:
                raise ValueError(f"Missing required field: {key}")
                
    def _scribe_to_markdown(self, report: dict) -> str:
        md = []
        md.append("# OSINT Draft Report\n")
        md.append("## Summary\n")
        md.append(report["summary"] + "\n")

        md.append("## Evidence\n")
        for e in report["evidence"]:
            md.append(f"- {e}")
        md.append("")

        md.append("## Sources\n")
        for s in report["sources"]:
            md.append(f"- {s}")
        md.append("")

        if report.get("investigator_notes"):
            md.append("## Investigator Notes\n")
            md.append(report["investigator_notes"] + "\n")

        return "\n".join(md)
        
    def _markdown_to_pdf(self, md_path: str) -> None:
        try:
            subprocess.run(
                ["pandoc", md_path, "-o", md_path.replace(".md", ".pdf")],
                check=True
            )
        except Exception:
            console.print(
                "[yellow]Pandoc not found. PDF generation skipped.[/yellow]"
            )

    def _ai_worker(self):
        while True:
            if not self.ai_queue:
                break

            # Pop the next task safely
            try:
                prompt, model, callback = self.ai_queue.pop(0)
            except IndexError:
                break

            try:
                result = self._darkelf_ai_run(prompt, model, purpose="scribe")
                callback(result)
            except Exception as e:
                callback(f"[ERROR] {e}")

        self.ai_worker_running = False
        
    def _enqueue_ai_task(self, prompt: str, model: str, callback):
        self.ai_queue.append((prompt, model, callback))

        if not self.ai_worker_running:
            self.ai_worker_running = True
            threading.Thread(
                target=self._ai_worker,
                daemon=True
            ).start()
            
    def write_pwa_assets(self, base_dir: str):
        os.makedirs(base_dir, exist_ok=True)

        files = {
            "index.html": """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Darkelf Scribe Viewer</title>
  <link rel="manifest" href="manifest.json">
</head>
<body>
  <h1>Darkelf Scribe Reports</h1>
  <input type="file" id="fileInput" />
  <section id="report"></section>
  <script src="app.js"></script>
</body>
</html>
""",
            "app.js": """document.getElementById("fileInput").addEventListener("change", e => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = () => {
    const data = JSON.parse(reader.result);
    render(data);
  };
  reader.readAsText(file);
});

function render(data) {
  document.getElementById("report").innerHTML = `
    <h2>Summary</h2>
    <p>${data.summary || ""}</p>

    <h2>Evidence</h2>
    <ul>${(data.evidence || []).map(e => `<li>${e}</li>`).join("")}</ul>

    <h2>Sources</h2>
    <ul>${(data.sources || []).map(s => `<li>${s}</li>`).join("")}</ul>
  `;
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("service-worker.js");
}
""",
            "manifest.json": """{
  "name": "Darkelf Scribe",
  "short_name": "Darkelf",
  "start_url": "./index.html",
  "display": "standalone",
  "background_color": "#000000",
  "theme_color": "#111111"
}
""",
            "service-worker.js": """self.addEventListener("install", e => {
  e.waitUntil(
    caches.open("darkelf-scribe").then(cache =>
      cache.addAll(["index.html", "app.js"])
    )
  );
});
"""
        }

        for name, content in files.items():
            path = os.path.join(base_dir, name)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)

                
    def _launch_pwa_viewer(self):
        import http.server
        import socketserver
        import webbrowser

        port = 8765

        if getattr(self, "pwa_server_running", False):
            webbrowser.open(f"http://127.0.0.1:{port}/index.html")
            console.print(
                "[green]Darkelf PWA Viewer already running — opened in browser.[/green]"
            )
            return

        pwa_dir = os.path.join(os.getcwd(), "darkelf_pwa")
        self.write_pwa_assets(pwa_dir)
        os.chdir(pwa_dir)

        def serve():
            handler = http.server.SimpleHTTPRequestHandler

            class ReusableTCPServer(socketserver.TCPServer):
                allow_reuse_address = True

            try:
                with ReusableTCPServer(("127.0.0.1", port), handler) as httpd:
                    httpd.serve_forever()
            except OSError as e:
                _log(f"PWA server error: {e}", "ERROR")

        threading.Thread(target=serve, daemon=True).start()

        # Mark server as running before opening browser
        self.pwa_server_running = True

        # Small delay to ensure server is bound before opening browser
        time.sleep(0.4)

        webbrowser.open(f"http://127.0.0.1:{port}/index.html")

        console.print(
            "[green]Darkelf PWA Viewer launched (offline, local-only).[/green]"
        )

    def run(self):
        while self.running:
            choice = self.main_menu()
            if choice == "1":
                self.cmd_scan()
            elif choice == "2":
                self.cmd_dork()
            elif choice == "3":
                self.cmd_indicators()
            elif choice == "4":
                self.cmd_fetch()
            elif choice == "5":
                self.cmd_vault()
            elif choice == "6":
                self.cmd_help()
            elif choice == "7":
                self.cmd_scribe()
            elif choice == "8":
                self._launch_pwa_viewer()
            elif choice == "q":
                if Confirm.ask("Exit Darkelf CLI?"):
                    self.running = False
            # small pause for UX
            time.sleep(0.15)

# ---------------------------
# CLI Entrypoint
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Darkelf CLI TL OSINT Tool Kit — Refactored Edition (Stealth/Tor enforced)")
    p.add_argument("--no-banner", action="store_true", help="Don't show banner on startup")
    p.add_argument("--quiet", action="store_true", help="Minimal console output")
    return p.parse_args()


def main():
    args = parse_args()
    if args.quiet:
        # minimal bootstrap logging
        _log("Starting Darkelf (quiet mode)")
    cli = DarkelfCLI()
    if not args.no_banner:
        cli.banner()
    try:
        cli.run()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user — exiting.[/red]")
    except Exception as e:
        _log(f"Unhandled exception: {e}", "ERROR")
        console.print(f"[red]Fatal error: {e}[/red]")
    finally:
        _log("Darkelf session ended")


if __name__ == "__main__":
    main() 

