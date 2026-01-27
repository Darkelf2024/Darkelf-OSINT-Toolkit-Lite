# Darkelf CLI TL OSINT Tool Kit v3.0 – Secure, Privacy-Focused Command-Line Web Browser
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
    def __init__(self, tor_binary="tor", socks_port=9050, control_port=9051):
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
        menu.add_row("q) quit", "Exit")
        console.print(menu)
        choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5", "6", "q"], default="1")
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
                
    def cmd_help(self):
        console.print(Rule("Help"))
        console.print("This is a refactored, safer Darkelf CLI. Use responsibly.")
        console.print("Stealth/Tor are enforced by default in this edition. Ensure Tor is running on localhost:9052.")
        console.print("Commands are intentionally conservative; for interactive advanced features see the developer docs.")

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
