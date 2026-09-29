#!/usr/bin/env python3
"""
Simple Python Port Scanner for Beginners
----------------------------------------
A lightweight TCP connect scanner that checks which ports are open on a
target, names the common service on each port, and (optionally) reads a
short banner if the service volunteers one.

ETHICAL USE ONLY: scan only systems you own or have explicit, written
permission to test. Safe practice targets: your own machine (127.0.0.1)
or scanme.nmap.org (please keep it gentle).
"""

import argparse
import math
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

MAX_THREADS = 1000      # sanity limit so a typo cannot exhaust your system
BANNER_WAIT = 1.0       # seconds to wait for a banner on an already-open port
BANNER_MAX_CHARS = 80

COMMON_PORTS = {
    21: "FTP - file transfer",
    22: "SSH - secure remote login",
    23: "Telnet - insecure remote login",
    25: "SMTP - sending email",
    53: "DNS - domain name lookups",
    80: "HTTP - web traffic",
    110: "POP3 - receiving email",
    143: "IMAP - receiving email",
    443: "HTTPS - encrypted web traffic",
    445: "SMB - Windows file sharing",
    3306: "MySQL - database",
    3389: "RDP - Windows remote desktop",
    8080: "HTTP-alt - alternate web server",
}


class InputError(ValueError):
    """Raised for bad user input. The message is written for beginners."""


# ── Input parsing / validation ────────────────────────────────────────────

def _to_port(token, context):
    """Convert one piece of text to a valid port number, or explain why not."""
    token = token.strip()
    if not (token.isascii() and token.isdigit()):
        raise InputError(
            f"'{token}' is not a valid port number (in '{context}'). "
            "Ports are whole numbers from 1 to 65535."
        )
    number = int(token)
    if not 1 <= number <= 65535:
        raise InputError(
            f"Port {number} is out of range. Ports must be between 1 and 65535."
        )
    return number


def parse_ports(text):
    """
    Turn text like '80', '22,80,443', '1-1024' or '22,80,100-200'
    into a sorted list of unique port numbers.
    """
    if text is None or not text.strip():
        raise InputError("No ports given. Example: -p 22,80,443 or -p 1-1024")

    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise InputError(
                f"Empty entry in the port list '{text}'. Check for extra commas."
            )
        if part.startswith("-"):
            raise InputError(
                f"'{part}' looks like a negative number. "
                "Ports must be between 1 and 65535."
            )
        if "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2 or not pieces[0].strip() or not pieces[1].strip():
                raise InputError(
                    f"'{part}' is not a valid range. Use START-END, for example 1-1024."
                )
            start = _to_port(pieces[0], part)
            end = _to_port(pieces[1], part)
            if start > end:
                raise InputError(
                    f"The range '{part}' is backwards. Write it as {end}-{start}."
                )
            ports.update(range(start, end + 1))
        else:
            ports.add(_to_port(part, part))
    return sorted(ports)


def resolve_target(target):
    """Return the IPv4 address for a hostname or IP, or explain the problem."""
    target = (target or "").strip()
    if not target or any(ch.isspace() for ch in target):
        raise InputError("Please give one target with no spaces, e.g. 127.0.0.1 or example.com")
    try:
        return socket.gethostbyname(target)
    except (socket.gaierror, UnicodeError):
        raise InputError(
            f"Could not resolve '{target}'. Check the spelling and your internet "
            "connection. Note: this scanner supports IPv4 only."
        ) from None
    except OSError as err:
        raise InputError(f"Could not look up '{target}': {err}") from None


# ── argparse helpers (turn bad values into friendly messages) ─────────────

def port_list(text):
    try:
        return parse_ports(text)
    except InputError as err:
        raise argparse.ArgumentTypeError(str(err)) from None


def thread_count(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{text}' is not a whole number. Example: -t 100"
        ) from None
    if value < 1:
        raise argparse.ArgumentTypeError("Threads must be at least 1.")
    if value > MAX_THREADS:
        raise argparse.ArgumentTypeError(
            f"Threads cannot be more than {MAX_THREADS}. Try a smaller number such as 100."
        )
    return value


def timeout_seconds(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{text}' is not a number. Example: --timeout 0.5"
        ) from None
    if math.isnan(value) or math.isinf(value) or value <= 0:
        raise argparse.ArgumentTypeError(
            "Timeout must be a number greater than 0 (in seconds), e.g. 0.5 or 1."
        )
    return value


# ── Scanning ──────────────────────────────────────────────────────────────

def service_name(port):
    """Explain a port: use our beginner notes, else the system's service table."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, OverflowError):
        return "unknown service"


def grab_banner(sock, wait=BANNER_WAIT):
    """
    Passively read a short greeting from an already-open connection.
    Nothing is sent. Many services (web servers, for example) stay silent
    until they receive a request, so an empty result is normal.
    """
    try:
        sock.settimeout(wait)
        data = sock.recv(128)
    except OSError:          # timeout, reset, etc. -> no banner
        return ""
    lines = data.decode("utf-8", errors="ignore").strip().splitlines()
    if not lines:
        return ""
    clean = "".join(ch for ch in lines[0] if ch.isprintable())
    return clean[:BANNER_MAX_CHARS]


def scan_port(target, port, timeout, banner):
    """Return (port, banner_text) if the port is open, otherwise None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target, port)) == 0:
                return port, (grab_banner(sock) if banner else "")
    except OSError:
        pass                 # treat unexpected socket errors as "not open"
    return None


def run_scan(ip, ports, threads, timeout, banner):
    """Scan all ports in parallel and return a sorted list of (port, banner)."""
    pool = ThreadPoolExecutor(max_workers=max(1, min(threads, len(ports))))
    try:
        results = list(pool.map(lambda p: scan_port(ip, p, timeout, banner), ports))
        pool.shutdown()
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    return sorted(r for r in results if r)


# ── Command-line interface ────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner. Use only on systems you own or "
                    "have explicit permission to test."
    )
    parser.add_argument("target", help="IPv4 address or hostname to scan")
    parser.add_argument("-p", "--ports", type=port_list, default="1-1024",
                        help="ports to scan, e.g. 80, 22,80,443, 1-1024 or 22,80,100-200 "
                             "(default: 1-1024)")
    parser.add_argument("-t", "--threads", type=thread_count, default=100,
                        help=f"number of parallel threads, 1-{MAX_THREADS} (default: 100)")
    parser.add_argument("--timeout", type=timeout_seconds, default=0.5,
                        help="seconds to wait per port, greater than 0 (default: 0.5)")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="try to read a banner from open ports (many services send none)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        ip = resolve_target(args.target)
    except InputError as err:
        print(f"[!] {err}", file=sys.stderr)
        return 1

    ports = args.ports
    shown_target = args.target if args.target == ip else f"{args.target} ({ip})"

    print("=" * 55)
    print(f" Target : {shown_target}")
    print(f" Ports  : {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s")
    print(f" Started: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(" Reminder: scan only what you own or have permission to test.")
    print("=" * 55)

    started = time.perf_counter()
    try:
        open_ports = run_scan(ip, ports, args.threads, args.timeout, args.banner)
    except RuntimeError:
        print("[!] Could not start that many threads. Try a smaller -t value.", file=sys.stderr)
        return 1
    duration = time.perf_counter() - started

    if open_ports:
        if args.banner:
            print(f"{'PORT':<8}{'SERVICE':<38}BANNER")
        else:
            print(f"{'PORT':<8}SERVICE")
        for port, banner in open_ports:
            if args.banner:
                print(f"{port:<8}{service_name(port):<38}{banner or '(none)'}")
            else:
                print(f"{port:<8}{service_name(port)}")
        if args.banner:
            print("\nNote: many services send no banner, so '(none)' is normal.")
    else:
        print("No open ports found.")

    print("\n" + "-" * 55)
    print(" Scan summary")
    print(f"  Target        : {shown_target}")
    print(f"  Ports scanned : {len(ports)}")
    print(f"  Open ports    : {len(open_ports)}"
          + (f" ({', '.join(str(p) for p, _ in open_ports)})" if open_ports else ""))
    print(f"  Not open      : {len(ports) - len(open_ports)} (closed or filtered)")
    print(f"  Duration      : {duration:.2f} s")
    print("-" * 55)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\n[!] Scan cancelled.")
