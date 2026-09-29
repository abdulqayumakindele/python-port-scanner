"""
Tests for the port scanner. Run from the project root with:

    python3 -m unittest discover -s tests -v

Only the standard library is needed. Scanning tests use 127.0.0.1 only.
"""

import contextlib
import io
import os
import socket
import subprocess
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tool")
sys.path.insert(0, TOOL)

import port_scanner as ps  # noqa: E402


def run_cli(*argv):
    """Run main() and capture (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = ps.main(list(argv))
        except SystemExit as exit_:      # argparse errors exit with code 2
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class LocalServer:
    """A throwaway TCP server on 127.0.0.1 that can send a banner."""

    def __init__(self, banner=b""):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if self.banner:
                    conn.sendall(self.banner)

    def close(self):
        self.sock.close()


def free_port():
    """A port on localhost that is (almost certainly) closed."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ParsePortsTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(ps.parse_ports("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(ps.parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(ps.parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_combination_is_sorted_and_deduplicated(self):
        self.assertEqual(ps.parse_ports("443, 22,20-22,22"), [20, 21, 22, 443])

    def test_boundaries(self):
        self.assertEqual(ps.parse_ports("1,65535"), [1, 65535])

    def test_invalid_inputs_raise_friendly_errors(self):
        bad = ["", "  ", "abc", "80,abc", "0", "65536", "-5", "1000-100",
               "1-", "-", "1-2-3", "80,,443", "80,", "1.5", "²"]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(ps.InputError):
                    ps.parse_ports(text)

    def test_reversed_range_message_suggests_fix(self):
        with self.assertRaises(ps.InputError) as ctx:
            ps.parse_ports("1000-100")
        self.assertIn("100-1000", str(ctx.exception))


class ArgumentValidationTests(unittest.TestCase):
    def assert_rejected(self, *argv, fragment):
        code, out, err = run_cli(*argv)
        self.assertEqual(code, 2)
        self.assertIn(fragment, err)
        self.assertNotIn("Traceback", err)

    def test_bad_ports(self):
        self.assert_rejected("127.0.0.1", "-p", "1000-100", fragment="backwards")
        self.assert_rejected("127.0.0.1", "-p", "70000", fragment="out of range")

    def test_bad_threads(self):
        for value in ("0", "-3", "abc", "100000"):
            with self.subTest(value=value):
                self.assert_rejected("127.0.0.1", "-t", value, fragment="hreads")

    def test_bad_timeout(self):
        for value in ("0", "-1", "abc", "nan", "inf"):
            with self.subTest(value=value):
                self.assert_rejected("127.0.0.1", "--timeout", value, fragment="imeout")

    def test_missing_target(self):
        code, _, err = run_cli()
        self.assertEqual(code, 2)
        self.assertIn("target", err)


class ServiceNameTests(unittest.TestCase):
    def test_known_ports_use_beginner_notes(self):
        self.assertIn("SSH", ps.service_name(22))
        self.assertIn("HTTPS", ps.service_name(443))

    def test_unknown_port(self):
        self.assertIsInstance(ps.service_name(54321), str)
        self.assertTrue(ps.service_name(54321))


class ScanTests(unittest.TestCase):
    def test_detects_open_port(self):
        server = LocalServer()
        self.addCleanup(server.close)
        self.assertIsNotNone(ps.scan_port("127.0.0.1", server.port, 1, False))

    def test_closed_port_returns_none(self):
        self.assertIsNone(ps.scan_port("127.0.0.1", free_port(), 0.5, False))

    def test_banner_is_read_when_service_sends_one(self):
        server = LocalServer(banner=b"220 hello from test\r\n")
        self.addCleanup(server.close)
        port, banner = ps.scan_port("127.0.0.1", server.port, 1, True)
        self.assertEqual(banner, "220 hello from test")

    def test_silent_service_gives_empty_banner_without_error(self):
        server = LocalServer()          # accepts but sends nothing
        self.addCleanup(server.close)
        port, banner = ps.scan_port("127.0.0.1", server.port, 1, True)
        self.assertEqual(banner, "")

    def test_banner_strips_control_characters(self):
        server = LocalServer(banner=b"hi\x00\x07there\n")
        self.addCleanup(server.close)
        _, banner = ps.scan_port("127.0.0.1", server.port, 1, True)
        self.assertEqual(banner, "hithere")

    def test_run_scan_finds_only_open_ports(self):
        server = LocalServer()
        self.addCleanup(server.close)
        closed = free_port()
        result = ps.run_scan("127.0.0.1", sorted({server.port, closed}), 10, 0.5, False)
        self.assertEqual([p for p, _ in result], [server.port])


class CliTests(unittest.TestCase):
    def test_full_scan_output_contains_summary(self):
        server = LocalServer(banner=b"220 demo\r\n")
        self.addCleanup(server.close)
        code, out, _ = run_cli("127.0.0.1", "-p", str(server.port), "-b")
        self.assertEqual(code, 0)
        for text in ("Target", "Ports scanned", "Open ports", "Duration",
                     str(server.port), "220 demo"):
            self.assertIn(text, out)

    def test_no_open_ports_is_not_an_error(self):
        code, out, _ = run_cli("127.0.0.1", "-p", str(free_port()))
        self.assertEqual(code, 0)
        self.assertIn("No open ports found", out)

    def test_unresolvable_host_gives_clean_error(self):
        code, out, err = run_cli("no-such-host.invalid", "-p", "80")
        self.assertEqual(code, 1)
        self.assertIn("Could not resolve", err)
        self.assertNotIn("Traceback", err)

    def test_host_with_spaces_rejected(self):
        code, _, err = run_cli("bad host", "-p", "80")
        self.assertEqual(code, 1)
        self.assertIn("no spaces", err)

    def test_script_runs_as_a_program_without_traceback(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOL, "port_scanner.py"), "127.0.0.1", "-p", "9-1"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
