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

    def test_added_alternate_web_and_nmap_test_ports(self):
        self.assertIn("HTTP-alt", ps.service_name(8000))
        self.assertIn("HTTP-alt", ps.service_name(8080))
        self.assertIn("HTTPS-alt", ps.service_name(8443))
        self.assertIn("Nping", ps.service_name(9929))

    def test_unknown_port(self):
        self.assertIsInstance(ps.service_name(54321), str)
        self.assertTrue(ps.service_name(54321))


class FormatBannerTests(unittest.TestCase):
    def test_empty_bytes(self):
        self.assertEqual(ps.format_banner(b""), "(none)")

    def test_plain_text_banner_is_clean(self):
        self.assertEqual(ps.format_banner(b"220 hello\r\n"), "220 hello")
        self.assertEqual(ps.format_banner(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6")

    def test_line_breaks_and_tabs_become_spaces(self):
        self.assertEqual(ps.format_banner(b"line one\r\nline two\n"), "line one line two")
        self.assertEqual(ps.format_banner(b"a\tb"), "a b")

    def test_unprintable_bytes_give_binary_summary(self):
        result = ps.format_banner(bytes([0, 255, 254]))
        self.assertTrue(result.startswith("(binary data"))
        self.assertIn("3 bytes", result)
        self.assertIn("00fffe", result)

    def test_long_binary_shows_only_a_short_preview(self):
        result = ps.format_banner(bytes(range(20)))
        self.assertIn("20 bytes", result)
        self.assertIn("...", result)
        self.assertLess(len(result), 60)

    def test_85_percent_boundary(self):
        mostly_text = b"a" * 17 + b"\x00\x01\x02"       # 17/20 = 85% printable -> still text
        self.assertEqual(ps.format_banner(mostly_text), "a" * 17)
        mostly_binary = b"a" * 16 + b"\x00\x01\x02\x03"  # 16/20 = 80% printable -> binary
        self.assertTrue(ps.format_banner(mostly_binary).startswith("(binary data"))

    def test_check_uses_raw_bytes_not_decoded_text(self):
        # Invalid UTF-8 bytes would vanish when decoded, hiding that this is binary.
        self.assertTrue(ps.format_banner(b"\xff\xfe\xfd\xfc\xfb\xfa").startswith("(binary data"))

    def test_result_is_always_one_line(self):
        for raw in (b"a\nb\r\nc", bytes(range(30)), b"\n\n\n", b"x" * 500):
            with self.subTest(raw=raw[:10]):
                self.assertNotIn("\n", ps.format_banner(raw))
                self.assertNotIn("\r", ps.format_banner(raw))


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
        self.assertEqual(banner, "(none)")

    def test_banner_strips_stray_control_characters_in_mostly_text(self):
        server = LocalServer(banner=b"hello\x00world service ready\n")
        self.addCleanup(server.close)
        _, banner = ps.scan_port("127.0.0.1", server.port, 1, True)
        self.assertEqual(banner, "helloworld service ready")

    def test_binary_banner_gives_summary_not_garbage(self):
        server = LocalServer(banner=bytes([0, 255, 254, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
        self.addCleanup(server.close)
        _, banner = ps.scan_port("127.0.0.1", server.port, 1, True)
        self.assertTrue(banner.startswith("(binary data, 12 bytes"))

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

    def test_cli_does_not_print_garbage_for_binary_banner(self):
        server = LocalServer(banner=bytes([0, 255, 254, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
        self.addCleanup(server.close)
        code, out, _ = run_cli("127.0.0.1", "-p", str(server.port), "-b")
        self.assertEqual(code, 0)
        self.assertIn("(binary data, 12 bytes", out)
        self.assertTrue(all(ch.isprintable() or ch == "\n" for ch in out))

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
