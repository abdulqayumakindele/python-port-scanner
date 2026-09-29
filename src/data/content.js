// ─────────────────────────────────────────────
// SITE — edit here, pages update automatically
// ─────────────────────────────────────────────
export const site = {
  name: 'Simple Python Port Scanner for Beginners',
  brand: 'PYTHON PORT SCANNER',
  tagline: 'A lightweight TCP port scanner built with Python — documented for beginners.',
  description: 'A beginner-friendly, multithreaded Python port scanner with service identification, banner grabbing, and an ethical-use notice. By Abdul Qayum Akindele.',
  url: 'https://python-port-scanner.netlify.app',
  repo: 'https://github.com/abdulqayumakindele/python-port-scanner',
  links: [
    ['GitHub Repo', 'https://github.com/abdulqayumakindele/python-port-scanner'],
    ['Portfolio',   'https://abdulqayum.netlify.app'],
    ['LinkedIn',    'https://www.linkedin.com/in/abdul-qayum-akindele-bb33573a3'],
  ],
};

export const stack = ['Python 3', 'socket', 'argparse', 'ThreadPoolExecutor'];

export const features = [
  { title: 'Multithreaded', description: 'Scans many ports in parallel with a configurable thread count.' },
  { title: 'Explains each port', description: 'Names the service usually found on each open port, e.g. 22 = SSH, 443 = HTTPS.' },
  { title: 'Optional banner reading', description: 'Reads the short greeting some services send. Many send nothing.' },
  { title: 'Beginner documentation', description: 'Clean code, clear error messages, tests, and an ethical-use notice.' },
];

export const howItWorks = [
  'You give the scanner a target (an IPv4 address or hostname) and a port, a list of ports, or a range.',
  'For each port it tries to open a TCP connection. This is called a "connect scan".',
  'If the connection succeeds, the port is open. If it is refused or times out, the port is closed or filtered by a firewall — the scanner cannot tell which.',
  'Open ports are matched to a service name and printed in a table, followed by a scan summary with the duration.',
];

export const options = [
  ['-p, --ports',   'Port, list, range or a mix: 80 · 22,80,443 · 1-1024 · 22,80,100-200. Valid ports are 1–65535.', '1-1024'],
  ['-t, --threads', 'Parallel threads, from 1 to 1000',                                                            '100'],
  ['--timeout',     'Seconds to wait per port; must be greater than 0',                                            '0.5'],
  ['-b, --banner',  'Try to read a banner from open ports (many services send none)',                             'off'],
];

export const examples = [
  'python3 port_scanner.py 127.0.0.1',
  'python3 port_scanner.py scanme.nmap.org -p 20-100 -b',
  'python3 port_scanner.py 192.168.1.1 -p 22,80,443 -t 50 --timeout 1',
];

export const commonPorts = [
  [21, 'FTP', 'File transfer'], [22, 'SSH', 'Secure remote login'], [23, 'Telnet', 'Insecure remote login'],
  [25, 'SMTP', 'Sending email'], [53, 'DNS', 'Domain name lookups'], [80, 'HTTP', 'Web traffic'],
  [443, 'HTTPS', 'Encrypted web traffic'], [445, 'SMB', 'Windows file sharing'], [3389, 'RDP', 'Windows remote desktop'],
];

export const ethics = [
  'Only scan systems you own or have explicit, written authorization to test.',
  'Permission to use a network or a website is not permission to scan it. If you are unsure, do not scan.',
  'Safe practice targets: your own machine (127.0.0.1), a device on your own home network, or scanme.nmap.org, which is provided for testing (keep scans small and gentle).',
  'Unauthorized scanning may be illegal in your country, can breach a provider\'s terms of service, and can trigger security alerts.',
  'This tool performs a plain TCP connect scan and passive banner reading only. It does not exploit anything, evade defences, or test for vulnerabilities.',
  'You are responsible for how you use it. The author accepts no responsibility for misuse.',
];

export const limitations = [
  'TCP connect scan only — no UDP, no stealth or half-open scans',
  'IPv4 only (IPv6 addresses are not supported)',
  'Firewalls can hide open ports, and a "closed or filtered" result cannot tell the two apart',
  'Service names come from the port number, not from inspecting the service — a service on an unusual port may be labelled wrongly or as unknown',
  'Not a vulnerability scanner and not a replacement for professional tools such as Nmap',
  'Speed depends on your network, the timeout, and the thread count',
];

// ─────────────────────────────────────────────
// INSTALL, EXAMPLE OUTPUT, BANNER NOTES
// ─────────────────────────────────────────────
export const install = [
  'Install Python 3.8 or newer (check with: python3 --version).',
  'Download or clone the repository: git clone ' + site.repo + '.git',
  'That is all — the scanner uses only Python\'s standard library, so there is nothing else to install.',
  'Run it: python3 tool/port_scanner.py 127.0.0.1',
];

export const exampleOutput = `=======================================================
 Target : 127.0.0.1
 Ports  : 3 | Threads: 100 | Timeout: 0.5s
 Started: 2026-09-28 23:20:16
 Reminder: scan only what you own or have permission to test.
=======================================================
PORT    SERVICE                               BANNER
2525    unknown service                       220 demo service ready
8765    unknown service                       (none)

Note: many services send no banner, so '(none)' is normal.

-------------------------------------------------------
 Scan summary
  Target        : 127.0.0.1
  Ports scanned : 3
  Open ports    : 2 (2525, 8765)
  Not open      : 1 (closed or filtered)
  Duration      : 1.00 s
-------------------------------------------------------`;
export const exampleNote = 'Sample output from a scan of two local test servers on 127.0.0.1 (one sends a banner, one stays silent). Your results will differ.';

// Screenshot: save your own screenshot as public/images/example-scan.png,
// then set screenshot to '/images/example-scan.png'. While it is '' the site
// shows a clearly marked placeholder instead.
export const screenshot = '';
export const screenshotTodo = 'Run: python3 tool/port_scanner.py 127.0.0.1 -p 1-1024 -b in a terminal, then screenshot the whole result (target header, results table and scan summary). Scan only your own machine.';

export const bannerNotes = [
  'Banner reading is passive: after a port opens, the scanner waits up to one second and reads whatever the service sends first. It never sends anything itself.',
  'Many services stay silent until a client speaks first — web servers (HTTP/HTTPS) are the common example — so an empty banner ("(none)") is normal and does not mean the port is closed.',
  'Banners are shortened, cleaned of control characters, and can be missing, generic, or misleading. Treat them as a hint, not proof of what is running.',
  'Banner reading only adds waiting time on ports that are already open, so it does not noticeably slow scans of mostly closed ports.',
];
