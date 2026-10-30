# nmap-triage

An offline command-line tool that turns an Nmap XML scan into a prioritised Markdown report.

> Nmap tells you what is exposed. This tool tells you what to look at first, and why.

## Security problem being solved

Raw Nmap output is a flat list of ports. It does not say which ports matter most, why they are risky, or which entries are noise (filtered ports, `tcpwrapped` services, services with no version). On a single host you can read it by eye. Across many hosts or repeated scans, nobody ranks it by hand.

`nmap-triage` reads the XML (`-oX`), removes noise, ranks exposure by severity, flags *potential* known vulnerabilities by version, and writes a report that can be handed to someone else.

## Intended users

- Penetration testers and students who run Nmap against their own lab or authorised targets and need a quick ranked summary.
- Junior security analysts triaging scan results.
- Anyone who wants a small, readable example of rule-based scan triage.

## Main features

- Parses Nmap XML: hosts, ports, state, service, product, version, SSL tunnel, CPE.
- **False-positive handling**
  - `closed` / `filtered` / `open|filtered` ports are listed as *ignored*, never as findings.
  - `tcpwrapped` ports are marked *unverified* (service unknown), not flagged.
  - Services with no version get exposure rules but **no** CVE lookup, and are listed for manual check.
  - HTTPS (`http` + `tunnel="ssl"`) is not reported as plain HTTP.
  - Non-numeric versions (`3.X - 4.X`, `4.7p1`) are never guessed or compared.
  - Versions outside a CVE's affected range get no match (for example ProFTPD 1.3.1 and CVE-2010-4221, which affects 1.3.2 and later).
- **13 exposure rules** in `rules.json` (Telnet, FTP, SMB, RDP, VNC, databases, r-services, bind shell, NFS/RPC, X11, Java RMI, TFTP/SNMP, plain HTTP). Matched on service name, not port number. Rules can be edited without touching Python.
- **Local CVE lookup** from `cve_data.json` (product plus exact version or version range). Every match is labelled *potential, version-based, verify manually*.
- Markdown report: summary table, exposure findings, CVE matches, needs-manual-check list, unmatched open services, ignored ports, limitations.
- Exit codes for scripts: `0` OK, `1` finding at or above `--fail-on`, `2` bad input.

## Technology used

- Python 3.10+ (developed and tested on Windows with Python 3.14)
- [`defusedxml`](https://pypi.org/project/defusedxml/) (PSF licence) for safe XML parsing
- `pytest` (MIT) for tests
- Standard library: `argparse`, `json`, `re`, `dataclasses`, `pathlib`
- Nmap itself is only used to create the input file. No Nmap code is included.

## Installation

```
git clone https://github.com/JohnJJoseph/nmap-triage.git
cd nmap-triage
python -m venv venv
venv\Scripts\activate.bat        # Windows (cmd)
# source venv/bin/activate       # Linux / macOS
pip install -r requirements.txt
```

No API key and no internet connection are needed to run the tool.

## Usage

Create a scan **of a system you own or are authorised to scan**. `-sV` is required, because the tool needs service and version data:

```
nmap -sV -oX scan.xml <target>
```

Run the tool from the repository folder:

```
python nmap_triage.py scan.xml -o report.md
```

Options:

| Option | Meaning |
|---|---|
| `-o, --output` | Report file (default `report.md`) |
| `--rules` | Exposure rules JSON (default `rules.json`) |
| `--cves` | Local CVE data JSON (default `cve_data.json`) |
| `--fail-on` | `critical`, `high` (default), `medium`, `low` or `never`. Exit code `1` if a finding at or above this level exists |

Run the tests (20 tests):

```
pytest
```

## Sample command

```
python nmap_triage.py samples\mini.xml -o samples\expected_report.md
```

On Linux or macOS, use `samples/mini.xml` and `samples/expected_report.md`.

## Sample input and output

**Input** (`samples/mini.xml`, excerpt):

```xml
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.2.8"/></port>
<port protocol="tcp" portid="8080"><state state="filtered"/><service name="http-proxy"/></port>
```

**Terminal output:**

```
Report written to samples\expected_report.md
  CRITICAL exposure: 0  potential CVE: 1
  HIGH     exposure: 1  potential CVE: 0
  LOW      exposure: 1  potential CVE: 0
Result: findings at or above 'high' found (exit code 1)
```

**Report** (excerpt of `samples/expected_report.md`):

| Severity | Port | Issue |
|---|---|---|
| High | 23/tcp | Telnet exposed |
| Low | 80/tcp | Plain HTTP (no TLS) |

Port 8080 is filtered, so it appears under *Ignored ports* and produces no finding. Apache 2.2.8 produces a *potential* CVE match (CVE-2017-7679). Telnet has no version, so it gets no CVE and is listed under *Needs manual check*.

### Real scan

`samples/metasploitable.xml` is a scan of a Metasploitable 2 VM on an isolated lab network (23 open ports). The result is in `samples/metasploitable_report.md`: 1 critical exposure (bind shell on 1524), 9 high, 6 medium, 1 low, and 2 potential CVE matches (vsftpd 2.3.4 and Apache 2.2.8).

ProFTPD 1.3.1 on port 2121 is **not** matched to CVE-2010-4221, because that CVE affects versions 1.3.2 and later. A test covers this.

### Sample files

| File | Shows |
|---|---|
| `mini.xml` | Basic successful case |
| `filtered.xml` | All ports filtered, so zero findings |
| `tcpwrapped.xml` | `tcpwrapped` marked unverified, not flagged |
| `https.xml` | HTTPS not reported as plain HTTP |
| `broken.xml` | Malformed XML gives a clean error and exit code 2 |
| `metasploitable.xml` | Real lab scan |
| `expected_report.md` | Expected output for `mini.xml` |
| `metasploitable_report.md` | Output for the real lab scan |

## Security considerations

- **XML parsing:** `defusedxml` is used instead of `xml.etree` so that malicious XML (entity expansion, "billion laughs") is rejected rather than parsed.
- **No network activity:** the tool never scans, connects to or downloads anything. It only reads local files.
- **Authorisation:** the samples come from a deliberately vulnerable VM on an isolated network. Only scan systems you own or have written permission to test.
- **Reports are sensitive:** they contain IP addresses, hostnames and a list of weaknesses. Handle real reports accordingly.
- **Input validation:** missing, empty, malformed or non-Nmap files, and malformed rule or CVE files, produce a clear error and exit code 2, not a crash.
- **No secrets** are stored in this repository.

## Known limitations

- **CVE matches are version-based and only "potential".** Linux distributions often backport fixes without changing the version string, so a match is not proof the host is vulnerable. For example, CVE-2011-2523 (the vsftpd 2.3.4 backdoor) only affects one download window of the source code, and Ubuntu lists its hardy release as not affected. The lab VM is deliberately backdoored, but a version match alone would not show that on a normal system.
- **Versions that are not plain numbers are skipped**, for example `OpenSSH 4.7p1`, `Samba 3.X - 4.X`, `PostgreSQL 8.3.0 - 8.3.7`, `MySQL 5.0.51a-...`. In the Metasploitable scan this means real vulnerabilities in those services are **not** matched. "No match" does not mean safe.
- Letter suffixes are not handled, so a range ending at ProFTPD `1.3.3` can miss `1.3.3a` to `1.3.3b`.
- **The CVE data is tiny and hand-curated** (3 entries) and goes stale. It is not a replacement for a scanner such as Nessus or OpenVAS.
- **Scores come from different CVSS versions.** Most entries use CVSS v3, but CVE-2010-4221 is scored with CVSS v2 (10.0), because that is what NVD publishes for it.
- Services with no version (for example UnrealIRCd on port 6667) cannot be matched, so a known backdoor would need a manual check.
- If the scan was run without `-sV`, Nmap guesses service names from port numbers and the results are unreliable.
- Severity levels in `rules.json` are judgment calls, not an official standard.
- Tested on TCP scans of a single host. UDP and multi-host scans are not covered by the samples.

## Future improvements

- Compare version strings with suffixes (`4.7p1`) and ranges (`8.3.0 - 8.3.7`).
- Larger CVE dataset built from NVD, plus an optional CISA KEV flag for "known exploited".
- Handle multi-host and UDP scans, and diff two scans over time.
- CVSS vector parsing and ATT&CK/CWE tags.
- JSON and HTML output.

## AI usage

See [AI_USAGE.md](AI_USAGE.md).

## Credits and licence

- Input format produced by [Nmap](https://nmap.org/). Metasploitable 2 (Rapid7) was used only as an isolated lab target.
- `defusedxml` and `pytest` are used under their own licences.
- Released under the MIT licence (see `LICENSE`).
- CVE descriptions in `cve_data.json` are short summaries. Authoritative data is on [nvd.nist.gov](https://nvd.nist.gov/).