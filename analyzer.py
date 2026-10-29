"""Classify parsed ports, apply exposure rules, and match known CVEs."""
import json
import re
from dataclasses import dataclass
from pathlib import Path

from parser import Port

OPEN = "open"              # confirmed open service
UNVERIFIED = "unverified"  # open, but the real service is unknown (tcpwrapped)
IGNORED = "ignored"        # not open (closed, filtered, open|filtered ...)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
REQUIRED_RULE_KEYS = {"id", "title", "services", "severity", "reason", "fix"}
REQUIRED_CVE_KEYS = {"cve", "product", "cvss", "summary"}


class RuleError(Exception):
    """Raised when rules.json is missing or malformed."""


class CveDataError(Exception):
    """Raised when cve_data.json is missing or malformed."""


@dataclass
class Assessment:
    host: str
    hostname: str
    port: Port
    status: str          # OPEN, UNVERIFIED or IGNORED
    reason: str          # why it got that status (empty if nothing to say)
    version_known: bool  # True only if Nmap detected a version


@dataclass
class Finding:
    host: str
    hostname: str
    port: Port
    severity: str
    title: str
    reason: str
    fix: str


@dataclass
class CveMatch:
    host: str
    hostname: str
    port: Port
    cve: str
    cvss: float
    severity: str
    summary: str


# ---------- Step 1: false-positive filtering ----------

def assess_port(host, port):
    """Label one port. 'host' is a parser.Host object."""
    if port.state != "open":
        return Assessment(host.address, host.hostname, port, IGNORED,
                          f"state is '{port.state}', not a confirmed open service",
                          False)

    if port.service == "tcpwrapped":
        return Assessment(host.address, host.hostname, port, UNVERIFIED,
                          "tcpwrapped: connection was accepted then closed, "
                          "real service unknown",
                          False)

    version_known = bool(port.version)
    reason = "" if version_known else "no version detected, needs manual check"
    return Assessment(host.address, host.hostname, port, OPEN, reason, version_known)


def assess_hosts(hosts):
    """Return an Assessment for every port on every host that is up."""
    results = []
    for host in hosts:
        if host.state != "up":
            continue
        for port in host.ports:
            results.append(assess_port(host, port))
    return results


# ---------- Step 2: exposure rules ----------

def load_rules(path):
    """Load and validate the exposure rules from a JSON file."""
    try:
        rules = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleError(f"Cannot load rules from {path}: {exc}") from exc
    for rule in rules:
        missing = REQUIRED_RULE_KEYS - rule.keys()
        if missing:
            raise RuleError(f"Rule {rule.get('id', '?')} is missing: {sorted(missing)}")
        if rule["severity"] not in SEVERITY_ORDER:
            raise RuleError(f"Rule {rule['id']} has unknown severity '{rule['severity']}'")
    return rules


def service_key(port):
    """Lowercase the service name. Nmap reports HTTPS as 'http' + tunnel 'ssl'."""
    name = port.service.lower()
    if name == "http" and port.tunnel == "ssl":
        return "https"
    return name


def match_rules(assessments, rules):
    """Apply exposure rules to confirmed open services only."""
    findings = []
    for a in assessments:
        if a.status != OPEN:
            continue
        key = service_key(a.port)
        for rule in rules:
            if key in rule["services"]:
                findings.append(Finding(a.host, a.hostname, a.port, rule["severity"],
                                        rule["title"], rule["reason"], rule["fix"]))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.host, f.port.number))
    return findings


# ---------- Step 3: CVE lookup ----------

def load_cves(path):
    """Load and validate the local CVE list."""
    try:
        entries = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CveDataError(f"Cannot load CVE data from {path}: {exc}") from exc
    for e in entries:
        missing = REQUIRED_CVE_KEYS - e.keys()
        if missing:
            raise CveDataError(f"CVE entry {e.get('cve', '?')} is missing: {sorted(missing)}")
        if "versions" not in e and "ranges" not in e:
            raise CveDataError(f"CVE entry {e['cve']} needs 'versions' or 'ranges'")
    return entries


def parse_version(text):
    """'2.2.8' -> (2, 2, 8). Anything not purely numeric (e.g. '3.X - 4.X') -> None."""
    if re.fullmatch(r"\d+(\.\d+)*", text):
        return tuple(int(p) for p in text.split("."))
    return None


def version_matches(version, entry):
    """True if 'version' is in the entry's exact list or inside one of its ranges."""
    if version in entry.get("versions", []):
        return True
    v = parse_version(version)
    if v is None:
        return False  # cannot compare, so do not guess
    for r in entry.get("ranges", []):
        if parse_version(r.get("from", "0")) <= v < parse_version(r["before"]):
            return True
    return False


def cvss_to_severity(score):
    """Standard CVSS v3 severity bands."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def match_cves(assessments, cves):
    """Potential, version-based matches. Skips ports with no known version."""
    matches = []
    for a in assessments:
        if a.status != OPEN or not a.version_known:
            continue
        product = a.port.product.lower()
        for e in cves:
            if e["product"].lower() in product and version_matches(a.port.version, e):
                matches.append(CveMatch(a.host, a.hostname, a.port, e["cve"], e["cvss"],
                                        cvss_to_severity(e["cvss"]), e["summary"]))
    matches.sort(key=lambda m: (-m.cvss, m.host, m.port.number))
    return matches