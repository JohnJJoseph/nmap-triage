"""Decide which parsed ports are real services and which are noise."""
import json
from dataclasses import dataclass
from pathlib import Path

from parser import Port

OPEN = "open"              # confirmed open service
UNVERIFIED = "unverified"  # open, but the real service is unknown (tcpwrapped)
IGNORED = "ignored"        # not open (closed, filtered, open|filtered ...)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
REQUIRED_RULE_KEYS = {"id", "title", "services", "severity", "reason", "fix"}


class RuleError(Exception):
    """Raised when rules.json is missing or malformed."""


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
    """Nmap reports HTTPS as service 'http' with tunnel 'ssl'. Treat it as https."""
    if port.service == "http" and port.tunnel == "ssl":
        return "https"
    return port.service


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


if __name__ == "__main__":  # quick manual check
    import sys
    from parser import parse_nmap_xml, NmapParseError

    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <scan.xml>")
        sys.exit(1)
    try:
        assessments = assess_hosts(parse_nmap_xml(sys.argv[1]))
        rules = load_rules(Path(__file__).with_name("rules.json"))
    except (NmapParseError, RuleError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print("Port status:")
    for a in assessments:
        line = f"  {a.host} {a.port.number}/{a.port.protocol} [{a.status}] {a.port.service}"
        if a.reason:
            line += f" - {a.reason}"
        print(line)

    print("Findings:")
    for f in match_rules(assessments, rules):
        print(f"  [{f.severity.upper()}] {f.host} {f.port.number}/{f.port.protocol} {f.title}")