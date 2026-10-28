"""Nmap XML in, prioritised Markdown report out.

Exit codes: 0 = done, 1 = findings at or above --fail-on, 2 = error.
"""
import argparse
import sys
from pathlib import Path

from analyzer import (SEVERITY_ORDER, CveDataError, RuleError, assess_hosts,
                      load_cves, load_rules, match_cves, match_rules)
from parser import NmapParseError, parse_nmap_xml
from report import SEVERITIES, build_report

HERE = Path(__file__).resolve().parent


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="nmap_triage",
        description="Prioritise Nmap XML (-oX, ideally with -sV) results into a Markdown report.")
    p.add_argument("scan", help="Nmap XML file")
    p.add_argument("-o", "--output", default="report.md", help="report file (default: report.md)")
    p.add_argument("--rules", default=str(HERE / "rules.json"), help="exposure rules JSON")
    p.add_argument("--cves", default=str(HERE / "cve_data.json"), help="local CVE data JSON")
    p.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "never"],
                   help="exit with code 1 if a finding at or above this severity exists "
                        "(default: high)")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    try:
        hosts = parse_nmap_xml(args.scan)
        rules = load_rules(args.rules)
        cves = load_cves(args.cves)
    except (NmapParseError, RuleError, CveDataError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    assessments = assess_hosts(hosts)
    findings = match_rules(assessments, rules)
    matches = match_cves(assessments, cves)
    report = build_report(Path(args.scan).name, assessments, findings, matches)

    try:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
    except OSError as exc:
        print(f"Error: cannot write report to {args.output}: {exc}", file=sys.stderr)
        return 2

    # Terminal summary
    print(f"Report written to {args.output}")
    for sev in SEVERITIES:
        n_find = sum(1 for f in findings if f.severity == sev)
        n_cve = sum(1 for m in matches if m.severity == sev)
        if n_find or n_cve:
            print(f"  {sev.upper():8} exposure: {n_find}  potential CVE: {n_cve}")
    if not findings and not matches:
        print("  No findings.")

    if args.fail_on == "never":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    worst = min([SEVERITY_ORDER[f.severity] for f in findings] +
                [SEVERITY_ORDER[m.severity] for m in matches], default=99)
    if worst <= limit:
        print(f"Result: findings at or above '{args.fail_on}' found (exit code 1)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())