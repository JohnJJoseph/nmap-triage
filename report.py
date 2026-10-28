"""Build the Markdown report from the analysis results."""
from analyzer import IGNORED, OPEN, SEVERITY_ORDER, UNVERIFIED

SEVERITIES = ["critical", "high", "medium", "low"]


def _esc(text):
    """Keep table cells valid: escape pipes and remove newlines."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _host(address, hostname):
    return f"{address} ({hostname})" if hostname else address


def _detected(port):
    text = " ".join(p for p in (port.product, port.version) if p)
    return text or port.service or "unknown"


def _port(port):
    return f"{port.number}/{port.protocol}"


def build_report(source_name, assessments, findings, cve_matches):
    """Return the full report as a Markdown string."""
    open_ports = [a for a in assessments if a.status == OPEN]
    unverified = [a for a in assessments if a.status == UNVERIFIED]
    ignored = [a for a in assessments if a.status == IGNORED]
    no_version = [a for a in open_ports if not a.version_known]

    out = []
    out.append("# Nmap Triage Report\n")
    out.append(f"Source scan: `{source_name}`\n")

    # Summary
    out.append("## Summary\n")
    out.append("| Severity | Exposure findings | Potential CVE matches |")
    out.append("|---|---|---|")
    for sev in SEVERITIES:
        n_find = sum(1 for f in findings if f.severity == sev)
        n_cve = sum(1 for m in cve_matches if m.severity == sev)
        out.append(f"| {sev.capitalize()} | {n_find} | {n_cve} |")
    out.append("")
    out.append(f"Ports: {len(open_ports)} confirmed open, "
               f"{len(unverified)} unverified, {len(ignored)} ignored.\n")

    # Exposure findings
    out.append("## Exposure findings\n")
    if findings:
        out.append("| Severity | Host | Port | Service | Issue | Why it matters | Suggested fix |")
        out.append("|---|---|---|---|---|---|---|")
        for f in findings:
            out.append(f"| {f.severity.capitalize()} | {_esc(_host(f.host, f.hostname))} "
                       f"| {_port(f.port)} | {_esc(_detected(f.port))} | {_esc(f.title)} "
                       f"| {_esc(f.reason)} | {_esc(f.fix)} |")
    else:
        out.append("None.")
    out.append("")

    # CVE matches
    out.append("## Potential CVE matches (version-based, verify manually)\n")
    if cve_matches:
        out.append("| Severity | CVSS | Host | Port | Detected | CVE | Summary |")
        out.append("|---|---|---|---|---|---|---|")
        for m in cve_matches:
            out.append(f"| {m.severity.capitalize()} | {m.cvss} "
                       f"| {_esc(_host(m.host, m.hostname))} | {_port(m.port)} "
                       f"| {_esc(_detected(m.port))} | {m.cve} | {_esc(m.summary)} |")
    else:
        out.append("None.")
    out.append("")

    # Needs manual check
    out.append("## Needs manual check\n")
    manual = unverified + no_version
    if manual:
        for a in manual:
            out.append(f"- {_host(a.host, a.hostname)} {_port(a.port)} "
                       f"`{a.port.service or 'unknown'}`: {a.reason}")
    else:
        out.append("None.")
    out.append("")

    # Ignored
    out.append("## Ignored ports\n")
    if ignored:
        for a in ignored:
            out.append(f"- {_host(a.host, a.hostname)} {_port(a.port)} "
                       f"`{a.port.service or 'unknown'}`: {a.reason}")
    else:
        out.append("None.")
    out.append("")

    # Limitations
    out.append("## Limitations\n")
    out.append("- CVE matches are based on the reported version only. Linux distributions "
               "often backport fixes without changing the version, so every match is "
               "potential and needs manual verification.")
    out.append("- Services with no detected version get exposure rules but no CVE lookup.")
    out.append("- If the scan was run without `-sV`, service names are guessed from port "
               "numbers and are unreliable.")
    out.append("- The CVE data file is small and hand-curated, so a missing match does not "
               "mean the service is safe.")
    out.append("")

    return "\n".join(out)