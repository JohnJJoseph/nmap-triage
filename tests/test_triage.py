import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer import (IGNORED, UNVERIFIED, assess_hosts, load_cves, load_rules,  # noqa: E402
                      match_cves, match_rules, version_matches)
from nmap_triage import main  # noqa: E402
from parser import NmapParseError, parse_nmap_xml  # noqa: E402
from report import build_report  # noqa: E402

SAMPLES = ROOT / "samples"
RULES = load_rules(ROOT / "rules.json")
CVES = load_cves(ROOT / "cve_data.json")


def run(name):
    assessments = assess_hosts(parse_nmap_xml(SAMPLES / name))
    return assessments, match_rules(assessments, RULES), match_cves(assessments, CVES)


# ---- successful cases ----

def test_mini_ranks_telnet_before_http():
    _, findings, _ = run("mini.xml")
    assert [(f.port.number, f.severity) for f in findings] == [(23, "high"), (80, "low")]


def test_old_apache_gets_potential_cve():
    _, _, cves = run("mini.xml")
    assert [(m.cve, m.port.number) for m in cves] == [("CVE-2017-7679", 80)]


# ---- false-positive handling ----

def test_filtered_ports_produce_nothing():
    assessments, findings, cves = run("filtered.xml")
    assert all(a.status == IGNORED for a in assessments)
    assert findings == [] and cves == []


def test_tcpwrapped_is_unverified_and_not_flagged():
    assessments, findings, _ = run("tcpwrapped.xml")
    status = {a.port.number: a.status for a in assessments}
    assert status[9999] == UNVERIFIED
    assert 9999 not in [f.port.number for f in findings]


def test_https_is_not_reported_as_plain_http():
    _, findings, _ = run("https.xml")
    ports = [f.port.number for f in findings]
    assert 80 in ports and 443 not in ports


def test_patched_range_gets_no_cve():
    _, _, cves = run("https.xml")  # Apache 2.4.57 is outside the 2.4.0-2.4.26 range
    assert 443 not in [m.port.number for m in cves]


def test_no_version_gets_no_cve():
    _, _, cves = run("mini.xml")
    assert 23 not in [m.port.number for m in cves]


def test_non_numeric_version_is_not_guessed():
    entry = {"product": "samba", "ranges": [{"from": "3.0.0", "before": "3.0.25"}]}
    assert version_matches("3.X - 4.X", entry) is False
    assert version_matches("3.0.20", entry) is True


def test_range_upper_bound_is_exclusive():
    entry = next(e for e in CVES if e["cve"] == "CVE-2017-7679")
    assert version_matches("2.2.32", entry) is True
    assert version_matches("2.2.33", entry) is False


# ---- error handling ----

def test_broken_xml_raises_clean_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml(SAMPLES / "broken.xml")


def test_missing_file_raises_clean_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml(SAMPLES / "nothere.xml")


# ---- CLI and report ----

def test_cli_exit_1_when_high_finding(tmp_path):
    out = tmp_path / "r.md"
    assert main([str(SAMPLES / "mini.xml"), "-o", str(out)]) == 1
    assert "Telnet exposed" in out.read_text(encoding="utf-8")


def test_cli_exit_0_when_nothing_found(tmp_path):
    assert main([str(SAMPLES / "filtered.xml"), "-o", str(tmp_path / "r.md")]) == 0


def test_cli_exit_2_on_broken_input(tmp_path):
    assert main([str(SAMPLES / "broken.xml"), "-o", str(tmp_path / "r.md")]) == 2


def test_report_matches_expected_file():
    expected = SAMPLES / "expected_report.md"
    if not expected.exists():
        pytest.skip("expected_report.md not generated yet")
    assessments, findings, cves = run("mini.xml")
    assert build_report("mini.xml", assessments, findings, cves) == expected.read_text(encoding="utf-8")

def test_service_name_is_case_insensitive():
    _, findings, _ = run("metasploitable.xml")
    assert 6000 in [f.port.number for f in findings]


def test_real_scan_does_not_guess_non_numeric_versions():
    _, _, cves = run("metasploitable.xml")
    assert not any(m.port.number in (22, 139, 445, 3306, 5432) for m in cves)


def test_real_scan_known_cves_present():
    _, _, cves = run("metasploitable.xml")
    found = {(m.cve, m.port.number) for m in cves}
    assert {("CVE-2011-2523", 21), ("CVE-2017-7679", 80), ("CVE-2010-4221", 2121)} <= found