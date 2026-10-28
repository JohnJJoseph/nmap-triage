"""Parse Nmap XML (-oX) output into simple Python objects."""
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


class NmapParseError(Exception):
    """Raised when the input is missing, empty or not valid Nmap XML."""


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list = field(default_factory=list)


@dataclass
class Host:
    address: str
    hostname: str = ""
    state: str = "unknown"
    ports: list = field(default_factory=list)


def parse_nmap_xml(path):
    """Return a list of Host objects from an Nmap XML file."""
    path = Path(path)
    if not path.is_file():
        raise NmapParseError(f"File not found: {path}")
    if path.stat().st_size == 0:
        raise NmapParseError(f"File is empty: {path}")

    try:
        root = ET.parse(str(path)).getroot()
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid XML in {path}: {exc}") from exc
    except DefusedXmlException as exc:
        raise NmapParseError(f"Unsafe XML rejected in {path}: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError(f"Not an Nmap XML file (root tag is <{root.tag}>)")

    return [_parse_host(h) for h in root.findall("host")]


def _parse_host(host_el):
    status = host_el.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    address = ""
    for addr in host_el.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):  # skip MAC addresses
            address = addr.get("addr", "")
            break

    name_el = host_el.find("hostnames/hostname")
    hostname = name_el.get("name", "") if name_el is not None else ""

    ports = [_parse_port(p) for p in host_el.findall("ports/port")]
    return Host(address=address, hostname=hostname, state=state, ports=ports)


def _parse_port(port_el):
    state_el = port_el.find("state")
    svc = port_el.find("service")

    port = Port(
        number=int(port_el.get("portid", "0")),
        protocol=port_el.get("protocol", ""),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
    )
    if svc is not None:
        port.service = svc.get("name", "")
        port.product = svc.get("product", "")
        port.version = svc.get("version", "")
        port.extrainfo = svc.get("extrainfo", "")
        port.cpes = [c.text.strip() for c in svc.findall("cpe") if c.text]
    return port


if __name__ == "__main__":  # quick manual check
    import sys

    if len(sys.argv) != 2:
        print("Usage: python parser.py <scan.xml>")
        sys.exit(1)
    try:
        for host in parse_nmap_xml(sys.argv[1]):
            print(host.address, host.hostname, host.state)
            for p in host.ports:
                print(f"  {p.number}/{p.protocol} {p.state} {p.service} {p.product} {p.version}")
    except NmapParseError as exc:
        print(f"Error: {exc}")
        sys.exit(1)