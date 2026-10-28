# Nmap Triage Report

Source scan: `mini.xml`

## Summary

| Severity | Exposure findings | Potential CVE matches |
|---|---|---|
| Critical | 0 | 1 |
| High | 1 | 0 |
| Medium | 0 | 0 |
| Low | 1 | 0 |

Ports: 2 confirmed open, 0 unverified, 1 ignored.

## Exposure findings

| Severity | Host | Port | Service | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|---|---|
| High | 192.168.56.101 (metasploitable) | 23/tcp | Linux telnetd | Telnet exposed | Telnet sends credentials and data in cleartext, so anyone on the network path can read them. | Disable Telnet and use SSH. |
| Low | 192.168.56.101 (metasploitable) | 80/tcp | Apache httpd 2.2.8 | Plain HTTP (no TLS) | Traffic is unencrypted, so logins and session cookies can be intercepted. | Serve over HTTPS and redirect HTTP to it. |

## Potential CVE matches (version-based, verify manually)

| Severity | CVSS | Host | Port | Detected | CVE | Summary |
|---|---|---|---|---|---|---|
| Critical | 9.8 | 192.168.56.101 (metasploitable) | 80/tcp | Apache httpd 2.2.8 | CVE-2017-7679 | mod_mime can read one byte past the end of a buffer when handling a crafted Content-Type header. |

## Needs manual check

- 192.168.56.101 (metasploitable) 23/tcp `telnet`: no version detected, needs manual check

## Ignored ports

- 192.168.56.101 (metasploitable) 8080/tcp `http-proxy`: state is 'filtered', not a confirmed open service

## Limitations

- CVE matches are based on the reported version only. Linux distributions often backport fixes without changing the version, so every match is potential and needs manual verification.
- Services with no detected version get exposure rules but no CVE lookup.
- If the scan was run without `-sV`, service names are guessed from port numbers and are unreliable.
- The CVE data file is small and hand-curated, so a missing match does not mean the service is safe.
