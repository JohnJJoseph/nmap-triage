# Nmap Triage Report

Source scan: `metasploitable.xml`

## Summary

| Severity | Exposure findings | Potential CVE matches |
|---|---|---|
| Critical | 1 | 3 |
| High | 9 | 0 |
| Medium | 6 | 0 |
| Low | 1 | 0 |

Ports: 23 confirmed open, 0 unverified, 0 ignored.

## Exposure findings

| Severity | Host | Port | Service | Issue | Why it matters | Suggested fix |
|---|---|---|---|---|---|---|
| Critical | 192.168.239.128 | 1524/tcp | Metasploitable root shell | Possible backdoor shell | A service identified as a bind shell gives remote command access with no authentication. | Isolate the host and investigate. Treat it as compromised. |
| High | 192.168.239.128 | 23/tcp | Linux telnetd | Telnet exposed | Telnet sends credentials and data in cleartext, so anyone on the network path can read them. | Disable Telnet and use SSH. |
| High | 192.168.239.128 | 139/tcp | Samba smbd 3.X - 4.X | SMB/NetBIOS exposed | SMB is a common target for credential attacks, relay and wormable bugs. | Block SMB at the perimeter and restrict to trusted hosts. |
| High | 192.168.239.128 | 445/tcp | Samba smbd 3.X - 4.X | SMB/NetBIOS exposed | SMB is a common target for credential attacks, relay and wormable bugs. | Block SMB at the perimeter and restrict to trusted hosts. |
| High | 192.168.239.128 | 512/tcp | netkit-rsh rexecd | Legacy r-service exposed | rexec, rlogin and rsh use cleartext and weak host-based trust. | Disable the service and use SSH. |
| High | 192.168.239.128 | 513/tcp | login | Legacy r-service exposed | rexec, rlogin and rsh use cleartext and weak host-based trust. | Disable the service and use SSH. |
| High | 192.168.239.128 | 514/tcp | Netkit rshd | Legacy r-service exposed | rexec, rlogin and rsh use cleartext and weak host-based trust. | Disable the service and use SSH. |
| High | 192.168.239.128 | 3306/tcp | MySQL 5.0.51a-3ubuntu5 | Database exposed | Databases should not be reachable from untrusted networks. | Bind to localhost or an internal network and firewall the port. |
| High | 192.168.239.128 | 5432/tcp | PostgreSQL DB 8.3.0 - 8.3.7 | Database exposed | Databases should not be reachable from untrusted networks. | Bind to localhost or an internal network and firewall the port. |
| High | 192.168.239.128 | 5900/tcp | VNC | VNC exposed | VNC often has weak or no authentication and weak encryption. | Tunnel through SSH or VPN and require strong passwords. |
| Medium | 192.168.239.128 | 21/tcp | vsftpd 2.3.4 | FTP exposed | FTP sends credentials in cleartext and often allows anonymous access. | Use SFTP/FTPS, disable anonymous login, restrict by firewall. |
| Medium | 192.168.239.128 | 111/tcp | rpcbind 2 | NFS/RPC exposed | Exposed NFS or RPC can leak shares and system information. | Restrict to trusted hosts and review the export list. |
| Medium | 192.168.239.128 | 1099/tcp | GNU Classpath grmiregistry | Java RMI exposed | Misconfigured RMI registries can allow remote code execution. | Restrict access and review the RMI configuration. |
| Medium | 192.168.239.128 | 2049/tcp | nfs 2-4 | NFS/RPC exposed | Exposed NFS or RPC can leak shares and system information. | Restrict to trusted hosts and review the export list. |
| Medium | 192.168.239.128 | 2121/tcp | ProFTPD 1.3.1 | FTP exposed | FTP sends credentials in cleartext and often allows anonymous access. | Use SFTP/FTPS, disable anonymous login, restrict by firewall. |
| Medium | 192.168.239.128 | 6000/tcp | X11 | X11 exposed | An open X11 server can allow remote screen capture and keystroke access. | Disable TCP listening and use SSH X11 forwarding. |
| Low | 192.168.239.128 | 80/tcp | Apache httpd 2.2.8 | Plain HTTP (no TLS) | Traffic is unencrypted, so logins and session cookies can be intercepted. | Serve over HTTPS and redirect HTTP to it. |

## Potential CVE matches (version-based, verify manually)

| Severity | CVSS | Host | Port | Detected | CVE | Summary |
|---|---|---|---|---|---|---|
| Critical | 9.8 | 192.168.239.128 | 21/tcp | vsftpd 2.3.4 | CVE-2011-2523 | The vsftpd 2.3.4 download was backdoored and opens a command shell on port 6200. |
| Critical | 9.8 | 192.168.239.128 | 80/tcp | Apache httpd 2.2.8 | CVE-2017-7679 | mod_mime can read one byte past the end of a buffer when handling a crafted Content-Type header. |
| Critical | 9.8 | 192.168.239.128 | 2121/tcp | ProFTPD 1.3.1 | CVE-2010-4221 | Stack-based buffer overflow in ProFTPD Telnet IAC handling can allow remote code execution. |

## Needs manual check

- 192.168.239.128 23/tcp `telnet`: no version detected, needs manual check
- 192.168.239.128 25/tcp `smtp`: no version detected, needs manual check
- 192.168.239.128 512/tcp `exec`: no version detected, needs manual check
- 192.168.239.128 513/tcp `login`: no version detected, needs manual check
- 192.168.239.128 514/tcp `shell`: no version detected, needs manual check
- 192.168.239.128 1099/tcp `java-rmi`: no version detected, needs manual check
- 192.168.239.128 1524/tcp `bindshell`: no version detected, needs manual check
- 192.168.239.128 5900/tcp `vnc`: no version detected, needs manual check
- 192.168.239.128 6000/tcp `X11`: no version detected, needs manual check
- 192.168.239.128 6667/tcp `irc`: no version detected, needs manual check
- 192.168.239.128 8009/tcp `ajp13`: no version detected, needs manual check
- 192.168.239.128 8180/tcp `unknown`: no version detected, needs manual check

## Open services with no rule or CVE match

These were not matched, which does not mean they are safe. Versions that are not plain numbers (for example `4.7p1` or `3.X - 4.X`) cannot be compared, so they are never guessed.

- 192.168.239.128 22/tcp `ssh`: OpenSSH 4.7p1 Debian 8ubuntu1
- 192.168.239.128 53/tcp `domain`: ISC BIND 9.4.2

## Ignored ports

None.

## Limitations

- CVE matches are based on the reported version only. Linux distributions often backport fixes without changing the version, so every match is potential and needs manual verification.
- Services with no detected version get exposure rules but no CVE lookup.
- If the scan was run without `-sV`, service names are guessed from port numbers and are unreliable.
- The CVE data file is small and hand-curated, so a missing match does not mean the service is safe.
