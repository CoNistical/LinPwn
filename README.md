# LinPwn
## Description
Another LinPeas, just a little less verbose.

## Features
- System Information: OS details, kernel version, architecture, hostname
- User Information: Current user, group memberships, sudo/doas privileges
- Active Directory: Domain join status detection
- PATH Analysis: Identifies dangerous entries in PATH
- SUID/SGID Binaries: Finds binaries with special permissions
- Cron Jobs: Detects writable cron files and misconfigurations
- File Capabilities: Identifies dangerous capabilities
- Vulnerability Checks:
  - Dirty Pipe (CVE-2022-0847)
  - Dirty COW (CVE-2016-5195)
  - PwnKit (CVE-2021-4034)
  - Copy Fail (CVE-2026-31431)
  - CVE-2017-16995
  - CVE-2026-24061
  - Netfilter vulnerabilities
  - Screen 4.5.0
- File System Analysis:
  - Writable critical files and directories
  - World-writable files and directories
  - Backup directories
  - SSH private keys
  - Credentials in configuration files and logs
  - Editor artifacts
- Python Library Hijacking: Identifies writable Python paths
- Network Information: Listening ports, interfaces, routing table
- Environment Variables: Scans for sensitive information
- Docker Detection: Identifies container environments
- Summary Report: Consolidated findings with severity indicators

## Usage
```bash
./magiclinpwn.sh
```
## References

- [HackTricks](https://book.hacktricks.wiki)
- [GTFOBins](https://gtfobins.github.io)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [Exploit-DB](https://www.exploit-db.com)
This script is intended for authorized security assessments and educational purposes only. Use it responsibly and only on systems you own or have explicit permission to test.
