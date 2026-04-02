# Compromise Assessment Tool (CAT)
<img width="1261" height="749" alt="Screenshot 2026-04-02 at 4 25 42 PM" src="https://github.com/user-attachments/assets/7cb6965e-abb3-4185-a8b7-758e4803c8a3" />

A comprehensive Python-based forensic analysis tool that parses Windows and Linux artifacts, detects malicious activities and anomalies, and maps findings to the MITRE ATT&CK framework.

## New in v2.0: Integrated Collection

The CAT tool now includes **built-in forensic artifact collection** capabilities:

```bash
# Collect and analyze in one step
python cat.py --collect --os windows --analyze
python cat.py --collect --os linux --analyze

# Collect specific artifacts only
python cat.py --collect --os windows --artifacts SecurityWELS PowerShellOperationalWELS

# Collect and package for transfer
python cat.py --collect --os windows --package
```

**30+ Windows artifacts** and **20+ Linux artifacts** can be collected automatically.

See [COLLECTION_GUIDE.md](COLLECTION_GUIDE.md) for detailed collection documentation.

## Features

### Core Capabilities
- **Multi-Platform Support**: Analyzes both Windows and Linux forensic artifacts
- **MITRE ATT&CK Integration**: Maps all findings to specific TTPs (Tactics, Techniques, and Procedures)
- **Comprehensive Artifact Parsing**: Supports 30+ different artifact types
- **Automated Detection**: Identifies suspicious patterns, IOCs, and attack behaviors
- **Rich Reporting**: Generates interactive HTML reports and machine-readable JSON outputs

### Windows Artifacts Supported
- **Execution**: Prefetch, ShimCache, AmCache, PowerShell logs
- **Persistence**: Autoruns, Services, Scheduled Tasks, WMI subscriptions
- **Defense Evasion**: Windows Defender logs, Firewall settings, CertUtil cache
- **Credential Access**: Security Event Logs (4624, 4625, 4672, etc.)
- **File System**: MFT analysis, USB device history

### Linux Artifacts Supported
- **Execution**: Shell history (bash, zsh), Yum logs
- **Persistence**: Cron jobs, Systemd services
- **Lateral Movement**: SSH logs, authentication attempts
- **Privilege Escalation**: Sudo command logs
- **Container Security**: Docker container analysis
- **Web Security**: Web shell detection

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
```bash
# Clone or download the tool
git clone https://github.com/Moe-93/Auto-Compromise-assessment-Tool.git
cd Auto-Compromise-assessment-Tool

# Install dependencies (if any)
pip install -r requirements.txt
```

## Usage

### Basic Usage

#### Process Windows Artifacts
```bash
python cat.py --windows-artifacts /path/to/windows/artifacts --output ./reports
```

#### Process Linux Artifacts
```bash
python cat.py --linux-artifacts /path/to/linux/artifacts --output ./reports
```

#### Process Both Windows and Linux
```bash
python cat.py --windows-artifacts /path/to/windows --linux-artifacts /path/to/linux
```

#### Process Single File
```bash
python cat.py --single-file /path/to/security.evtx --artifact-type security_event_logs
```

### List Supported Artifacts
```bash
python cat.py --list-artifacts
```

### Command Line Options
```
--windows-artifacts PATH    Directory containing Windows forensic artifacts
--linux-artifacts PATH      Directory containing Linux forensic artifacts
--single-file PATH          Process a single artifact file
--artifact-type TYPE        Type of artifact (required with --single-file)
--output DIR                Output directory for reports (default: reports)
--list-artifacts            List supported artifact types and exit
-h, --help                  Show help message and exit
```

## MITRE ATT&CK Mapping

The tool maps findings to the following MITRE ATT&CK tactics and techniques:

### Execution (TA0002)
- **T1059** - Command and Scripting Interpreter
  - T1059.001 - PowerShell
  - T1059.004 - Unix Shell
- **T1053** - Scheduled Task/Job
  - T1053.003 - Cron
  - T1053.005 - Scheduled Task
  - T1053.006 - Systemd Timers
- **T1204** - User Execution
- **T1106** - Native API

### Persistence (TA0003)
- **T1547** - Boot or Logon Autostart Execution
- **T1543** - Create or Modify System Process
  - T1543.002 - Systemd Service
  - T1543.003 - Windows Service
- **T1546** - Event Triggered Execution
  - T1546.003 - WMI Event Subscription
- **T1136** - Create Account
- **T1098** - Account Manipulation
- **T1505** - Server Software Component
  - T1505.003 - Web Shell

### Privilege Escalation (TA0004)
- **T1548** - Abuse Elevation Control Mechanism
  - T1548.003 - Sudo and Sudo Caching
- **T1055** - Process Injection

### Defense Evasion (TA0005)
- **T1562** - Impair Defenses
  - T1562.001 - Disable or Modify Tools
  - T1562.004 - Disable or Modify System Firewall
- **T1036** - Masquerading
- **T1027** - Obfuscated Files or Information
- **T1070** - Indicator Removal
  - T1070.002 - Clear Linux or Mac System Logs

### Credential Access (TA0006)
- **T1003** - OS Credential Dumping
  - T1003.001 - LSASS Memory
- **T1558** - Steal or Forge Kerberos Tickets
- **T1110** - Brute Force
  - T1110.001 - Password Guessing

### Discovery (TA0007)
- **T1083** - File and Directory Discovery
- **T1047** - Windows Management Instrumentation

### Lateral Movement (TA0008)
- **T1021** - Remote Services
  - T1021.004 - SSH
- **T1570** - Lateral Tool Transfer

### Collection (TA0009)
- **T1074** - Data Staging

### Command and Control (TA0010)
- **T1071** - Application Layer Protocol
- **T1572** - Protocol Tunneling
- **T1105** - Ingress Tool Transfer

### Exfiltration (TA0011)
- **T1567** - Exfiltration Over Web Service

### Initial Access (TA0001)
- **T1078** - Valid Accounts

## Detection Capabilities

### Windows Detections
- **Brute Force Attacks**: Multiple failed logon attempts (Event ID 4625)
- **Privilege Escalation**: Service installations, privilege assignments
- **Persistence Mechanisms**: New services, scheduled tasks, WMI subscriptions
- **PowerShell Abuse**: Encoded commands, suspicious cmdlets, download cradles
- **Living Off The Land**: CertUtil, MSHTA, Rundll32 abuse
- **Defense Evasion**: Defender disabled, firewall modifications

### Linux Detections
- **Reverse Shells**: Netcat, Bash, Python, Perl reverse shells
- **Persistence**: Suspicious cron jobs, systemd services
- **Credential Access**: SSH brute force, sudo abuse
- **Download & Execute**: wget/curl piped to shell
- **Container Escape**: Privileged containers, mounted root filesystems
- **Web Shells**: PHP eval, system, exec functions

## Output Reports

### HTML Report
- Interactive dashboard with severity statistics
- MITRE ATT&CK matrix visualization
- Detailed findings with full context
- Technique descriptions and recommendations
- Severity-based color coding

### JSON Report
- Machine-readable format for SIEM integration
- Complete finding details
- MITRE technique mappings
- Metadata and timestamps

## Exit Codes

- **0**: No critical findings detected
- **1**: High severity findings detected (review recommended)
- **2**: Critical findings detected (immediate investigation required)
- **130**: Interrupted by user

## Project Structure

```
ca_tool/
├── cat.py                      # Main application entry point
├── config/
│   ├── __init__.py
│   └── mitre_config.py         # MITRE ATT&CK mappings and configurations
├── parsers/
│   ├── __init__.py
│   ├── windows_parser.py       # Windows artifact parsers
│   └── linux_parser.py         # Linux artifact parsers
├── mitre_mapping/
│   ├── __init__.py
│   └── mitre_mapper.py         # MITRE ATT&CK mapping engine
├── reports/
│   ├── __init__.py
│   └── report_generator.py     # HTML and JSON report generation
├── utils/
│   ├── __init__.py
└── reports/                    # Output directory (created automatically)
```

## Examples

### Example 1: Full Windows Assessment
```bash
python cat.py --windows-artifacts C:\forensics\windows --output ./investigation_reports
```

### Example 2: Linux Server Analysis
```bash
python cat.py --linux-artifacts /var/log --output ./linux_analysis
```

### Example 3: Single PowerShell Log Analysis
```bash
python cat.py --single-file C:\logs\powershell.evtx --artifact-type powershell_operational_logs
```

### Example 4: Incident Response Triage
```bash
# Quick analysis of critical artifacts
python cat.py \
    --single-file /var/log/auth.log \
    --artifact-type sshlogin \
    --output ./triage
```

## Best Practices

1. **Artifact Collection**: Use established forensic tools (KAPE, Velociraptor, etc.) for artifact collection
2. **Chain of Custody**: Maintain proper documentation of evidence handling
3. **Timeline Analysis**: Correlate findings across multiple artifacts for comprehensive timeline
4. **False Positives**: Review findings in context of your environment
5. **Regular Updates**: Keep MITRE mappings updated as new techniques emerge

## Limitations

- Text-based log parsing (does not parse binary .evtx files directly)
- Pattern-based detection (may miss novel attack techniques)
- Context-dependent (requires understanding of baseline environment)

## Contributing

Contributions are welcome! Areas for enhancement:
- Additional artifact parsers
- New detection patterns
- Enhanced MITRE mappings
- Report format improvements
- Performance optimizations

## License

MIT License - See LICENSE file for details

## Acknowledgments

- MITRE ATT&CK Framework (https://attack.mitre.org/)
- Forensics community for artifact research
- Open source security tools and research

## Support

For issues, questions, or contributions, please refer to the project repository or contact the maintainers.

---

**Disclaimer**: This tool is for authorized security assessments and incident response only. Always ensure proper authorization before analyzing systems.
