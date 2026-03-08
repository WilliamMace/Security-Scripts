# Security-Scripts

A collection of PowerShell and Python scripts for cybersecurity automation, designed for federal IT environments and GRC workflows.

## Overview

This repository contains practical scripts for security professionals working in DoD and federal environments. Each script is designed to automate common security tasks including STIG compliance checking, log analysis, vulnerability assessment, and compliance reporting.

## Repository Structure

```
Security-Scripts/
|-- powershell/
|   |-- stig-compliance/       # DISA STIG compliance automation
|   |-- log-analysis/           # Windows event log parsing and analysis
|   |-- active-directory/       # AD security auditing scripts
|   |-- network-security/       # Network scanning and monitoring
|
|-- python/
|   |-- vulnerability-scanner/  # Basic vulnerability assessment tools
|   |-- compliance-reporting/   # NIST 800-53 compliance report generation
|   |-- log-parser/             # Security log parsing and analysis
|   |-- threat-intel/           # Threat intelligence feed integration
|
|-- docs/
|   |-- setup-guides/           # Environment setup documentation
|   |-- usage-examples/         # Script usage examples
```

## Scripts

### PowerShell

| Script | Description | Status |
|--------|-------------|--------|
| STIG Compliance Checker | Automates DISA STIG compliance checks for Windows systems | Planned |
| Event Log Analyzer | Parses Windows Security event logs for suspicious activity | Planned |
| AD Security Audit | Audits Active Directory for security misconfigurations | Planned |
| Firewall Rule Reviewer | Reviews and validates Windows Firewall rules | Planned |

### Python

| Script | Description | Status |
|--------|-------------|--------|
| NIST 800-53 Report Generator | Generates compliance reports mapped to NIST controls | Planned |
| Vulnerability Scanner | Basic network vulnerability assessment tool | Planned |
| Log Parser | Parses and correlates security logs from multiple sources | Planned |
| CVE Lookup Tool | Queries NVD for CVE details and risk scoring | Planned |

## Frameworks and Standards

- NIST SP 800-53 Rev 5
- NIST Risk Management Framework (RMF)
- DISA STIGs
- FISMA
- CMMC

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- Python 3.9+
- See individual script folders for specific dependencies

## Usage

Detailed usage instructions will be provided in each script's folder as they are developed.

## Contributing

This is a personal portfolio project. Suggestions and feedback are welcome via Issues.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**William Mace**
- Cybersecurity & GRC Professional
- Program Analyst | U.S. Department of Defense
- [LinkedIn](https://www.linkedin.com/in/williamamace)
- [GitHub](https://github.com/WilliamMace)
