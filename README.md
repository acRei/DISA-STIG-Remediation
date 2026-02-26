# DISA STIG Remediation Repository

##  Overview

This repository contains practical remediation scripts, configurations, and documentation for implementing DISA STIG (Security Technical Implementation Guide) controls across various systems.

The goal of this project is to demonstrate:
* A clear understanding of security hardening standards
* Hands-on experience translating STIG findings into real-world remediations
* Repeatable, auditable approaches to improving system security posture

Each remediation is designed to be clear, testable, and aligned with DISA STIG requirements.

---

##  Objectives

* Provide ready-to-use remediation examples for common DISA STIG findings
* Show how STIG controls can be enforced using scripts and configuration changes
* Serve as a learning and reference resource for security operations, compliance, and system hardening
* Demonstrate security engineering skills relevant to SOC, GRC, and system security roles

---

##  What Each Remediation Includes

Each remediation file aims to include:
* **STIG ID** (e.g., WN11-AU-000500)
* **STIG Description**
* **Why the control matters**
* **Remediation logic**
* **Scripted implementation** (PowerShell, Bash, etc.)
* **Validation steps** to confirm compliance
* **Rollback notes** (when applicable)

---

##  Testing Environment

All remediations are tested in lab environments, including:
* Virtual machines
* Non-production systems
* Security simulation setups

⚠️ **These scripts are not intended for direct production use without review.** Always test in a controlled environment and follow your organization's change management process.

---

##  References

* [DISA STIG Documentation](https://public.cyber.mil/stigs/)
* [STIG Viewer](https://public.cyber.mil/stigs/srg-stig-tools/)
* [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
* NIST SP 800-53 / 800-171 (where applicable)

Specific references for each control are documented alongside their respective remediations.

---

##  Roadmap

Planned additions include:
* Expanded Windows 11 STIG coverage
* Linux STIG remediations (RHEL / Ubuntu)
* Automated validation checks
* Mapping STIGs to NIST controls
* Detection vs. remediation comparisons

---

##  Disclaimer

This repository is for educational and demonstration purposes only. Scripts are provided as-is with no warranty. I am not responsible for system misconfigurations or unintended impacts.
