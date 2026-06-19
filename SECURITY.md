# Security Policy

## Supported Versions

Currently, only the latest version of HydraSight (`main` branch or latest release) is actively supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 4.x.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in HydraSight itself, please report it via one of the following methods:

1. **GitHub Security Advisory:** Go to the [Security tab](https://github.com/Shyamprasanth04/hydrasight/security/advisories) of this repository and click **"Report a vulnerability"** to open a private advisory draft.
2. **Direct Contact:** If GitHub Security Advisories are disabled, please email the repository owner directly.

### What to include

Please provide the following information when reporting a vulnerability:

*   **Description of the vulnerability:** What is it and what impact does it have?
*   **Steps to reproduce:** How can we reproduce the vulnerability? (Please provide clear, step-by-step instructions).
*   **Environment details:** What operating system, Python version, and execution mode (`confirm`, `auto`, `never`) were you using?
*   **Suggested fix (optional):** If you have a proposed fix or workaround.

### Our Response

We take security seriously and will acknowledge receipt of your vulnerability report within 48 hours. We will strive to provide regular updates as we investigate the issue and develop a patch. We ask that you maintain confidentiality until we have had an opportunity to address the vulnerability and release a fix.

## Note on Offensive Capabilities

HydraSight is an offensive security tool designed to interact with target systems, exploit vulnerabilities (when approved by the operator and within ROE), and establish access. The tool *itself* performing these actions is its intended behavior.

Vulnerabilities *in* HydraSight would include, but are not limited to:
*   Bypassing the Rules of Engagement (ROE) enforcement layer.
*   Bypassing the `execution_mode` (e.g., executing without confirmation when in `confirm` mode).
*   Remote Code Execution (RCE) *against the operator's host machine* triggered by processing malicious output from a target system.
*   Exposure of the local Ollama instance or Kali MCP credentials to external untrusted networks due to insecure defaults.
