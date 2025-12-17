# Security Policy

## Supported Versions

We currently support the following versions of Scalpel Racer with security updates:

| Version | Supported          | Notes                                  |
| :-----: | :----------------: | :------------------------------------- |
| Latest  | :white_check_mark: | The latest commit on the `main` branch |

If you are using an older version, please upgrade to the latest version to ensure you have the most recent security patches and features.

## Reporting a Vulnerability

We take the security of Scalpel Racer seriously. If you have discovered a security vulnerability in this project, please report it to us responsibly.

**Do not open a public issue** on GitHub for security vulnerabilities, as this may disclose the flaw to malicious actors before a fix is available.

### How to Report

Please email your findings to **xkilldash9x@proton.me**.

In your report, please include:
1.  **Description**: A clear and concise description of the vulnerability.
2.  **Reproduction Steps**: Detailed steps, scripts, or commands to reproduce the issue.
3.  **Impact**: The potential impact of the vulnerability.
4.  **Environment**: The version of Scalpel Racer, Python version, and operating system used.

We will acknowledge your report within 48 hours and provide an estimated timeline for triage and resolution.

### Vulnerability Handling Process

1.  **Triage**: We will investigate the report to verify the vulnerability and assess its severity.
2.  **Fix Development**: If confirmed, we will develop a patch to address the issue.
3.  **Review**: The fix will be reviewed to ensure it effectively resolves the vulnerability without introducing regressions.
4.  **Release**: A security update will be released.
5.  **Disclosure**: After a reasonable period to allow users to upgrade, we may publish a security advisory or public disclosure, crediting you for the discovery (unless you prefer to remain anonymous).

## Security Best Practices for Users

Since Scalpel Racer is a security testing tool, it interacts with network traffic and certificates. We recommend the following best practices:

*   **Virtual Environment**: Always run Scalpel Racer in an isolated virtual environment (`venv`) to prevent dependency conflicts and ensure a clean state.
*   **CA Certificate**: Protect the generated `scalpel_ca.key`. Do not share it. If you suspect it has been compromised, delete `scalpel_ca.key` and `scalpel_ca.pem` and restart the tool to generate a new pair.
*   **Root Privileges**: The `first-seq` strategy requires `sudo` privileges on Linux. Only run with root privileges when necessary and ensure you trust the code you are running.
*   **Target Scope**: Only use this tool against targets you have explicit permission to test. Unauthorized use of this tool is illegal and unethical.

## License

This project is open-source. Please refer to the LICENSE file for more details.
