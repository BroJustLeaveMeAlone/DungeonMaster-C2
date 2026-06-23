# Security Policy

## Supported Versions

Only the latest commit on `master` is actively maintained.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by emailing: amitkor2009@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You will receive an acknowledgement within 72 hours and a status update within 7 days.

## Scope

This is an offensive security research tool intended for **authorized red team operations only**.
Users are responsible for ensuring they have written authorization before deploying against any target.

Vulnerabilities in the framework itself (server auth bypass, agent key extraction, credential exposure)
are in scope. Issues with community-contributed modules or third-party dependencies should be
reported to their respective maintainers.

**The tool's intended offensive capabilities — credential dumping, process injection, lateral movement,
persistence, and related techniques — are features, not vulnerabilities. Reports about the tool
functioning as designed will be closed without action.**

## Disclosure Policy

We follow coordinated disclosure. Once a fix is confirmed, reporters are credited in the release
notes unless they prefer to remain anonymous.
