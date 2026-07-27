# Security Policy

This policy covers Keyorix's coordinated vulnerability disclosure (CVD) process,
aligned with EU Cyber Resilience Act (CRA) Article 14 and NIS2 Directive
expectations for responsible disclosure.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email **security@keyorix.io** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including any proof-of-concept code or screenshots
- Affected versions or components
- Your name/handle (optional — anonymous reports accepted)

We will acknowledge your report within **2 business days** and provide a
remediation timeline within **10 business days**.

## Scope

In scope:

- Keyorix web application and API endpoints
- Authentication and authorisation flows
- Secrets storage, access control, and sharing features
- Admin and RBAC functionality

Out of scope:

- Denial-of-service attacks
- Vulnerabilities in dependencies that are already publicly disclosed upstream
- Social engineering or phishing of Keyorix staff
- Scanner output without a demonstrated exploit path

## Our Commitment

- We will not pursue legal action against researchers who act in good faith and
  follow this policy (safe harbour).
- We will work with you to understand and resolve the issue promptly.
- We will credit you in the release notes if you wish (opt-in).
- We target a **90-day** patch-and-disclose timeline from the date we reproduce
  the issue. If we need more time, we will communicate that proactively.

## Disclosure Timeline

| Milestone | Target |
|---|---|
| Initial acknowledgement | 2 business days |
| Triage and severity assessment | 5 business days |
| Remediation plan communicated | 10 business days |
| Patch released | 90 days from reproduction |
| Public disclosure | After patch is available |

If we cannot meet the 90-day target we will notify you and agree a revised date.
We will not request indefinite extensions.

## Supported Versions

We release fixes for the current production version only. Keyorix is a SaaS
product; users are always on the latest version automatically.

## Preferred Languages

English or Russian.
