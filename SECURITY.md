# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security vulnerability in agent-immune, **please do not open a public GitHub issue**.

Instead, email **denial@khmbot.com** with:

- A description of the vulnerability
- Steps to reproduce
- Impact assessment (if known)

You should receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

This policy covers vulnerabilities in the agent-immune library itself, including:

- Bypass of injection detection (false negatives on known attack patterns)
- False positives that could cause denial of service
- Memory bank poisoning or manipulation
- Credential/PII leakage through the output scanner
- Issues in the MCP server transport layer

## Disclosure timeline

- **Day 0**: Report received, acknowledgment sent
- **Day 1-7**: Triage and initial assessment
- **Day 7-30**: Fix developed, tested, and released
- **Day 30+**: Public disclosure after fix is available
