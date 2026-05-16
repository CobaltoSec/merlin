# Security Policy

## Scope

Merlin is an offensive testing framework for LLM-integrated web applications.
It is intended for use against systems you own or have explicit written
authorization to assess.

**In scope for vulnerability reports:**
- `merlin/payloads/loader.py` — YAML deserialization issues
- `merlin/core/http_client.py` — request smuggling, SSRF against the operator host
- `merlin/cli.py` — argument injection
- State / config file handling — if Merlin trusts a tampered state file
  in a way that leads to command execution on the operator machine

**Out of scope:**
- Vulnerabilities in target LLM applications (that's what Merlin finds — by design)
- Vulnerabilities in third-party packages — report upstream
- Issues that require the attacker to already control the operator host

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **nicolas@cobalto-sec.tech**  
Subject line: `[MERLIN SECURITY] <short description>`

Include:
1. Description of the vulnerability and affected component
2. Reproduction steps (minimal proof of concept)
3. Potential impact assessment
4. Your suggested fix (optional but appreciated)

We will acknowledge receipt within **48 hours** and aim to ship a fix within
**7 days** for critical issues, **30 days** for moderate issues.

## Disclosure policy

We follow coordinated disclosure. Please give us time to patch before public
disclosure. We will credit you in the release notes unless you prefer
anonymity.
