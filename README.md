# VulnScanner

Security vulnerability scanner — network, web, dependencies, Docker, and secrets.

## Why this exists

Most security tools are either enterprise-grade with a massive footprint, or single-purpose CLI tools that only do one thing. VulnScanner aims to be a unified, lightweight scanner you can run in CI pipelines or locally to catch common security issues before they reach production.

## Scanners

| Scanner | What it checks |
|---------|---------------|
| **Network** | Open ports against known risky services (25+ common ports) |
| **Web** | Security headers, SSL/TLS, cookie flags, CORS misconfiguration |
| **Dependencies** | Known CVEs in package.json (lodash, minimist, axios, express, etc.) |
| **Docker** | Container security: root user, privileged mode, host namespace, Docker socket mounts, missing limits |
| **Secrets** | Hardcoded credentials (AWS keys, GitHub tokens, private keys, DB URLs, JWTs, API keys, passwords) |

## Quick Start

```bash
npm install
npm run build
npm start scan --target 192.168.1.1
npm start scan --target https://example.com --scanners web
npm start scan --target . --scanners secrets,dependency
```

## CLI

```bash
# Scan everything
vulnscanner scan -t 192.168.1.1

# Web-only scan
vulnscanner scan -t https://mysite.com -s web

# Scan local project for secrets and dependency issues
vulnscanner scan -t . -s secrets,dependency

# JSON output
vulnscanner scan -t 10.0.0.1 -o json

# List available scanners
vulnscanner list-scanners
```

## Output

```
══════════════════════════════════════════════════════════════════════
  VULNSCANNER REPORT
══════════════════════════════════════════════════════════════════════

  SUMMARY
  ────────────────────────────────────────
  Total scans:     3
  Total findings:  12
  Critical:        2
  High:            5
  Medium:          3
  Low:             2
  Info:            0

  [Network] → 192.168.1.1
  ──────────────────────────────────────────────────
  🔴 [CRITICAL] Redis (6379): No authentication by default
    ID: NET-6379-no-authentication-by-default
    Port 6379 (Redis) is open. Risk: No authentication by default
    Fix: Restrict access to port 6379 using firewall rules.
```

## Exit codes

- `0` — No critical or high vulnerabilities found
- `1` — One or more critical/high vulnerabilities detected

Makes it easy to integrate into CI/CD pipelines.

## Integration with SecOps Dashboard

VulnScanner findings can be imported into the SecOps Dashboard for tracking, triage, and incident management. See the [SecOps Dashboard](../secops-dashboard) project.

## Requirements

- Node.js 18+
- Docker socket (for Docker scanner)

## License

MIT
