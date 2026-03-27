# Security Audit Skill for Claude Code

A phase-based security audit skill for [Claude Code](https://claude.ai/code) that lets you run targeted security reviews on any codebase. Select exactly which security domains to audit — run one phase, a few, or all ten.

## Features

- **10 independent security phases** — pick what matters, skip what doesn't
- **Multiple-choice selection** — enter `1,2,5` or `ALL` when prompted
- **Consistent finding format** — every issue includes severity, location, evidence, impact, and fix
- **Real-world reference patterns** — proper implementations for every anti-pattern shown
- **Phase-aware reporting** — report shows which phases ran and which were skipped

## Phases

| # | Phase | What It Catches |
|---|-------|----------------|
| 1 | Secrets & Credentials | Hardcoded API keys, committed `.env` files, secrets in frontend bundles |
| 2 | Authentication & Sessions | Session hijacking, missing brute force protection, insecure cookies |
| 3 | Authorization & Access Control | Privilege escalation, missing role checks, client-side-only auth |
| 4 | Data Protection & Tenant Isolation | IDOR vulnerabilities, cross-tenant data leaks, missing ownership checks |
| 5 | Input Validation & Injection | XSS, SQL injection, command injection, prompt injection |
| 6 | API Security & Rate Limiting | Unprotected endpoints, missing rate limits, enumeration attacks |
| 7 | Infrastructure & Security Headers | CORS misconfiguration, missing security headers, clickjacking |
| 8 | Dependencies & Supply Chain | Vulnerable packages, outdated dependencies, typosquatting |
| 9 | Encryption & Key Management | Weak algorithms, hardcoded keys, IV reuse, poor key lifecycle |
| 10 | Logging, Auditing & Monitoring | Missing audit trails, sensitive data in logs, undetected breaches |

## Installation

### Option 1: Add to your project (recommended for teams)

```bash
mkdir -p .claude/skills/security-audit
curl -o .claude/skills/security-audit/SKILL.md \
  https://raw.githubusercontent.com/JayDoolan/security-audit-skill/main/SKILL.md
```

Commit it to your repo so everyone on the team has access.

### Option 2: Add to your global Claude Code skills

```bash
mkdir -p ~/.claude/skills/security-audit
curl -o ~/.claude/skills/security-audit/SKILL.md \
  https://raw.githubusercontent.com/JayDoolan/security-audit-skill/main/SKILL.md
```

This makes the skill available across all your projects.

## Usage

In Claude Code, run:

```
/security-audit
```

You'll see a selection menu:

```
Which security phases would you like to run? (enter numbers comma-separated, or ALL)

 [1]  Secrets & Credentials
 [2]  Authentication & Sessions
 [3]  Authorization & Access Control
 [4]  Data Protection & Tenant Isolation
 [5]  Input Validation & Injection Prevention
 [6]  API Security & Rate Limiting
 [7]  Infrastructure & Security Headers
 [8]  Dependencies & Supply Chain
 [9]  Encryption & Key Management
 [10] Logging, Auditing & Monitoring

 [ALL] Complete security review (all phases)

Example: 1,2,5 or ALL
```

### Examples

Run a quick secrets + auth check:
```
/security-audit
> 1,2
```

Run a full review:
```
/security-audit
> ALL
```

Focus on data protection and input validation:
```
/security-audit
> 4,5
```

## Severity Levels

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Exploitable now. Immediate data breach risk. | Fix before next deploy |
| **HIGH** | Significant vulnerability, clearly exploitable. | Fix this sprint |
| **MEDIUM** | Defense gap or weak implementation. | Fix next sprint |
| **LOW** | Hardening opportunity, defense-in-depth. | Backlog |

## Report Output

After running selected phases, you get a structured report:

- Which phases were completed vs. skipped
- Findings grouped by phase with severity tags
- Summary table (X critical, Y high, Z medium, W low)
- Prioritised quick wins
- Recommendation to run remaining phases for full coverage

## Works With Any Stack

The skill is framework-agnostic. It includes detection patterns and grep commands for:

- **JavaScript / TypeScript** (Next.js, Express, React, Node.js)
- **Python** (Django, Flask, FastAPI)
- **Go, Ruby, Java, PHP**
- **Any SQL or NoSQL database**
- **Any authentication framework**

## What This Skill Is Good For

- Initial security triage of unfamiliar codebases
- Reviewing AI-generated or rapidly prototyped applications
- Targeted audits of specific security domains
- Pre-deployment security checks
- Onboarding security review for new projects

## What This Skill Is Not

- A replacement for formal penetration testing
- A compliance audit tool (SOC 2, HIPAA, etc.)
- An automated scanner — it guides Claude's analysis of your specific code
- A deep cryptographic analysis tool

## Contributing

PRs welcome. When adding or modifying phases:

1. Follow the existing per-phase structure (Objective, Checklist, Where to Look, Anti-Patterns, Proper Patterns, Quick Fixes)
2. Include both anti-patterns and proper patterns with code examples
3. Tag all findings with severity levels (CRITICAL/HIGH/MEDIUM/LOW)
4. Keep detection patterns framework-agnostic where possible

## License

MIT
