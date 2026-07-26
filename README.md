# Security Audit Skill for Claude Code

A phase-based security audit skill for [Claude Code](https://claude.ai/code) that lets you run targeted security reviews on any codebase. Select exactly which security domains to audit — run one phase, a few, or all ten.

Only the phases you select are loaded, so the audit stays focused and your context doesn't fill with material you didn't ask for.

Built and maintained by the team behind [SecuriVibe](https://securivibe.com).

## Install

### macOS / Linux

```bash
git clone --depth 1 https://github.com/JayDoolan/security-audit .claude/skills/security-audit \
  && rm -rf .claude/skills/security-audit/.git
```

### Windows (PowerShell)

```powershell
git clone --depth 1 https://github.com/JayDoolan/security-audit .claude/skills/security-audit
Remove-Item -Recurse -Force .claude/skills/security-audit/.git
```

### Install globally instead

Swap `.claude/skills/security-audit` for `~/.claude/skills/security-audit` (macOS/Linux) or
`$HOME\.claude\skills\security-audit` (Windows) to make it available in every project.

### Updating

Delete the folder and run the install command again.

Commit the folder to your repo if you want everyone on the team to have it.

## Usage

```
/security-audit
```

You'll get a menu. Pick the phases you want:

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

You can also skip the menu by naming the phases up front:

```
/security-audit 1,2,5
/security-audit ALL
```

Or just describe what you care about — "check my auth and look for leaked keys" — and it'll propose the matching phases before running anything.

## Phases

| #  | Phase                              | What It Catches                                                         |
| -- | ---------------------------------- | ----------------------------------------------------------------------- |
| 1  | Secrets & Credentials              | Hardcoded API keys, committed `.env` files, secrets in frontend bundles |
| 2  | Authentication & Sessions          | Session hijacking, missing brute force protection, insecure cookies     |
| 3  | Authorization & Access Control     | Privilege escalation, missing role checks, client-side-only auth        |
| 4  | Data Protection & Tenant Isolation | IDOR vulnerabilities, cross-tenant data leaks, missing ownership checks |
| 5  | Input Validation & Injection       | XSS, SQL injection, command injection, prompt injection                 |
| 6  | API Security & Rate Limiting       | Unprotected endpoints, missing rate limits, enumeration attacks         |
| 7  | Infrastructure & Security Headers  | CORS misconfiguration, missing security headers, clickjacking           |
| 8  | Dependencies & Supply Chain        | Vulnerable packages, outdated dependencies, typosquatting               |
| 9  | Encryption & Key Management        | Weak algorithms, hardcoded keys, IV reuse, poor key lifecycle           |
| 10 | Logging, Auditing & Monitoring     | Missing audit trails, sensitive data in logs, undetected breaches       |

Each phase has its own file under `phases/`, containing an objective, checklist, detection commands, anti-patterns, correct patterns, and quick fixes.

## Severity Levels

| Severity     | Meaning                                         | Action                 |
| ------------ | ----------------------------------------------- | ---------------------- |
| **CRITICAL** | Exploitable now. Immediate data breach risk.    | Fix before next deploy |
| **HIGH**     | Significant vulnerability, clearly exploitable. | Fix this sprint        |
| **MEDIUM**   | Defense gap or weak implementation.             | Fix next sprint        |
| **LOW**      | Hardening opportunity, defense-in-depth.        | Backlog                |

## Report Output

- Which phases ran vs. were skipped
- Findings grouped by phase, with severity, location, evidence, impact, and a fix
- Summary counts by severity
- Prioritised quick wins

## Works With Any Stack

Framework-agnostic. Detection patterns cover JavaScript/TypeScript (Next.js, Express, React, Node), Python (Django, Flask, FastAPI), Go, Ruby, Java, PHP, any SQL or NoSQL database, and any auth framework.

## Repository Layout

```
SKILL.md          # entry point: menu, routing, severity scale, report template
phases/
  01-secrets.md
  02-auth-sessions.md
  …
  10-logging.md
```

To edit a phase, edit its file. To add one, add the file and register it in the routing table in `SKILL.md`.

## What This Skill Is Good For

- Initial security triage of unfamiliar codebases
- Reviewing AI-generated or rapidly prototyped applications
- Targeted audits of specific security domains
- Pre-deployment security checks

## What This Skill Is Not

- A replacement for formal penetration testing
- A compliance audit tool (SOC 2, HIPAA, etc.)
- An automated scanner — it guides Claude's analysis of your specific code
- A deep cryptographic analysis tool

It also doesn't cover the non-code side of shipping: privacy policy, data residency, GDPR/CCPA
deletion paths, bot protection on public forms, or spend caps on paid APIs. Those matter as much as
the code once you have real users.

## Finding Things Is the Easy Part

This skill will tell you what's wrong. Interpreting it and fixing it is the rest of the work — and
that's where most people stall:

- **A long findings list isn't a plan.** Ten MEDIUMs sharing one root cause is one fix, not ten. Knowing which is which takes judgement.
- **Severity isn't the same as urgency.** Whether a HIGH blocks your launch depends on your data, your users, and your exposure — not on the label.
- **Fixes break things.** Adding row-level policies to a live database, or tightening CORS on a production API, will take your app down if done carelessly.
- **A clean scan is not a secure app.** Business logic flaws, broken authorization state, and race conditions don't show up in any checklist, including this one.

If you'd rather not do that part yourself, [SecuriVibe](https://securivibe.com) is the managed
version: connect a repo, get a prioritised report written in plain English, and get the fixes back as
reviewable patches. Built by the same people who wrote this skill.

The skill stays free and MIT-licensed either way. Use it, fork it, ship it in your own product — no
attribution required beyond the licence.

## Contributing

PRs welcome. When adding or modifying phases:

1. Follow the existing per-phase structure (Objective, Checklist, Where to Look, Anti-Patterns, Proper Patterns, Quick Fixes)
2. Include both anti-patterns and proper patterns with code examples
3. Tag all findings with severity levels (CRITICAL/HIGH/MEDIUM/LOW)
4. Keep detection patterns framework-agnostic where possible
5. Register any new phase in the routing table in `SKILL.md`

## License

MIT
