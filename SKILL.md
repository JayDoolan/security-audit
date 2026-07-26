---
name: security-audit
description: Phase-based security audit with selectable phases — covers secrets, auth, authorization, data protection, input validation, rate limiting, headers, dependencies, encryption, and audit logging. Runs only the phases requested, loading each phase's detection guidance on demand. Use when reviewing a codebase for vulnerabilities, triaging an unfamiliar repo, or checking a specific security domain before deploy.
---

# Security Audit — Phase-Based Review

A phase-based security audit for modern full-stack applications. **Select exactly which security
domains to audit** — run one phase, a few, or all ten.

Each phase lives in its own file under `phases/`. Only the selected phases are read, so the audit
stays focused and the irrelevant material never enters context.

## How this skill works

### Step 1 — Determine the selection

Resolve the selection in this order. Stop at the first that applies.

1. **Explicit numbers in the invocation.** If phase numbers or the word `ALL` appear anywhere in the invoking message (e.g. `/security-audit 1,2,5`), use them. Do not show the menu.
2. **A named domain in the invocation.** If the user asked for something like "check my auth" or "look for leaked keys", map it to the matching phases using the Quick Reference table below, then state which phases you selected and ask for confirmation before proceeding. Do not silently expand scope.
3. **Nothing specified, interactive session.** Present the menu below verbatim and end your turn. Do not begin any phase until the user replies.
4. **Nothing specified, non-interactive session** (headless, scripted, or running as a subagent, where no reply is possible). Run `ALL`, and state at the top of the report that no selection was given and full coverage was assumed.

### The menu

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

### Step 2 — Load only the selected phases

Read the file for each selected phase, and only those files:

| # | Phase | File |
|---|---|---|
| 1 | Secrets & Credentials | `phases/01-secrets.md` |
| 2 | Authentication & Sessions | `phases/02-auth-sessions.md` |
| 3 | Authorization & Access Control | `phases/03-authorization.md` |
| 4 | Data Protection & Tenant Isolation | `phases/04-data-protection.md` |
| 5 | Input Validation & Injection Prevention | `phases/05-input-validation.md` |
| 6 | API Security & Rate Limiting | `phases/06-api-security.md` |
| 7 | Infrastructure & Security Headers | `phases/07-infrastructure.md` |
| 8 | Dependencies & Supply Chain | `phases/08-dependencies.md` |
| 9 | Encryption & Key Management | `phases/09-encryption.md` |
| 10 | Logging, Auditing & Monitoring | `phases/10-logging.md` |

Each phase file contains its own objective, checklist, detection commands, anti-patterns, proper
patterns, and quick fixes. Work through them in ascending order.

### Step 3 — Report

Generate a phase-aware report using the template at the end of this file.

---

## Severity classification

Use these tags consistently across all findings.

| Severity | Meaning | Action |
|---|---|---|
| **CRITICAL** | Exploitable now. Immediate data breach or account takeover risk. | Fix before next deploy |
| **HIGH** | Significant vulnerability. Requires attacker effort but clearly exploitable. | Fix this sprint |
| **MEDIUM** | Defense gap. Missing security layer or weak implementation. | Fix next sprint |
| **LOW** | Hardening opportunity. Defense-in-depth improvement. | Backlog |

## Finding format

Report each finding using this format:

````markdown
### [SEVERITY] Finding Title

**Phase:** N — Phase Name
**Location:** `file/path.ts:line`
**CWE:** CWE-XXX (if applicable)

**Issue:** One-paragraph description of the vulnerability.

**Evidence:**
```language
// The vulnerable code
```

**Impact:** What an attacker can do if this is exploited.

**Fix:**
```language
// The corrected code
```
````

**Group findings by root cause.** Several symptoms of one underlying flaw are one finding, not
several. Inflated counts bury the severe items.

## Report template

````markdown
# Security Audit Report

**Date:** YYYY-MM-DD
**Project:** [Project Name]
**Stack:** [Framework, database, auth, etc.]

## Phases Completed

- [x] Phase 1: Secrets & Credentials
- [x] Phase 2: Authentication & Sessions
- [ ] Phase 3: Authorization & Access Control _(skipped)_
...

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | X     |
| HIGH     | Y     |
| MEDIUM   | Z     |
| LOW      | W     |

## Findings

### Phase 1: Secrets & Credentials

[Findings using the format above]

...

## Quick Wins (Priority Order)

1. [Most impactful fix]
2. ...

## Phases Not Run

The following phases were not included. Consider running them for complete coverage:
- Phase 3: Authorization & Access Control
- ...
````

## Quick reference

Use this to map a named concern onto phase numbers when the user describes a domain rather than
selecting one.

| Phase | Key question | Primary risk | Maps from |
|---|---|---|---|
| 1. Secrets | Are credentials in source or bundles? | Credential theft | keys, tokens, `.env`, leaked secrets |
| 2. Auth & Sessions | Can someone bypass login or hijack sessions? | Account takeover | login, session, cookies, passwords, JWT |
| 3. Authorization | Can users escalate privileges? | Privilege escalation | roles, admin, permissions |
| 4. Data Protection | Can users access other users' data? | Data breach (IDOR) | tenancy, IDOR, ownership, multi-tenant |
| 5. Input Validation | Can user input execute code or inject content? | XSS, SQLi, RCE | injection, XSS, sanitisation, prompt injection |
| 6. API Security | Can APIs be abused without limits? | DoS, enumeration | rate limits, endpoints, webhooks, pagination |
| 7. Infrastructure | Are security headers and CORS configured? | Clickjacking, MIME attacks | headers, CORS, CSP, HTTPS |
| 8. Dependencies | Are packages current and trusted? | Supply chain compromise | packages, CVEs, npm audit, lockfile |
| 9. Encryption | Is encryption strong with proper key management? | Data exposure | crypto, keys, AES, hashing |
| 10. Audit & Logging | Are security events tracked without leaking data? | Undetected breaches | logs, audit trail, monitoring |
