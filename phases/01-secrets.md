## Phase 1: Secrets & Credentials

**Objective:** Find credentials that anyone with repo access, bundle access, or network access can steal.

### Checklist

1. Search for hardcoded API keys, tokens, passwords, and connection strings in source code
2. Check if `.env` files are committed to git (check `.gitignore`)
3. Verify no secrets are exposed in frontend/client bundles
4. Check for secrets in comments, TODOs, or test fixtures
5. Verify `.env.example` contains only placeholders, not real values
6. Check CI/CD configs for inline secrets (vs. secret injection)
7. Look for secrets in Docker files, docker-compose, or infrastructure configs
8. Check for credentials in log output or error messages

### Where to Look

```bash
# Hardcoded secrets in source
grep -r "api_key\|API_KEY\|secret\|SECRET\|password\|PASSWORD\|token\|TOKEN\|private_key\|PRIVATE_KEY" --include="*.{js,ts,tsx,py,java,go,rb,php,env*,yml,yaml,json,config,toml}" | grep -v node_modules | grep -v ".git"

# Frontend exposure (NEXT_PUBLIC_, VITE_, REACT_APP_ prefixed secrets)
grep -r "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*PASSWORD\|VITE_.*SECRET\|REACT_APP_.*SECRET" --include="*.{js,ts,tsx,env*}"

# Git history check
git log --all --diff-filter=A -- "*.env" "*.env.*"

# Check .gitignore
cat .gitignore | grep -i "env\|secret\|key\|credential"

# Config files
find . -name "*.env" -o -name "*.env.*" -o -name "docker-compose*" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: API key hardcoded in source
const OPENAI_API_KEY = "sk-proj-abc123...";

// CRITICAL: Secret in frontend-accessible env var
// .env.local
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc123

// HIGH: Database URL with credentials in source
const DB_URL = "postgresql://admin:password123@db.prod.com/app";

// HIGH: Secret in comment
// TODO: remove before prod â€” test key: sk-test-abc123

// MEDIUM: Real values in .env.example
// .env.example
BETTER_AUTH_SECRET=my-actual-secret-key-here
```

### Proper Patterns

```typescript
// GOOD: All secrets via environment variables
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) throw new Error("OPENAI_API_KEY not configured");

// GOOD: .env.example with placeholders only
// .env.example
// BETTER_AUTH_SECRET=your-secret-here
// CONVEX_DEPLOYMENT=your-deployment-id

// GOOD: Server-only env vars (no NEXT_PUBLIC_ prefix for secrets)
// .env.local
// BETTER_AUTH_SECRET=actual-secret    (server-only)
// RESEND_API_KEY=re_abc123           (server-only)
// NEXT_PUBLIC_CONVEX_URL=https://...  (safe â€” public URL)

// GOOD: .gitignore includes all env files
// .gitignore
// .env
// .env.local
// .env.*.local
```

### Quick Fixes

- Move all hardcoded secrets to environment variables
- Add `.env*` patterns to `.gitignore`
- Replace real values in `.env.example` with placeholders
- Use `NEXT_PUBLIC_` prefix ONLY for non-sensitive values
- If secrets were committed, rotate them immediately (git history retains them)
- Use CI/CD secret injection (GitHub Secrets, Vercel env vars) instead of config files
