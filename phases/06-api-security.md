## Phase 6: API Security & Rate Limiting

**Objective:** Find unprotected endpoints, missing rate limits, and API abuse vectors.

### Checklist

1. Verify all API endpoints require authentication (unless explicitly public)
2. Check for rate limiting on authentication endpoints (login, signup, password reset)
3. Check for rate limiting on data mutation endpoints
4. Verify rate limit responses include proper headers (429, Retry-After)
5. Check for enumeration attacks (user listing, ID brute-forcing)
6. Verify webhook endpoints validate signatures
7. Check for mass assignment vulnerabilities (accepting unexpected fields)
8. Verify pagination limits are enforced (can't request 10,000 records)

### Where to Look

```bash
# Rate limiting
grep -r "rate.*limit\|throttle\|RateLimiter\|rateLimit\|429\|too.*many" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# API routes
find . -path "*/api/*" -name "*.ts" -o -path "*/api/*" -name "*.js" | grep -v node_modules

# Webhook handlers
grep -r "webhook\|signature\|verify.*hmac\|stripe.*event" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Pagination
grep -r "take\|limit\|offset\|page.*size\|per_page" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// HIGH: No rate limiting on login
app.post('/login', (req, res) => {
  // Unlimited attempts â€” brute force away!
  authenticate(req.body.email, req.body.password);
});

// HIGH: No rate limiting on mutations
app.post('/api/contacts', (req, res) => {
  // Attacker can create millions of records
  await db.insert("contacts", req.body);
});

// MEDIUM: No pagination limit
app.get('/api/records', (req, res) => {
  const limit = parseInt(req.query.limit); // User sends limit=999999
  return db.query("records").take(limit);
});

// MEDIUM: Webhook without signature validation
app.post('/api/webhooks/stripe', (req, res) => {
  // Anyone can POST fake events!
  processPayment(req.body);
});
```

### Proper Patterns

```typescript
// GOOD: Two-tier rate limiting

// Tier 1: API-level per-IP rate limiting
class RateLimiter {
  private store = new Map();

  check(key, limit, windowMs) {
    const now = Date.now();

    // Periodic cleanup of stale entries
    if (now - this.lastCleanup > 60_000) {
      this.cleanup(now);
    }

    const entry = this.store.get(key);
    if (!entry || now >= entry.resetAt) {
      this.store.set(key, { count: 1, resetAt: now + windowMs });
      return { allowed: true, remaining: limit - 1 };
    }

    entry.count++;
    if (entry.count > limit) {
      return { allowed: false, remaining: 0, resetAt: entry.resetAt };
    }

    return { allowed: true, remaining: limit - entry.count };
  }
}

// Usage: 100 requests per 60 seconds per IP
const limiter = new RateLimiter();
const result = limiter.check(clientIP, 100, 60_000);
if (!result.allowed) {
  return new Response("Too Many Requests", { status: 429 });
}

// Tier 2: Mutation-level per-user rate limiting via audit logs
async function checkMutationRateLimit(ctx, userId) {
  const windowMs = 60_000;
  const limit = 100;
  const since = Date.now() - windowMs;

  const recentActions = await ctx.db.query("auditLogs")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .filter((q) => q.gte(q.field("createdAt"), since))
    .collect();

  if (recentActions.length >= limit) {
    throw new Error("Rate limit exceeded");
  }
}

// GOOD: Pagination with enforced limits
const MAX_PAGE_SIZE = 100;
const limit = Math.min(args.limit || 20, MAX_PAGE_SIZE);
const results = await db.query("records").take(limit);
```

### Quick Fixes

- Add per-IP rate limiting to all API routes (100 req/min is a reasonable default)
- Add per-user rate limiting to mutation endpoints
- Enforce maximum pagination limits (never let clients request unlimited records)
- Return 429 status with Retry-After header when rate limited
- Validate webhook signatures before processing
- Add authentication to all non-public endpoints
