## Phase 10: Logging, Auditing & Monitoring

**Objective:** Verify security events are logged, auditable, and don't leak sensitive data.

### Checklist

1. Verify all CRUD operations are audit logged (who, what, when)
2. Check that sensitive admin actions have a separate audit trail
3. Verify security events are logged (login failures, rate limit hits, blocked requests)
4. Check that logs don't contain sensitive data (passwords, tokens, PII)
5. Verify log entries include sufficient context (userId, IP, action, resource)
6. Check for log injection vulnerabilities (user input in log messages)
7. Verify that audit logs are tamper-resistant (append-only, not user-editable)
8. Check for alerting on critical security events

### Where to Look

```bash
# Audit logging
grep -r "audit\|logEvent\|logAction\|auditLog\|adminAction" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# General logging
grep -r "console\.log\|console\.error\|logger\.\|log\.\|logging" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Sensitive data in logs
grep -r "console\.log.*password\|console\.log.*token\|console\.log.*secret\|console\.log.*key" --include="*.{js,ts,tsx,py}" | grep -v node_modules

# Security event logging
grep -r "\[SECURITY\]\|blocked\|suspicious\|unauthorized\|forbidden" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// HIGH: No audit logging
async function deleteContact(ctx, args) {
  const contact = await ctx.db.get(args.id);
  await ctx.db.delete(args.id);
  // Who deleted this? When? Why? No record.
}

// HIGH: Logging sensitive data
console.log(`Login attempt: email=${email}, password=${password}`);
console.log(`Session token: ${token}`);
console.log(`API key: ${apiKey}`);

// MEDIUM: No security event logging
if (!rateLimitResult.allowed) {
  return new Response("Too Many Requests", { status: 429 });
  // No log of who hit the rate limit or from where
}

// MEDIUM: User-editable audit logs
async function deleteAuditLog(ctx, args) {
  // Users can delete their own audit trail!
  await ctx.db.delete(args.logId);
}

// LOW: Logs without context
console.log("Unauthorized access attempt");
// Which user? Which endpoint? What IP?
```

### Proper Patterns

```typescript
// GOOD: Structured audit logging for all mutations
async function logAuditEvent(ctx, params) {
  await ctx.db.insert("auditLogs", {
    userId: params.userId,
    action: params.action,        // "create" | "update" | "delete"
    resourceType: params.resourceType,  // "contact" | "invoice" | etc.
    resourceId: params.resourceId,
    details: params.details ? JSON.stringify(params.details) : undefined,
    createdAt: Date.now(),
  });
}

// Usage in every mutation:
async function updateContact(ctx, args) {
  const { userId } = await requireAuth(ctx, args.sessionToken);
  const contact = await ctx.db.get(args.id);
  await requireOwnership(ctx, contact, userId);

  await ctx.db.patch(args.id, { name: args.name });

  await logAuditEvent(ctx, {
    userId,
    action: "update",
    resourceType: "contact",
    resourceId: args.id,
    details: { field: "name", oldValue: contact.name, newValue: args.name },
  });
}

// GOOD: Separate admin action logging with extra context
await ctx.db.insert("adminActions", {
  adminId: adminUser.id,
  adminEmail: adminUser.email,
  targetUserId: args.targetUserId,
  targetResourceType: "user",
  action: "ban_user",
  details: JSON.stringify({
    reason: args.reason,
    expiresAt: banExpiresAt,
    permanent: !args.expiresIn,
    sessionsRevoked: sessions.length,
  }),
  createdAt: Date.now(),
});

// GOOD: Security event logging with context
function logSecurityEvent(method, url, ip, reason) {
  console.log(JSON.stringify({
    level: "SECURITY",
    timestamp: new Date().toISOString(),
    method,
    url,
    ip,
    blocked: true,
    reason,  // "cors_violation" | "rate_limit" | "auth_failure"
  }));
}

// GOOD: Normal request logging (no sensitive data)
function logRequest(method, url, ip, userAgent, statusCode) {
  console.log(JSON.stringify({
    level: "API",
    timestamp: new Date().toISOString(),
    method,
    url,
    ip,
    userAgent,
    statusCode,
    // Note: NO passwords, tokens, or session data logged
  }));
}
```

### Quick Fixes

- Create a shared `logAuditEvent()` function and call it in every mutation
- Add separate admin action logging for sensitive operations
- Log security events (failed logins, rate limit hits, CORS violations) with context
- Audit all `console.log` statements â€” remove any that include passwords, tokens, or keys
- Make audit log tables append-only (no delete/update mutations exposed to users)
- Include userId, IP, timestamp, and action in every security log entry
