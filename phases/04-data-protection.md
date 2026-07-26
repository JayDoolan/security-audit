## Phase 4: Data Protection & Tenant Isolation

**Objective:** Find endpoints where changing an ID leaks or modifies another user's data.

### Checklist

1. Verify every data query filters by authenticated user's ID
2. Check that record IDs in URLs/params are validated against ownership
3. Verify list/search endpoints don't return cross-tenant data
4. Check for IDOR (Insecure Direct Object Reference) on all CRUD endpoints
5. Verify that batch/bulk operations respect ownership
6. Check GraphQL resolvers for missing tenant filters
7. Verify that related resources (comments, attachments) inherit parent's access control
8. Check for data leaks in error messages or logs

### Where to Look

```bash
# Data access patterns
grep -r "findById\|findOne\|get.*Id\|query.*id\|db\.get\|db\.query" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# API endpoints accepting IDs
grep -r "params\.\|req\.query\.\|req\.body\.\|args\." --include="*.{js,ts,tsx,py,go,rb,php}" | grep -i "id\|userId" | grep -v node_modules

# Ownership checks
grep -r "userId.*===\|userId.*==\|owner\|requireOwnership" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Schema indexes (for tenant isolation)
grep -r "by_user\|userId.*index\|tenant" --include="*.{js,ts,tsx}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: No ownership check â€” any user can access any record
app.get('/api/orders/:orderId', (req, res) => {
  const order = await db.get(req.params.orderId);
  return res.json(order); // Returns ANY order!
});

// CRITICAL: Client-controlled userId filter
app.get('/api/transactions', (req, res) => {
  const transactions = await db.query("transactions")
    .filter(t => t.userId === req.query.userId) // Attacker controls userId!
    .collect();
  return res.json(transactions);
});

// HIGH: Missing tenant filter on list endpoint
async function listContacts(ctx) {
  return await ctx.db.query("contacts").collect(); // Returns ALL users' contacts!
}

// MEDIUM: Leaking data in error messages
if (!record) {
  throw new Error(`Invoice #${invoiceId} belongs to user ${record.userId}`);
  // Leaks internal userId
}
```

### Proper Patterns

```typescript
// GOOD: Ownership validation helper
async function requireOwnership(ctx, record, authenticatedUserId) {
  if (!record) throw new Error("Not found");
  if (record.userId !== authenticatedUserId) throw new Error("Forbidden");
}

// GOOD: Every query scoped by authenticated userId
async function listContacts(ctx, args) {
  const { userId } = await requireAuth(ctx, args.sessionToken);
  return await ctx.db.query("contacts")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .collect();
}

// GOOD: Record access with ownership check
async function getInvoice(ctx, args) {
  const { userId } = await requireAuth(ctx, args.sessionToken);
  const invoice = await ctx.db.get(args.invoiceId);
  await requireOwnership(ctx, invoice, userId);
  return invoice;
}

// GOOD: Schema design with userId index on every tenant table
// Every user-facing table includes:
//   userId: v.string(),
// With index:
//   .index("by_user", ["userId"])
// This enforces tenant isolation at the data layer

// GOOD: Generic error messages
if (!record) throw new Error("Not found");
// Don't reveal whether the record exists but belongs to another user
```

### Quick Fixes

- Add userId filter to every query that returns user data
- Create a shared `requireOwnership()` helper and use it consistently
- Add `by_user` indexes to all user-facing tables
- Always derive userId from the authenticated session, never from request params
- Return generic "Not found" (not "Forbidden") to avoid revealing record existence
- Audit all API endpoints that accept record IDs â€” each needs an ownership check
