## Phase 2: Authentication & Sessions

**Objective:** Find paths to impersonate users, hijack sessions, or bypass login.

### Checklist

1. Verify session tokens are validated server-side on every protected request
2. Check session expiration is enforced (not just set)
3. Verify cookies use `httpOnly`, `secure`, and `sameSite` flags
4. Check for brute force protection on login endpoints
5. Verify password hashing uses a strong algorithm (bcrypt, scrypt, argon2) with adequate cost
6. Check password reset flow for predictable tokens and proper expiration
7. Verify OAuth state parameter is validated (CSRF in OAuth flow)
8. Check that failed login attempts don't leak user existence
9. Verify sessions are invalidated on password change and logout
10. Check for session fixation vulnerabilities

### Where to Look

```bash
# Authentication code
grep -r "login\|signIn\|sign_in\|authenticate\|session\|jwt\|token" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Session/cookie handling
grep -r "cookie\|httpOnly\|secure\|sameSite\|maxAge\|expires" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Password handling
grep -r "bcrypt\|scrypt\|argon2\|hash.*password\|password.*hash\|pbkdf2" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Login attempt tracking
grep -r "attempt\|lockout\|brute\|throttle.*login\|rate.*login" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: No server-side session validation
app.get('/api/profile', (req, res) => {
  const userId = req.query.userId; // Trust client-provided identity!
  return db.getProfile(userId);
});

// CRITICAL: JWT without expiration check
const decoded = jwt.decode(token); // decode, not verify!
return decoded.userId;

// HIGH: No brute force protection
app.post('/login', (req, res) => {
  // Unlimited login attempts allowed
  if (checkPassword(req.body.email, req.body.password)) {
    createSession();
  }
});

// HIGH: Insecure cookie flags
res.cookie('session', token, {
  httpOnly: false,  // Accessible to JavaScript â€” XSS can steal it
  secure: false,    // Sent over HTTP â€” network sniffing
  sameSite: 'none', // No CSRF protection
});

// MEDIUM: User existence leak
if (!user) return res.status(404).json({ error: "User not found" });
if (!validPassword) return res.status(401).json({ error: "Wrong password" });
// Attacker can enumerate valid emails
```

### Proper Patterns

```typescript
// GOOD: Server-side session validation with expiry + ban check
async function requireAuth(ctx, sessionToken) {
  if (!sessionToken) throw new Error("Unauthorized");

  const session = await ctx.db.query("sessions")
    .withIndex("by_token", (q) => q.eq("token", sessionToken))
    .unique();

  if (!session) throw new Error("Unauthorized");
  if (session.expiresAt < Date.now()) throw new Error("Unauthorized");

  const user = await ctx.db.query("users")
    .withIndex("by_auth_id", (q) => q.eq("id", session.userId))
    .unique();

  if (!user) throw new Error("Unauthorized");
  if (user.banned) throw new Error("Unauthorized: Account is suspended");

  return { userId: session.userId, user };
}

// GOOD: Brute force protection with lockout
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

async function recordFailedAttempt(email) {
  const record = await getAttempts(email.toLowerCase());

  if (!record) {
    await insertAttempt({ email: email.toLowerCase(), attempts: 1 });
    return { locked: false, attemptsRemaining: MAX_ATTEMPTS - 1 };
  }

  // Reset if previous lockout expired
  if (record.lockedUntil && record.lockedUntil <= Date.now()) {
    await resetAttempts(record.id);
    return { locked: false, attemptsRemaining: MAX_ATTEMPTS - 1 };
  }

  const newAttempts = record.attempts + 1;
  if (newAttempts >= MAX_ATTEMPTS) {
    await lockAccount(record.id, Date.now() + LOCKOUT_DURATION_MS);
    return { locked: true, attemptsRemaining: 0 };
  }

  await incrementAttempts(record.id, newAttempts);
  return { locked: false, attemptsRemaining: MAX_ATTEMPTS - newAttempts };
}

// GOOD: Clear attempts on successful login
async function onLoginSuccess(email) {
  await clearAttempts(email.toLowerCase());
}

// GOOD: Consistent error messages that don't leak user existence
if (!user || !validPassword) {
  return res.status(401).json({ error: "Invalid credentials" });
}

// GOOD: Password hashing with strong algorithm
// bcrypt with cost factor 12 (recommended minimum: 10)
const hash = await bcrypt.hash(password, 12);

// GOOD: Session configuration with secure defaults
{
  session: {
    expiresIn: 30 * 60,    // 30 minutes
    updateAge: 5 * 60,     // Refresh every 5 minutes
    cookieCache: { enabled: true },
  },
  advanced: {
    useSecureCookies: process.env.NODE_ENV === "production",
  }
}
```

### Quick Fixes

- Add server-side session validation to every protected endpoint
- Set `httpOnly: true`, `secure: true`, `sameSite: 'lax'` on all session cookies
- Implement login attempt tracking with lockout (5 attempts, 15-min lockout)
- Use bcrypt/scrypt/argon2 with adequate cost factor (bcrypt: 12+)
- Return generic "Invalid credentials" for both wrong email and wrong password
- Set session expiration and enforce it server-side
- Invalidate all sessions on password change
