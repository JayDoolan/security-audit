## Phase 7: Infrastructure & Security Headers

**Objective:** Find missing security headers, CORS misconfigurations, and transport security gaps.

### Checklist

1. Check for security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy
2. Check for Content-Security-Policy (CSP) header
3. Verify CORS configuration is not overly permissive
4. Check that CORS doesn't allow `*` with credentials
5. Verify HTTPS enforcement in production
6. Check for Strict-Transport-Security (HSTS) header
7. Verify CORS preflight is properly handled
8. Check for exposed server/framework version headers

### Where to Look

```bash
# Security headers
grep -r "X-Content-Type\|X-Frame-Options\|Content-Security-Policy\|Referrer-Policy\|Strict-Transport" --include="*.{js,ts,tsx,py,go,config}" | grep -v node_modules

# CORS configuration
grep -r "cors\|CORS\|Access-Control\|origin\|allowedOrigins" --include="*.{js,ts,tsx,py,go,rb,php,config}" | grep -v node_modules

# Next.js/framework config
find . -name "next.config.*" -o -name "nuxt.config.*" -o -name "vite.config.*" | grep -v node_modules

# Middleware
find . -name "middleware.*" -o -name "proxy.*" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: CORS allows all origins with credentials
app.use(cors({
  origin: '*',           // Any website can make requests!
  credentials: true,     // With the user's cookies!
}));

// HIGH: No security headers
// next.config.ts has no headers() configuration

// MEDIUM: Missing CSP header
// No Content-Security-Policy â€” allows inline scripts, any source

// MEDIUM: Missing X-Frame-Options
// Page can be embedded in iframes â€” clickjacking risk
```

### Proper Patterns

```typescript
// GOOD: Security headers on all routes (Next.js example)
// next.config.ts
async headers() {
  return [
    {
      source: "/:path*",
      headers: [
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      ],
    },
    {
      source: "/api/:path*",
      headers: [
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      ],
    },
  ];
}

// GOOD: CORS with explicit origin whitelist
const ALLOWED_ORIGINS = [
  "http://localhost:3000",       // Development
  "https://yourdomain.com",     // Production
];

function handleCORS(req) {
  const origin = req.headers.get("origin");
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
    return new Response("Forbidden", { status: 403 });
  }

  const headers = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400", // Cache preflight for 24 hours
  };

  // Handle preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  return headers;
}
```

### Quick Fixes

- Add security headers via framework config (Next.js `headers()`, Express `helmet`)
- Replace `origin: '*'` with explicit origin whitelist
- Never combine `origin: '*'` with `credentials: true`
- Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing
- Add `X-Frame-Options: DENY` to prevent clickjacking
- Add `Referrer-Policy: strict-origin-when-cross-origin`
- Consider adding Content-Security-Policy for XSS mitigation
