## Phase 9: Encryption & Key Management

**Objective:** Find weak encryption, exposed keys, and insecure key management.

### Checklist

1. Verify encryption algorithm is modern and strong (AES-256-GCM, not ECB or DES)
2. Check that encryption keys are properly derived (PBKDF2 100k+ iterations, or argon2)
3. Verify IVs/nonces are random and unique per operation (never reused)
4. Check that encryption keys are not hardcoded
5. Verify key storage is appropriate (not in plaintext config)
6. Check for proper key lifecycle (generation, rotation, destruction)
7. Verify encrypted data format handles IV + ciphertext separation
8. Check for use of deprecated/weak algorithms (MD5, SHA1 for security, DES, RC4)
9. Verify key material is cleared from memory when no longer needed

### Where to Look

```bash
# Encryption code
grep -r "encrypt\|decrypt\|cipher\|AES\|RSA\|crypto\|subtle" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Key management
grep -r "generateKey\|deriveKey\|importKey\|exportKey\|PBKDF2\|argon2\|scrypt" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Weak algorithms
grep -r "MD5\|SHA1\|DES\|RC4\|ECB\|createCipher(" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# IV/nonce handling
grep -r "iv\|nonce\|randomBytes\|getRandomValues" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: Hardcoded encryption key
const ENCRYPTION_KEY = "my-secret-encryption-key-12345";

// CRITICAL: ECB mode (patterns in plaintext visible in ciphertext)
const cipher = crypto.createCipher('aes-128-ecb', key);

// HIGH: Static/reused IV
const iv = Buffer.from("1234567890123456"); // Same IV every time!
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// HIGH: Weak key derivation
const key = crypto.createHash('sha256').update(password).digest();
// No salt, no iterations â€” vulnerable to rainbow tables

// MEDIUM: MD5 for integrity
const hash = crypto.createHash('md5').update(data).digest('hex');
// MD5 has known collisions
```

### Proper Patterns

```typescript
// GOOD: AES-256-GCM with random IV per operation
async function encryptData(text, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // Random 12-byte IV

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  // Store IV alongside ciphertext (needed for decryption)
  const ivStr = arrayBufferToBase64(iv);
  const encryptedStr = arrayBufferToBase64(new Uint8Array(encrypted));
  return `${ivStr}:${encryptedStr}`;
}

// GOOD: Strong key derivation with PBKDF2
async function deriveKeyFromPassword(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt), // Unique salt per user
      iterations: 100000,                   // 100k iterations minimum
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// GOOD: Key lifecycle management
const STORAGE_KEY = "app_master_key";

// Initialize on login (derive from password)
async function initializeEncryptionKey(password, userId) {
  const key = await deriveKeyFromPassword(password, userId);
  const exported = await exportKey(key);
  localStorage.setItem(STORAGE_KEY, exported);
  return key;
}

// Retrieve during session
async function getEncryptionKey() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) return await importKey(stored);
  return null; // Needs re-initialization
}

// Clear on logout
function clearEncryptionKey() {
  cachedKey = null;
  localStorage.removeItem(STORAGE_KEY);
}
```

### Quick Fixes

- Replace ECB mode with GCM (authenticated encryption)
- Generate random IVs for every encryption operation
- Use PBKDF2 with 100k+ iterations (or argon2id) for password-derived keys
- Use unique salts per user (userId works well)
- Never hardcode encryption keys
- Clear keys from memory/storage on logout
- Replace MD5/SHA1 with SHA-256+ for any security-sensitive hashing
