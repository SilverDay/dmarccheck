# Security Audit — DMARC Report Analyzer

**Date:** 2026-08-09  
**Scope:** All PHP source under `src/`, `bin/`, and `public/index.php`  
**Method:** Manual code review + automated analysis (CodeQL-class pattern matching)

---

## Summary

| ID | Severity | Component | Title |
|----|----------|-----------|-------|
| F-01 | **Medium** | `AuthController` | Recovery-code TOCTOU race — same code usable twice concurrently |
| F-02 | **Medium** | `TotpService` | No TOTP replay protection — same OTP valid for the full leeway window |
| F-03 | **Medium** | `AuthController` | Timing oracle leaks whether a login email exists |
| F-04 | **Low** | `public/index.php` | No login rate-limiting / brute-force protection |
| F-05 | **Low** | `public/index.php` | Missing `Strict-Transport-Security` response header |
| F-06 | **Low** | `public/index.php` | CSRF token and SealedCookie share the same `app_secret` key material |

No Critical findings were identified. The sections below contain detailed descriptions and remediation advice. A clean-bill section afterwards lists areas that were examined and found sound.

---

## Findings

### F-01 — Recovery-code TOCTOU race (Medium)

**File:** `src/Http/Controllers/AuthController.php` — `consumeRecoveryCode()`  
**Confidence:** High

**Description:**  
Recovery codes are intended to be single-use, but the check-then-consume sequence is not atomic. The method `SELECT`s every recovery code for the user into PHP via `fetchAll()`, matches the submitted code in PHP with `RecoveryCodes::findMatch()`, then issues a separate `UPDATE recovery_codes SET consumed_at = NOW() WHERE id = ?`. Under MySQL/MariaDB's default REPEATABLE READ isolation, two concurrent POST requests to `/login/totp` carrying the same recovery code will both read the same snapshot (both see `consumed_at = NULL`), both match in PHP, and both issue the same idempotent `UPDATE`—returning `true` twice and granting two authenticated sessions from a single code. No row-level lock or conditional `UPDATE` prevents this.

**Evidence:**
- `consumeRecoveryCode()`: `SELECT … fetchAll()` → PHP match → `UPDATE … WHERE id = ?` (three separate statements, no transaction)
- `db/migrations/0001_baseline.sql`: `recovery_codes` table has a per-user index but no unique constraint on `(user_id, code_hash)` and no conditional guard
- `Database::connect()`: PDO initialized with no explicit isolation override; InnoDB defaults to REPEATABLE READ

**Remediation:**  
Replace the SELECT + PHP-match + UPDATE sequence with a single atomic conditional update per code:

```sql
UPDATE recovery_codes
   SET consumed_at = NOW()
 WHERE user_id = ?
   AND code_hash = ?        -- hash the submitted code first
   AND consumed_at IS NULL
```

Check `rowCount() === 1` before treating the code as consumed. Alternatively, wrap the full block in a `BEGIN … COMMIT` with `SELECT … FOR UPDATE` to acquire a row-level lock before the match step.

---

### F-02 — TOTP replay attack (Medium)

**File:** `src/Auth/TotpService.php` — `verifyPlaintext()`  
**Confidence:** High

**Description:**  
There is no used-code tracking for TOTP verification. `verifyPlaintext()` delegates entirely to the OTPHP library's `verify()` with a 15-second leeway. Any valid 6-digit code remains accepted for the full 30-second TOTP step plus the leeway on each side — up to ~60 seconds during which the same code verifies successfully on every attempt. NIST SP 800-63B §5.1.3.2 requires that an authenticator "SHALL NOT accept a given OTP code … if the code has already been accepted."

An attacker who intercepts or observes a valid `{code, userId}` pair during that window can establish an independent authenticated session without requiring the victim's device again. This is distinct from the recovery-code TOCTOU (F-01): that is a race under concurrency; this is a replay that works even sequentially.

**Evidence:**
- `TotpService::verifyPlaintext()`: calls `TOTP::createFromSecret($secret)->verify($code, null, self::LEEWAY_SECONDS)` with no subsequent tracking
- `recovery_codes` has `consumed_at` showing the application already applies single-use semantics to backup codes; TOTP codes have no equivalent
- No `used_totp_codes` table or TTL cache exists in any migration

**Remediation:**  
After a successful TOTP `verify()` call, record the validated `{user_id, totp_period_counter}` in a short-lived table (TTL = leeway window × 2) or a fast cache (Redis/Memcached). Reject verification if the same period counter has already been accepted for that user. The period counter for a 30-second step TOTP is `floor(time() / 30)`.

---

### F-03 — Timing oracle for email enumeration at login (Medium)

**File:** `src/Http/Controllers/AuthController.php` — `login()`  
**Confidence:** Medium

**Description:**  
The login condition short-circuits:

```php
if ($user === null || !$user->isActive() || !$user->hasPassword()
                   || !$this->hasher->verify($password, (string) $user->credentialHash)
) { … }
```

When `$user === null` (email does not exist), `$this->hasher->verify()` is never called and the response returns immediately after the fast DB miss. When the user exists but the password is wrong, `password_verify()` runs Argon2id — deliberately ~100 ms. An attacker issuing many login attempts can distinguish "no such email" (consistently fast, ~5 ms) from "wrong password" (consistently slow, ~100–150 ms) by timing the response, enabling reliable email enumeration against the invitation-only user list.

**Evidence:**
- `AuthController::login()`: `|| !$this->hasher->verify(…)` is only reached when all earlier conditions are false; a null user exits the condition immediately
- `PasswordHasher::hash()` uses `PASSWORD_ARGON2ID` which is intentionally slow; the wall-clock difference is measurable without special equipment

**Remediation:**  
When the user is not found (or is not a password user), still call `password_verify()` against a dummy constant hash to consume an equivalent amount of time:

```php
// Constant-time fallback — prevents timing-based user enumeration
private const string DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$…'; // pre-generated once

public function login(): void
{
    $email    = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $user     = $this->users->findByEmail($email);

    $hashToVerify = $user !== null && $user->hasPassword()
        ? (string) $user->credentialHash
        : self::DUMMY_HASH;

    $passwordOk = $this->hasher->verify($password, $hashToVerify);

    if ($user === null || !$user->isActive() || !$user->hasPassword() || !$passwordOk) {
        $this->renderLoginForm('Invalid email or password.', $email);
        return;
    }
    …
}
```

---

### F-04 — No brute-force / rate-limiting on the login endpoint (Low)

**File:** `public/index.php` (route wiring), `src/Http/Controllers/AuthController.php`  
**Confidence:** High

**Description:**  
The application provides `SenderRateLimiter` for IMAP-ingest protection but has no equivalent for the web login form (`POST /login`) or the TOTP step (`POST /login/totp`). A remote attacker can submit unlimited authentication attempts at whatever rate the server sustains, enabling:

- Credential stuffing against the invitation-only user list
- Dictionary / brute-force attacks against passwords and 6-digit TOTP codes (10⁶ space)

The existing Argon2id hashing (~100 ms per attempt) limits throughput to roughly 10 guesses/second per connection, which provides some natural friction but not a meaningful cap against a distributed attack.

**Remediation:**  
Implement server-side rate limiting keyed on (source IP, endpoint). Pragmatic approaches include:
1. A database-backed counter table similar to `ingest_sender_counters` (already in the codebase), sliding or fixed window per IP
2. An Apache / nginx `mod_ratelimit` / `limit_req` directive at the web-server layer
3. A lightweight middleware class that increments a counter in APCu or a cache before the controller runs

Lockout or CAPTCHA after N failures per IP per window (e.g. 5 failures / 5 min) is the standard posture for an invite-only application.

---

### F-05 — Missing `Strict-Transport-Security` header (Low)

**File:** `public/index.php`  
**Confidence:** High

**Description:**  
The front controller sends four security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`) but not `Strict-Transport-Security` (HSTS). The config already detects HTTPS from `app.base_url` to set `Secure` cookies:

```php
$secureCookie = str_starts_with($baseUrl, 'https://');
```

Without HSTS, browsers connecting over HTTP will not be automatically upgraded to HTTPS, and an active network attacker can intercept the first request on a new machine or after cookie expiry to perform SSL stripping.

**Remediation:**  
Add HSTS conditionally alongside the existing security headers:

```php
if ($secureCookie) {
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains');
}
```

A `max-age` of at least one year (31536000) is the common minimum recommendation. Consider adding `; preload` and submitting to the HSTS preload list once the policy is stable.

---

### F-06 — CSRF token and SealedCookie share the same `app_secret` (Low)

**File:** `public/index.php`  
**Confidence:** Medium

**Description:**  
Both `Csrf` and `SealedCookie` are constructed with the same `app.app_secret`:

```php
$csrf   = new Csrf((string) $config->require('app.app_secret'));
$sealed = new SealedCookie((string) $config->require('app.app_secret'), $secureCookie);
```

`Csrf` derives `hash_hmac('sha256', $sessionToken, $appSecret)`. `SealedCookie` derives a 32-byte key via `sodium_crypto_generichash($purpose . ':' . $appSecret)`. Both derivations are purpose-tagged, so no practical cross-protocol attack is known from this configuration. However, sharing raw secret material across components is contrary to the principle of key separation and may complicate future security reviews. The TOTP component (`TotpService`) already uses a correctly separate `app.totp_encryption_key`, setting a good precedent that is not followed here.

**Remediation:**  
Split `app_secret` into two distinct config keys, e.g.:

```php
'csrf_secret'          => '…',   // for Csrf
'cookie_seal_secret'   => '…',   // for SealedCookie
```

Generate each independently with `php -r "echo base64_encode(random_bytes(32));"`. Update `config.sample.php` accordingly.

---

## Areas Examined and Found Sound

The following were reviewed and no actionable findings were identified:

| Area | Verdict |
|------|---------|
| **SQL injection** | All database queries use PDO prepared statements with bound parameters throughout. The one dynamically composed query in `DomainController::fetchSourceRows()` uses a `match` expression to map user input to a fixed allow-list of column expressions before interpolation—not raw user input. |
| **XSS** | `View::e()` (wrapping `htmlspecialchars(ENT_QUOTES, UTF-8)`) is applied consistently to all database-sourced and user-supplied values before HTML output in every controller. The `Content-Security-Policy: default-src 'self'` header provides additional defence-in-depth. |
| **Shell injection (`dig`)** | `SystemDigLookup::query()` uses `escapeshellarg()` on all three variable arguments (`$type`, `$name`, `$this->resolver`) and `%d` for the integer timeout. No user-controlled value reaches `exec()` unescaped. |
| **Path traversal / Decompressor** | `Decompressor` uses `tempnam(sys_get_temp_dir(), 'dmarc_')` for ZIP processing; the resulting path is OS-generated and not influenced by attachment filenames or Content-Type. The archive filename is separately derived from a content hash in `bin/ingest.php`, not from the attacker-controlled attachment filename. |
| **Decompression bombs** | Gzip is inflated through `inflate_add()` in 32 KB chunks with a per-chunk ceiling check. ZIP entries are capped by both declared size and actual read size. Both caps are enforced before the full payload is materialised. |
| **XXE / XML injection** | `ReportParser` does not pass `LIBXML_NOENT` or `LIBXML_DTDLOAD`, detects and enables `LIBXML_NO_XXE` on PHP 8.4+, and rejects any DOCTYPE declaration outright. |
| **CSRF** | All authenticated state-changing routes go through `AuthMiddleware::guardPost()`, which verifies the HMAC synchronizer token before the handler runs. Cookies are `SameSite=Strict`. |
| **Session management** | Session tokens are stored only as SHA-256 hashes in the database. Cookies are `HttpOnly`, `Secure` (when HTTPS), `SameSite=Strict`. Both idle and absolute timeouts are enforced on every lookup with immediate deletion on expiry. |
| **Password hashing** | Argon2id via PHP's `password_hash(PASSWORD_ARGON2ID)`. Minimum length enforced (12 chars); no composition rules that could reduce entropy. |
| **TOTP secret at rest** | TOTP secrets are stored encrypted with XSalsa20-Poly1305 (`sodium_crypto_secretbox`) under a dedicated key (`app.totp_encryption_key`) derived independently of `app_secret`. |
| **Invitation tokens / password-reset tokens** | Only SHA-256 hashes are stored; raw tokens exist only in the emailed link. `InvitationService` invalidates prior pending tokens on re-issue. `PasswordResetService` enforces a cap (3) on outstanding tokens per user. |
| **IDOR on report detail** | `DomainController::reportDetail()` fetches the report with `WHERE report_id = ? AND domain_id = ?` in a single query; a report belonging to a different domain simply returns no rows (404) rather than requiring a separate ownership check after the fact. |
| **Audit log** | `AuditLog` uses INSERT-only access; the recommended DB grant is `INSERT, SELECT` with no `UPDATE`/`DELETE`, making the trail append-only in practice. |
| **Redirect destinations** | All `header('Location: …')` targets are hardcoded relative paths; no user-supplied URL is ever used as a redirect destination. |
