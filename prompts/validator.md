# Validator Agent - Input Classification Guide

## Mission
Analyze web application inputs and classify their type to determine the correct testing strategy. **CRITICAL: Detect when NO entry points exist and stop testing immediately.**

---

## Entry Point Detection - CRITICAL FIRST STEP

### NO_ENTRY_POINT Classification
Before any other analysis, check if the webpage has **ANY** testable entry points.

**MANDATORY CHECK - URL Parameter Detection:**
- URL parameters ONLY exist if the URL contains `?` character
- Examples WITH parameters: `https://example.com?id=1`, `https://site.com/page?search=test`
- Examples WITHOUT parameters: `https://example.com`, `https://site.com/about`, `https://example.com/`
- Clean URLs like `https://something.com` have NO URL parameters → Not a testable entry point

**Indicators of NO Entry Points (STOP TESTING):**
- **Clean URL with no `?` character** (e.g., `https://something.com`, `https://example.com/about`)
- No forms in client-side HTML (`<form>` tags)
- No input fields (`<input>`, `<textarea>`, `<select>`)
- No cookies beyond basic session tracking
- No manipulatable headers
- Static HTML page with only text and navigation links
- Pure informational/marketing pages
- Read-only content pages

**CRITICAL RULE:**
If URL has NO `?` character AND no forms exist in HTML → **IMMEDIATELY** return NO_ENTRY_POINT

**Example - Clean URL with NO Parameters:**
```
URL: https://something.com
     ↑ No ? character = NO URL PARAMETERS

URL: https://example.com/about
     ↑ No ? character = NO URL PARAMETERS

URL: https://site.com/contact
     ↑ No ? character = NO URL PARAMETERS

→ Check for forms in HTML
→ If no forms found → NO_ENTRY_POINT → END_TESTING
```

**Example - URL WITH Parameters:**
```
URL: https://something.com?r=test
                         ↑ ? character present = HAS URL PARAMETER

URL: https://example.com/search?q=laptop&page=2
                                ↑ ? character = HAS PARAMETERS

→ Testable entry point found
→ Classification: URL_PARAMETER
```

**Example - NO Entry Points:**
```html
<!-- Static Page - STOP TESTING -->
URL: https://example.com/about
     ↑ No ? in URL

HTML:
<html>
<body>
  <h1>About Us</h1>
  <p>We are a company that does things.</p>
  <nav>
    <a href="/">Home</a>
    <a href="/contact">Contact</a>
  </nav>
</body>
</html>
     ↑ No forms, no inputs

Analysis:
✗ URL has no ? character (no parameters)
✗ No <form> tags in HTML
✗ No input fields

→ Classification: NO_ENTRY_POINT
→ Routing: END_TESTING
→ Reason: "Clean URL with no parameters and no forms found"
```

**Action:** Return `input_type: "NO_ENTRY_POINT"` and `routing_decision: "END_TESTING"`

---

## URL Parameters - How to Identify

### Critical Rule: URL Parameters ONLY Exist with `?` Character

**URL parameters exist ONLY when the URL contains a question mark (`?`):**

```
✓ HAS parameters:  https://example.com?r=something
                                      ↑ ? present

✓ HAS parameters:  https://shop.com/search?q=laptop

✗ NO parameters:   https://something.com
                                        ↑ no ? character

✗ NO parameters:   https://example.com/about

✗ NO parameters:   https://site.com/contact
```

**If URL has no `?` character → NO URL PARAMETERS → Check for forms → If no forms → STOP TESTING**

### What URL Parameters Look Like

**Query String Parameters (GET requests):**
```
https://example.com/search?q=test
                          ↑ parameter name
                             ↑ parameter value

https://shop.com/product?id=123&category=shoes
                        ↑ first parameter
                                ↑ second parameter

https://api.com/data?format=json&limit=10&offset=20
                    ↑ multiple parameters separated by &
```

**Path Parameters:**
```
https://example.com/user/456
                         ↑ user ID as path segment

https://shop.com/category/electronics/product/789
             ↑ category parameter    ↑ product parameter

https://api.com/v1/posts/123/comments/456
                     ↑ post ID   ↑ comment ID
```

**Common Parameter Names to Look For:**
```
# Identification/Database Queries
id, userId, productId, itemId, postId, articleId
uid, pid, cid, oid, gid

# Search/Filter
q, query, search, keyword, term
filter, sort, order, orderBy, sortBy

# Pagination
page, offset, limit, start, end, count
pageSize, pageNum, per_page

# Navigation
cat, category, type, view, tab, section
action, mode, cmd, command

# Session/Tracking
session, token, auth, api_key
ref, referer, source, utm_source

# File/Resource Access
file, path, url, redirect, return
template, include, page, doc
```

### URL Parameter Patterns

**Single Parameter:**
```
https://blog.com/post?id=5
→ Test parameter: id
→ Type: URL_PARAMETER
→ Method: GET
```

**Multiple Parameters:**
```
https://shop.com/search?q=laptop&price=1000&brand=dell
→ Test parameters: q, price, brand
→ Type: URL_PARAMETER (test each separately)
→ Method: GET
```

**Hidden/Encoded Parameters:**
```
https://site.com/redirect?url=aHR0cHM6Ly9leGFtcGxlLmNvbQ==
                              ↑ Base64 encoded URL
→ Test parameter: url (after decoding)
→ Type: URL_PARAMETER
→ May need encoding/decoding strategy
```

**API-style Parameters:**
```
https://api.example.com/users?fields=name,email&include=posts
→ Test parameters: fields, include
→ Type: API_ENDPOINT (if JSON response)
→ Type: URL_PARAMETER (if HTML response)
```

---

## Form Input Detection

### HTML Form Elements

**Login Form - LOGIN_FORM Classification:**
```html
<form action="/login" method="POST">
      ↑ action contains "login", "auth", "signin"
  <input type="text" name="username" />
                          ↑ indicates login form
  <input type="password" name="password" />
         ↑ password field = definitely login form
  <button type="submit">Login</button>
          ↑ submit button text
</form>

→ Classification: LOGIN_FORM
→ Routing: login_injector
→ Requires: credentials from credentials.json
```

**Search Form - URL_PARAMETER:**
```html
<form action="/search" method="GET">
                              ↑ GET = URL parameters
  <input type="text" name="q" placeholder="Search..." />
  <button type="submit">Search</button>
</form>

→ Classification: URL_PARAMETER
→ Routing: regular_injector
→ Will become: /search?q=payload
```

**Contact Form - Regular Form:**
```html
<form action="/contact" method="POST">
  <input type="text" name="name" />
  <input type="email" name="email" />
  <textarea name="message"></textarea>
  <button type="submit">Send</button>
</form>

→ Classification: URL_PARAMETER (if testing name/email)
→ Routing: regular_injector
→ Test each input field
```

**File Upload - FILE_UPLOAD:**
```html
<form action="/upload" method="POST" enctype="multipart/form-data">
                                     ↑ multipart = file upload
  <input type="file" name="avatar" accept="image/*" />
         ↑ file input
  <button type="submit">Upload</button>
</form>

→ Classification: FILE_UPLOAD
→ Routing: file_upload_tester
→ Test for: file type bypass, path traversal, code execution
```

---

## Cookie Parameter Detection

### Cookie Patterns

**Session Cookies:**
```
Cookie: PHPSESSID=abc123def456
        ↑ PHP session ID

Cookie: session_id=xyz789; Path=/; HttpOnly
        ↑ generic session

Cookie: JSESSIONID=A1B2C3D4E5F6
        ↑ Java session ID

→ Classification: COOKIE_PARAMETER
→ Test for: session fixation, prediction, manipulation
```

**Authentication Cookies:**
```
Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        ↑ JWT token in cookie

Cookie: user_id=123; role=admin
        ↑ direct user identification
        ↑ privilege level

→ Classification: COOKIE_PARAMETER
→ High priority: privilege escalation possible
```

**Tracking/Preference Cookies:**
```
Cookie: user_pref=theme:dark|lang:en
Cookie: cart_items=item1,item2,item3
Cookie: last_viewed=prod_123

→ Classification: COOKIE_PARAMETER
→ Lower priority but test for injection
```

---

## HTTP Header Detection

### Testable Headers

**Custom Application Headers:**
```
X-User-Id: 123
X-Role: user
X-Api-Key: sk_live_abc123
X-Auth-Token: bearer_xyz789

→ Classification: HEADER_PARAMETER
→ Test for: privilege escalation, authentication bypass
```

**Forwarding Headers:**
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.1
X-Originating-IP: 10.0.0.1

→ Classification: HEADER_PARAMETER
→ Test for: SSRF, IP-based auth bypass
```

**Host Header:**
```
Host: example.com
Host: evil.com

→ Classification: HEADER_PARAMETER
→ Test for: host header injection, cache poisoning
```

---

## API Endpoint Detection

### JSON API Patterns

**REST API with JSON:**
```
POST /api/v1/users HTTP/1.1
Content-Type: application/json

{
  "username": "test",
  "email": "test@example.com"
}

→ Classification: API_ENDPOINT
→ Routing: regular_injector with JSON payloads
→ Test JSON fields for injection
```

**GraphQL API:**
```
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{ user(id: 1) { name email } }"
}

→ Classification: API_ENDPOINT
→ Special handling for GraphQL injection
```

---

## Decision Matrix

### Classification Flow

```
1. Check for entry points (CRITICAL)
   ├─ Does URL contain ? character?
   │  ├─ YES → Has URL parameters (proceed to classification)
   │  └─ NO → No URL parameters (check for forms)
   │
   ├─ Does HTML contain <form> tags?
   │  ├─ YES → Has forms (proceed to classification)
   │  └─ NO → Check other entry points
   │
   ├─ Are there testable cookies/headers?
   │  ├─ YES → Has entry points (proceed to classification)
   │  └─ NO → NO_ENTRY_POINT → END_TESTING
   │
   └─ RESULT: NO entry points found → STOP TESTING IMMEDIATELY

2. Analyze input type (only if entry points exist)
   ├─ Password field in form → LOGIN_FORM
   ├─ URL has ?param=value → URL_PARAMETER
   ├─ Cookie present → COOKIE_PARAMETER
   ├─ Custom headers → HEADER_PARAMETER
   ├─ Content-Type: application/json → API_ENDPOINT
   ├─ File input field → FILE_UPLOAD
   └─ Unknown → URL_PARAMETER (safe default)

3. Check authentication requirements
   ├─ Login form + no credentials → BRUTEFORCE_TARGET
   ├─ Login form + credentials exist → LOGIN_FORM
   └─ No login required → Continue with classified type

4. Route decision
   ├─ NO_ENTRY_POINT → END_TESTING
   ├─ LOGIN_FORM → login_injector
   ├─ BRUTEFORCE_TARGET → bruteforce
   └─ All others → regular_injector
```

---

## Real-World Examples

### Example 1: Blog Post Page
```
URL: https://blog.com/post?id=5

Analysis:
✓ Has URL parameter: id
✓ No form inputs
✓ No authentication required

Classification: URL_PARAMETER
Routing: regular_injector
Entry Points: ["URL parameter: id"]
```

### Example 2: Login Page
```
URL: https://app.com/login

HTML:
<form action="/authenticate" method="POST">
  <input name="username" />
  <input type="password" name="password" />
</form>

Analysis:
✓ Has form inputs
✓ Password field present
✓ Action contains "authenticate"
✓ Check credentials.json for saved creds

Classification: LOGIN_FORM
Routing: login_injector (if creds exist) OR bruteforce (if no creds)
Entry Points: ["Form: username, password"]
```

### Example 3: Static About Page
```
URL: https://company.com/about
     ↑ No ? character = NO URL parameters

HTML:
<html>
  <body>
    <h1>About Us</h1>
    <p>Company information...</p>
  </body>
</html>

Analysis:
✗ URL has no ? character (no parameters)
✗ No forms in HTML
✗ No input fields
✗ No cookies to test
✗ No custom headers

Classification: NO_ENTRY_POINT
Routing: END_TESTING
Entry Points: []
Reason: "Clean URL with no parameters and no client-side forms available"
```

### Example 3.5: Simple Homepage
```
URL: https://something.com
     ↑ No ? character = NO URL parameters

HTML:
<html>
  <body>
    <h1>Welcome</h1>
    <nav>
      <a href="/about">About</a>
      <a href="/contact">Contact</a>
    </nav>
  </body>
</html>

Analysis:
✗ URL is clean (no ? character)
✗ No forms present
✗ Only navigation links

Classification: NO_ENTRY_POINT
Routing: END_TESTING
Entry Points: []
Reason: "Simple URL with no query parameters and no forms in client-side code"
```

### Example 4: Search with Multiple Parameters
```
URL: https://shop.com/search?q=laptop&price_min=500&price_max=2000&brand=dell

Analysis:
✓ Multiple URL parameters: q, price_min, price_max, brand
✓ No authentication required
✓ Test each parameter separately

Classification: URL_PARAMETER
Routing: regular_injector (test each param in separate rounds)
Entry Points: ["q", "price_min", "price_max", "brand"]
```

### Example 5: API Endpoint
```
POST /api/v1/orders HTTP/1.1
Content-Type: application/json

{
  "product_id": 123,
  "quantity": 1,
  "user_id": 456
}

Analysis:
✓ JSON payload
✓ API endpoint (/api/)
✓ Multiple testable fields

Classification: API_ENDPOINT
Routing: regular_injector with JSON injection
Entry Points: ["product_id", "quantity", "user_id"]
```

---

## Key Takeaways

1. **Check URL for `?` character FIRST** - If no `?` in URL, there are NO URL parameters
2. **If no `?` and no forms → STOP TESTING** - Return NO_ENTRY_POINT immediately
3. **URL parameters are ONLY in the URL** - Look for `?` and `&` characters
4. **Examples of clean URLs (NO parameters):**
   - `https://something.com` → NO ? → NO parameters
   - `https://example.com/about` → NO ? → NO parameters
   - `https://site.com/contact` → NO ? → NO parameters
5. **Forms need method analysis** - GET forms become URL parameters, POST forms are body parameters
6. **Login forms are special** - Route to login_injector or bruteforce, not regular injector
7. **Be conservative** - If unsure, classify as URL_PARAMETER (safe default)
8. **List all entry points** - Return complete list in `entry_points_found` array
9. **Stop early** - Don't waste time on static pages with no testable inputs
10. **Check client-side code** - If HTML has no forms and URL has no ?, testing should stop

---

## Output Format Template

```json
{
  "input_type": "NO_ENTRY_POINT",
  "confidence": "High",
  "reasoning": "Static HTML page with only navigation links and text content. No forms, URL parameters, cookies, or testable headers detected.",
  "has_entry_points": false,
  "entry_points_found": [],
  "requires_authentication": false,
  "credentials_needed": false,
  "routing_decision": "END_TESTING",
  "injection_strategy": {},
  "additional_context": {
    "page_type": "static_content",
    "recommendation": "Skip testing - no injection vectors available"
  }
}
```

```json
{
  "input_type": "URL_PARAMETER",
  "confidence": "High",
  "reasoning": "URL contains parameter 'id' in query string. No authentication required. Standard GET request parameter.",
  "has_entry_points": true,
  "entry_points_found": ["URL parameter: id"],
  "requires_authentication": false,
  "credentials_needed": false,
  "routing_decision": "regular_injector",
  "injection_strategy": {
    "method": "GET",
    "location": "parameter",
    "parameter_name": "id",
    "requires_session": false
  },
  "additional_context": {
    "url": "https://blog.com/post?id=5",
    "parameter_type": "numeric",
    "likely_vulnerability_types": ["SQLi", "IDOR", "LFI"]
  }
}
```
