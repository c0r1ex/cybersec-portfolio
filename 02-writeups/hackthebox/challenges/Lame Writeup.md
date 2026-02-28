Starting scan with
nmap -sV -sC -v --open -OA lame-scan <ip> -Pn

![[Pasted image 20260228013703 1.png]]

Found 4 TCP ports open
Including VSFTPd version 2.3.4

Ran and searchsploit metasploit to find vulnerabilities
Found VSFTPD v2.3.4 Backdoor Command Execution

No luck. Didnt work

Then we have also in nmap results the Samba service running with v3.0.20

Searched with dbexploit 
'Username' map script' Command Execution (Metasploit)

Later went to CVE details

CVE-2007-2447
The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

With this i could ran another metasploit using this vulnerabilty
![[Pasted image 20260228014857.png]]

Already in...
![[Pasted image 20260228014925.png]]

Post-Exploitation -> Find user.txt and root.txt flags
