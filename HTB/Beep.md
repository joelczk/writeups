## Default Information
IP Address: 10.10.10.7\
OS: Linux

## Enumeration

First, let's add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.7    beep.htb
```

Next, we will scan for open ports using masscan. Form the output, we realize that there are numerous open ports on this machine.

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

Now, we will scan these open ports using Nmap to identify the service behind each of these open ports.

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

From the masscan, we notice that there is an open UDP port. We will use nmap to scan the UDP port, but we did not notice anything of interest from the nmap scan. 

## Discovery

First, we will try to find the endpoints of https://beep.htb. From the output, we were able to find an interesting endpoint https://beep.htb/vtigercrm

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

Next, we will visit the https://beep.htb. From the website we realize that the website uses PHP. Now, we will use gobuster to find for endpoints with PHP

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
