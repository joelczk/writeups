## Default Information
IP Address: 10.10.10.191\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.191    blunder.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.191 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-06 15:56:58 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.191  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |


### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://blunder.htb

```
http://10.10.10.191:80/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess            (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd            (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.asp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.asp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.aspx       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.aspx       (Status: 403) [Size: 277]
http://10.10.10.191:80/0                    (Status: 200) [Size: 7562]
http://10.10.10.191:80/.htaccess.jsp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.jsp        (Status: 403) [Size: 277]
http://10.10.10.191:80/LICENSE              (Status: 200) [Size: 1083]
http://10.10.10.191:80/about                (Status: 200) [Size: 3281]
http://10.10.10.191:80/admin                (Status: 301) [Size: 0] [--> http://10.10.10.191/admin/]
http://10.10.10.191:80/cgi-bin/             (Status: 301) [Size: 0] [--> http://10.10.10.191/cgi-bin]
http://10.10.10.191:80/install.php          (Status: 200) [Size: 30]
http://10.10.10.191:80/robots.txt           (Status: 200) [Size: 22]
http://10.10.10.191:80/robots.txt           (Status: 200) [Size: 22]
http://10.10.10.191:80/server-status        (Status: 403) [Size: 277]
http://10.10.10.191:80/todo.txt             (Status: 200) [Size: 118]
http://10.10.10.191:80/usb                  (Status: 200) [Size: 3960]
```

### Web-content discovery

From Gobuster, we discover an interesting endpoint /cgi-bin, but we realize that this site redirects us to an empty page that says PAGE NOT FOUND. 

Another interesting discovery from Gobuster is the /robots.txt endpoint, but there is not much discovery on this endpoint. However, visiting http://blunder.htb/todo.txt shows
us some interesting users, and we can guess that fergus is one of the user of the website.

```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

Visiting http://blunder.htb/admin, we are greeted with a login interface which also tells us that this is a Bludit CMS. Viewing the source code, we are also able to find out 
that the Bludit version that we are looking at 3.9.2

![Bludit version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Blundit/bludit_version.png)

Searching the potential vulnerabilities of Bludit, we are able to discover an authentication bruteforce bypass, which means that we can try to bruteforce the password using fergus 
as the username for the login page
```
┌──(kali㉿kali)-[~]
└─$ searchsploit bludit 3.9.2
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypas | php/webapps/48746.rb
Bludit 3.9.2 - Auth Bruteforce Bypass                      | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploi | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal                         | multiple/webapps/48701.txt
----------------------------------------------------------- ---------------------------------
```
## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
