## Default Information
IP Address: 10.10.10.171\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.171    openadmin.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.171 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-31 02:16:56 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.171                                    
Discovered open port 80/tcp on 10.10.10.171   
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| ssh | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.29 ((Ubuntu)) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://openadmin.htb

```
http://10.10.10.171:80/.htpasswd            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.asp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.html            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.aspx       (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.php             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.jsp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.asp             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.asp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.aspx            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.aspx       (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.jsp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta                 (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.jsp             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.txt             (Status: 403) [Size: 277]
http://10.10.10.171:80/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
http://10.10.10.171:80/index.html           (Status: 200) [Size: 10918]
http://10.10.10.171:80/sierra               (Status: 301) [Size: 313] [--> http://10.10.10.171/sierra/]
http://10.10.10.171:80/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
http://10.10.10.171:80/server-status        (Status: 403) [Size: 277]
```

### Web-content discovery

Viewing all the sites, there was not much discovery until we visit http://openadmin.htb/admin. Viewing the page source of the website, we notice a strange ```href``` tag 
that points to ../ona

![ona href link](https://github.com/joelczk/writeups/blob/main/HTB/Images/OpenAdmin/href_ona.png)

Following that link, we are redirected to http;//openadmin.htb/ona which is OpenNetAdmin. From there, we are also able to find the current version of OpenNetAdmin that we are 
using

![ona site](https://github.com/joelczk/writeups/blob/main/HTB/Images/OpenAdmin/ona.png)
## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
