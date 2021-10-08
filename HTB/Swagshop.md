## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.140    swagshop.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.140 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-08 12:48:00 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.140                                    
Discovered open port 80/tcp on 10.10.10.140 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. However, the only vulnerabilities discovered are maninly CSRF, which is not really useful in the machine here.

### Sslyze

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
http://swagshop.htb/media                (Status: 301) [Size: 312] [--> http://swagshop.htb/media/]
http://swagshop.htb/includes             (Status: 301) [Size: 315] [--> http://swagshop.htb/includes/]
http://swagshop.htb/lib                  (Status: 301) [Size: 310] [--> http://swagshop.htb/lib/]
http://swagshop.htb/app                  (Status: 301) [Size: 310] [--> http://swagshop.htb/app/]
http://swagshop.htb/js                   (Status: 301) [Size: 309] [--> http://swagshop.htb/js/]
http://swagshop.htb/shell                (Status: 301) [Size: 312] [--> http://swagshop.htb/shell/]
http://swagshop.htb/skin                 (Status: 301) [Size: 311] [--> http://swagshop.htb/skin/]
http://swagshop.htb/var                  (Status: 301) [Size: 310] [--> http://swagshop.htb/var/]
http://swagshop.htb/errors               (Status: 301) [Size: 313] [--> http://swagshop.htb/errors/]
http://swagshop.htb/mage                 (Status: 200) [Size: 1319]
http://swagshop.htb/server-status        (Status: 403) [Size: 300]
```

We will also tried to find virtual hosts on http://gobuster.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://swagshop.htb/index.php            (Status: 200) [Size: 16097]
http://swagshop.htb/media                (Status: 301) [Size: 312] [--> http://swagshop.htb/media/]
http://swagshop.htb/includes             (Status: 301) [Size: 315] [--> http://swagshop.htb/includes/]
http://swagshop.htb/lib                  (Status: 301) [Size: 310] [--> http://swagshop.htb/lib/]
http://swagshop.htb/install.php          (Status: 200) [Size: 44]
http://swagshop.htb/app                  (Status: 301) [Size: 310] [--> http://swagshop.htb/app/]
http://swagshop.htb/js                   (Status: 301) [Size: 309] [--> http://swagshop.htb/js/]
http://swagshop.htb/api.php              (Status: 200) [Size: 37]
http://swagshop.htb/shell                (Status: 301) [Size: 312] [--> http://swagshop.htb/shell/]
http://swagshop.htb/skin                 (Status: 301) [Size: 311] [--> http://swagshop.htb/skin/]
http://swagshop.htb/cron.php             (Status: 200) [Size: 0]
http://swagshop.htb/LICENSE.txt          (Status: 200) [Size: 10410]
http://swagshop.htb/LICENSE.html         (Status: 200) [Size: 10679]
http://swagshop.htb/var                  (Status: 301) [Size: 310] [--> http://swagshop.htb/var/]
http://swagshop.htb/errors               (Status: 301) [Size: 313] [--> http://swagshop.htb/errors/]
http://swagshop.htb/mage                 (Status: 200) [Size: 1319]
http://swagshop.htb/server-status        (Status: 403) [Size: 300]
```

### Ferox Buster
We will also use Ferox Buster to check if we are able to find any new endpoints, that was previously not discovered by Gobuster.

### Web-content discovery

## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
