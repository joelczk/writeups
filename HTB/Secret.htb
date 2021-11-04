## Default Information
IP Address: 10.10.11.120\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.120    secret.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.120 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-04 07:01:01 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.11.120                                    
Discovered open port 80/tcp on 10.10.11.120                                    
Discovered open port 3000/tcp on 10.10.11.120    
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we can easily see that 
this machine uses Express middleware which signifies that the backend of this machine is Node JS.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | nginx 1.18.0 (Ubuntu) | Open |
| 3000	| HTTP | Node.js (Express middleware) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://secret.htb on port 80. At the same time, we also realize that endpoints on port 3000 
is the same as port 80.

```
http://10.10.11.120/api/experiments.php  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.asp  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.txt (Status: 200) [Size: 93]
http://10.10.11.120/api                  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.aspx (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.jsp  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.html (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments      (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.php (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.txt  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.asp (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.html (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.aspx (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.jsp (Status: 200) [Size: 93]
http://10.10.11.120/assets               (Status: 301) [Size: 179] [--> /assets/]
http://10.10.11.120/download             (Status: 301) [Size: 183] [--> /download/]
http://10.10.11.120/docs                 (Status: 200) [Size: 20720]
```

### Web-content discovery

From the main page of http://secret,htb, we can find http://secret.htb/download/files.zip that allows us to download files.zip folder. Unzipping the folder 
gives us a local-web directory which contains a .git folder that tells us that this folder is most likely a zip file downloaded from a git repo.

```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ ls -la        
total 116
drwxrwxr-x   8 kali kali  4096 Sep  3 01:57 .
drwxr-xr-x   8 kali kali  4096 Nov  4 03:10 ..
-rw-rw-r--   1 kali kali    72 Sep  3 01:59 .env
drwxrwxr-x   8 kali kali  4096 Sep  8 14:33 .git
-rw-rw-r--   1 kali kali   885 Sep  3 01:56 index.js
drwxrwxr-x   2 kali kali  4096 Aug 13 00:42 model
drwxrwxr-x 201 kali kali  4096 Aug 13 00:42 node_modules
-rw-rw-r--   1 kali kali   491 Aug 13 00:42 package.json
-rw-rw-r--   1 kali kali 69452 Aug 13 00:42 package-lock.json
drwxrwxr-x   4 kali kali  4096 Sep  3 01:54 public
drwxrwxr-x   2 kali kali  4096 Sep  3 02:32 routes
drwxrwxr-x   4 kali kali  4096 Aug 13 00:42 src
-rw-rw-r--   1 kali kali   651 Aug 13 00:42 validations.js
```

Visiting http://secret.htb/docs, we are presented with a documentation on how to register a user and login to the user. Let us try to register a new user and login to the new 
user. Let's start by registering a new user.

![Registering user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/register.png)

### Analysis of git folder

## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
