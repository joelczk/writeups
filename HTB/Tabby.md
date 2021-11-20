## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.194    tabby.htb
```

### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.194 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-20 10:02:48 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.194                                  
Discovered open port 80/tcp on 10.10.10.194                                    
Discovered open port 22/tcp on 10.10.10.194
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we know that there are 2 
ports running web services, namely port 80 and port 8080.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 8080	| HTTP | Apache Tomcat | Open |

However, we are also able to obtain an email address of interest (sales@megahosting.htb) from the nmap output. As such, we will also add megahosting.htb to our /etc/hosts file.

```
10.10.10.194    megahosting.htb tabby.htb
```

### Gobuster

We will first use Gobuster to enumerate for any common endpoints of http://tabby.htb on port 80. From the output, there is an interesting /new.php endpoint that returns a size 
of 0

```
http://10.10.10.194:80/Readme.txt           (Status: 200) [Size: 1574]
http://10.10.10.194:80/assets               (Status: 301) [Size: 313] [--> http://10.10.10.194/assets/]
http://10.10.10.194:80/favicon.ico          (Status: 200) [Size: 766]
http://10.10.10.194:80/files                (Status: 301) [Size: 312] [--> http://10.10.10.194/files/]
http://10.10.10.194:80/index.php            (Status: 200) [Size: 14175]
http://10.10.10.194:80/news.php             (Status: 200) [Size: 0]
```

Afterwards, we will use Gobuster to enuemerate for common endpoints of http;//tabby.htb on port 8080

```
http://10.10.10.194:8080/docs                 (Status: 302) [Size: 0] [--> /docs/]
http://10.10.10.194:8080/examples             (Status: 302) [Size: 0] [--> /examples/]
http://10.10.10.194:8080/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
http://10.10.10.194:8080/index.html           (Status: 200) [Size: 1895]
http://10.10.10.194:8080/index.html           (Status: 200) [Size: 1895]
http://10.10.10.194:8080/manager              (Status: 302) [Size: 0] [--> /manager/]
```

### Web-content discovery
Visiting http://tabby.htb:80, we are able to find a /news.php that redirects to http://megahosting.htb/news.php?file=statement
![news.php page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Tabby/news.png)

Capturing the request via Burp Suite, we realize that there is a file parameter that might possibly be vulnerable to LFI. Using ```../../../../etc/passwd``` worked as we are 
able to view the file contents of /etc/passwd file. From this output alone, even though we are unable to obtain any credentials that is of any use to use, we are able to find a
few users that might be of use to use (tomcat, lxd, ash)

![LFI Burp](https://github.com/joelczk/writeups/blob/main/HTB/Images/Tabby/lfi_burp.png)

Now, let's try to find a configuration file that can leak potential credentials.
## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
