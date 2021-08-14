## Default Information
IP address : 10.10.10.56
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.56 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.18 (Ubuntu) | Open |
| 435	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |

## Discovery
Firstly, we will try to visit the website to obtain some information about the website. However, there isn't much information that can be obtained from the website.
Next, we try to enumerate the directory and files on the website using ```gobuster```.
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56 -w /usr/share/wordlists/dirb/common.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:00:29 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/.hta                 (Status: 403) [Size: 290]
http://10.10.10.56/.htaccess            (Status: 403) [Size: 295]
http://10.10.10.56/.htpasswd            (Status: 403) [Size: 295]
http://10.10.10.56/cgi-bin/             (Status: 403) [Size: 294]
http://10.10.10.56/index.html           (Status: 200) [Size: 137]
http://10.10.10.56/server-status        (Status: 403) [Size: 299]
                                                                 
===============================================================
2021/08/14 15:00:57 Finished
===============================================================

```
What is special in the output of the ```gobuster``` is the presence of the ```cgi-bin``` directory which is normally used to store perl or compiled script files. So, next what we
will do is to do enumeration for the ```/cgi-bin``` directory. Form the output, we have noticed that the ```/cgin-bin``` directory actually contains a ```user.sh``` file
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x .txt,.php,.pl,.cgi,.c,.sh -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              c,sh,txt,php,pl,cgi
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:03:38 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/cgi-bin/.htpasswd            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.htaccess.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.hta.cgi             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.c               (Status: 403) [Size: 300]
http://10.10.10.56/cgi-bin/.htpasswd.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.hta                 (Status: 403) [Size: 298]
http://10.10.10.56/cgi-bin/.htpasswd.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.sh              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/.htpasswd.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.txt             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.htaccess.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.php             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.pl              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/user.sh              (Status: 200) [Size: 118]
                                                                         
===============================================================
2021/08/14 15:06:40 Finished
===============================================================
```
We will just keep this ```/cgi-bin/user.sh``` file in mind for now and carry on with a `Nikto` scan, which detected that we are using an old version of ```Apache```.
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2021-08-14 13:49:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
```
