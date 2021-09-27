## Default Information
IP address : 10.10.10.233\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```
nmap -sC -sV -A -p- -T4 10.10.10.233 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.4 (protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.6 ((CentOS) PHP/5.4.16) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.233 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.10.233    armageddon.htb
```

## Discovery

Firstly, We will now run ```gobuster``` on ```http://armageddon.htb``` to enumerate the directories on the endpoints. However, we were unable to find any meaningful endpoints 
from the output.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://armageddon.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://armageddon.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/27 00:37:20 Starting gobuster in directory enumeration mode
===============================================================
http://armageddon.htb/sites                (Status: 301) [Size: 236] [--> http://armageddon.htb/sites/]
http://armageddon.htb/scripts              (Status: 301) [Size: 238] [--> http://armageddon.htb/scripts/]
http://armageddon.htb/themes               (Status: 301) [Size: 237] [--> http://armageddon.htb/themes/] 
http://armageddon.htb/profiles             (Status: 301) [Size: 239] [--> http://armageddon.htb/profiles/]
http://armageddon.htb/misc                 (Status: 301) [Size: 235] [--> http://armageddon.htb/misc/] 
http://armageddon.htb/modules              (Status: 301) [Size: 238] [--> http://armageddon.htb/modules/] 

```
Next, we will try to fuzz for potential virtual hosts using ```Gobuster```, but we were unable to discover any virtual hosts.

Now, we will run ```whatweb``` to identify the web technologies. From the output, we discovered that the website is using a CMS known as Drupal, and we also know that Drupal 
contains a few security vulnerabilities.

```
┌──(kali㉿kali)-[~]
└─$ whatweb http://armageddon.htb                     
http://armageddon.htb [200 OK] Apache[2.4.6], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.233], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], PHP[5.4.16], PasswordField[pass], PoweredBy[Arnageddon], Script[text/javascript], Title[Welcome to  Armageddon |  Armageddon], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.4.16]
```

From ```whatweb```, we know that the website supports PHP. Now, we will try to enumerate for endpoints again, but using php as a file extension. However, we were not able to find any interesting endpoints from the output. 

```
                                                                                        
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://armageddon.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50 -x php                       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://armageddon.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/27 02:40:21 Starting gobuster in directory enumeration mode
===============================================================
http://armageddon.htb/scripts              (Status: 301) [Size: 238] [--> http://armageddon.htb/scripts/]
http://armageddon.htb/themes               (Status: 301) [Size: 237] [--> http://armageddon.htb/themes/] 
http://armageddon.htb/profiles             (Status: 301) [Size: 239] [--> http://armageddon.htb/profiles/]
http://armageddon.htb/install.php          (Status: 200) [Size: 3206] 
http://armageddon.htb/index.php            (Status: 200) [Size: 7480] 
http://armageddon.htb/cron.php             (Status: 403) [Size: 7428]
http://armageddon.htb/misc                 (Status: 301) [Size: 235] [--> http://armageddon.htb/misc/] 
http://armageddon.htb/modules              (Status: 301) [Size: 238] [--> http://armageddon.htb/modules/] 
http://armageddon.htb/xmlrpc.php           (Status: 200) [Size: 42]
http://armageddon.htb/includes             (Status: 301) [Size: 239] [--> http://armageddon.htb/includes/]
http://armageddon.htb/authorize.php        (Status: 403) [Size: 2854]
```

Next, we would need to find the version of Drupal that is being used. Looking at the forums [here](https://www.drupal.org/forum/support/post-installation/2005-10-16/how-to-check-drupal-version), we can find the latest version of Drupal used at the ```/CHANGELOG.txt``` endpoint. Visiting that endpoint, we discover that the latest version of Drupal is 7.56

![Drupal version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Armagaddon/drupal_version.PNG)

Reseaching on Drupal online, we realized that Drupal 7.56 may be vulnerable to CVE-2018-7600, which is a remote code execution vulnerability. For this CVE, we are able to find an exploit code on github [here](https://github.com/dreadlocked/Drupalgeddon2). Th 
* Tried to use burp suite to exploit it but failed to exploit
* Tried to use the repository [here](https://github.com/pimps/CVE-2018-7600) as well but failed too! (Maybe I used the wrong payload)

![Web Shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Armagaddon/web_shell.PNG)
