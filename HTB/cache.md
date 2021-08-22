## Default Information
IP address : 10.10.10.188\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.188 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.29 (Ubuntu) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.188 -T4 -vv 
```

Next, we would have to add the IP address to our ```/etc/hosts``` file. 
```
10.10.10.188    cache.htb 
```

## Discovery
First, we will try to discover the endpoints on ```http://cache.htb```. From the results, we discover that there is a ```jquery``` directory that are of interest to us.
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.188 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.188
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/22 00:16:18 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.188/javascript           (Status: 301) [Size: 317] [--> http://10.10.10.188/javascript/]
http://10.10.10.188/jquery               (Status: 301) [Size: 313] [--> http://10.10.10.188/jquery/]
http://10.10.10.188/server-status        (Status: 403) [Size: 277] 
```

Visiting the ```/jquery``` endpoint, we are able to find a ```functionality.js``` file. Viewing the javascript file, we realize that this is a code determining the logic 
for login functionality. In the code, we find that the username is ```ash``` and the password is ```H@v3_fun```

![functionality.js file](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/functionality_js.PNG)

However, after logging in we are unable to find any possible points of entry for exploitation. All we can see is a page showing that the webpage is still under construction.

![Page under construction](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/construction_page.PNG)

Next we would want to find for possible virtual hosts on the IP address. To do that we would first add ```htb``` to the ```/etc/hosts``` file.
```
10.10.10.188    cache.htb htb 
```
