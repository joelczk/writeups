## Default Information
IP address : 10.10.10.215\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```
nmap -sC -sV -A -p- -T4 10.10.10.215 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 33069	| mysqlx? | NIL | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.215 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.10.215    academy.htb
```

## Discovery
Firstly, We will now run ```gobuster``` on ```http://academy.htb``` to enumerate the directories on the endpoints. However, we were unable to find any meaningful endpoints from the output. 

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://academy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/26 12:17:01 Starting gobuster in directory enumeration mode
===============================================================
http://academy.htb/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]                                                                                                                               
```

Next, we will try to fuzz for potential virtual hosts using ```Gobuster```, but we were unable to discover any virtual hosts.

Now, we will visit the webpage and the Webapplyzer plugin tells us that the website is using PHP.  We will fuzz again for potential PHP endpoints using Gobuster.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://academy.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/26 12:17:01 Starting gobuster in directory enumeration mode
===============================================================
http://academy.htb/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
http://academy.htb/admin.php            (Status: 200) [Size: 2633] 
http://academy.htb/login.php            (Status: 200) [Size: 2627] 
http://academy.htb/home.php             (Status: 302) [Size: 55034] [--> login.php] 
http://academy.htb/register.php         (Status: 200) [Size: 3003]
http://academy.htb/config.php           (Status: 200) [Size: 0] 
http://academy.htb/index.php            (Status: 200) [Size: 2117] 
```

Upon visiting the ```/admin.php``` endpoint, we realize that this is a login page to the admin interface of the website. Before we can access the admin page, we will first have
to register for an admin account via the ```/register.php```. However, a normal registration doesn't seem to be able to give us admin access to the webpage. 

We will now intercept the request made when we register an account. We noticed that when we register for an account, there is a ```roleid=0``` in the body of the request. We will
then modify this to become ```roleid=1``` to try to register an admin account instead.

![Modifying roleid](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/register_roleid.PNG)

Logging into the ```/admin.php``` using the newly created admin account,  we were able to discover a new Virtual host, ```dev-staging-01.academy.htb```. We will add this host to 
our ```/etc/hosts``` file.

![admin page](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/adminpage.PNG)

```
10.10.10.215    dev-staging-01.academy.htb academy.htb
```
