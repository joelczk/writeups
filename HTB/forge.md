## Default Information
IP address : 10.10.11.101\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.11.101 -vv
```

From the output of ```NMAP```, we find something interesting, which is that this box has an FTP server.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21	| FTP | NIL | filtered |
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.11.111 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.11.111    forge.htb
```

## Discovery
Firstly, We will now run ```gobuster``` on ```http://forge.htb``` to enumerate the directories on the endpoints. From the output, we discover an interesting ```/upload``` endpoint.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://forge.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://forge.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/11 13:46:22 Starting gobuster in directory enumeration mode
===============================================================
http://forge.htb/uploads              (Status: 301) [Size: 224] [--> http://forge.htb/uploads/]
http://forge.htb/static               (Status: 301) [Size: 307] [--> http://forge.htb/static/]
http://forge.htb/upload               (Status: 200) [Size: 929]
http://forge.htb/server-status        (Status: 403) [Size: 274] 
===============================================================
2021/09/20 03:27:11 Finished
===============================================================
```

Next, we will run a VHOST enumeration using Gobuster to find possible subdomains on ```http://forge.htb```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster vhost forge.htb -u http://forge.htb/ -w /home/kali/Desktop/subdomains.txt -k -t 50 -o gobuster.txt   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb/
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /home/kali/Desktop/subdomains.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/20 03:12:11 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]                                                                                                           
===============================================================
2021/09/20 03:22:05 Finished
===============================================================
```

Now, we will add the subdomain to our ```etc/hosts``` file. 

```
10.10.11.111    admin.forge.htb forge.htb
```

Visiting http://admin.forge.htb, we get the following message that it only allows connections from localhost. This gives us the idea that to be able to connect to http://admin.forget.htb, the only way would be through Server-Side Request Forgery.

![Message shown on admin.forge.htb](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/admin_forge.PNG)

Next, we will visit http://forge.htb/upload. We notice that there are 2 options for file uploads (Upload from local files and upload from URL). Let's first test with uploading of local file. 

We notice that upon a successful file upload from local file, we are presented with a URL that will display an error page when we attempt to visit the page. However, on Burp we will be presented with a response that shows the file contents.

![Error page](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/loal_file_upload_error.PNG)

![Burp output](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/local_file_upload_burp.PNG)

Next, we will test out file upload by url. We will first try to use http://localhost as the url. However, we realize that this url is blacklisted and we are unable to access it. Similarly, when we try to use http://admin.forge.htb as the URL we will also realize that the url is blacklisted and we are unable to access it.

