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
