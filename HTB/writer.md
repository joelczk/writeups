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

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 139	| netbios-ssn | Samba smbd 4.6.2 | Open |
| 445	| netbios-ssn | Samba smbd 4.6.2 | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.11.101 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.11.101    writer.htb
```

## Discovery
Firstly, We will now run ```gobuster``` on ```http://writer.htb``` to enumerate the directories on the endpoints. From the output, we discover an interesting ```/adminstrative``` endpoint.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://writer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://writer.htb
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
http://writer.htb/contact              (Status: 200) [Size: 4905]
http://writer.htb/about                (Status: 200) [Size: 3522]
http://writer.htb/static               (Status: 301) [Size: 309] [--> http://writer.htb/static/]
http://writer.htb/logout               (Status: 302) [Size: 208] [--> http://writer.htb/]       
http://writer.htb/dashboard            (Status: 302) [Size: 208] [--> http://writer.htb/]       
http://writer.htb/administrative       (Status: 200) [Size: 1443]                               
http://writer.htb/server-status        (Status: 403) [Size: 275]                                
                                                                                                
===============================================================
2021/09/11 14:06:47 Finished
===============================================================
```
