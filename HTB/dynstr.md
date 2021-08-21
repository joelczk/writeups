## Default Information
IP address : 10.10.10.244\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.244 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 53	| domain | syn-ack ISC BIND 9.16.1 (Ubuntu Linux) | Open |
| 80	| http | Apache httpd 2.4.41 (Ubuntu) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.244 -T4 -vv 
```

## Discovery
Looking through the webpages, we are able to discover several domains and credentials related this challenge.

![Dynstr domains](https://github.com/joelczk/writeups/blob/main/HTB/Images/dyntsr/dynstr_domains.PNG)

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/dyntsr/dynstr_email_domains.PNG" width = "2000">

Next, we will try to find for subdomains for the domains using ```subfinder```. However, we are unable to find any subdomains for all the domains above. 
Now, we will add these domains into the ```etc/hosts``` file
```
10.10.10.244    dyna.htb dnsalias.htb dynamicdns.htb no-ip.htb dns@dyna.htb
```

We will now run ```gobuster``` on ```http://dyna.htb``` to enumerate the directories on the endpoints
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://dyna.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.244
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/20 20:59:12 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/assets               (Status: 301) [Size: 313] [--> http://10.10.10.244/assets/]
http://dyna.htb/nic                  (Status: 301) [Size: 310] [--> http://10.10.10.244/nic/]   
http://dyna.htb/server-status        (Status: 403) [Size: 277]                                  
                                                                                                    
===============================================================
2021/08/20 21:18:41 Finished
===============================================================
```

Afterwards, we will run ```gobuster``` again on ```http://dyba.htb/nic``` to enumerate the endpoints
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://dyna.htb/nic -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.244/nic
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/20 21:01:38 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/nic/update               (Status: 200) [Size: 8]
                                                                    
===============================================================
2021/08/20 21:21:04 Finished
```
We will now visit the ```/nic/update``` endpoints, and we notice that we are returned with a ```badauth```. After some research, we found from [here](https://www.noip.com/integrate/request)
that this endpoints takes in a request of the following format:
```
GET /nic/update?hostname=mytest.example.com&myip=192.0.2.25 HTTP/1.1
Host: dynupdate.no-ip.com
Authorization: Basic base64-encoded-auth-string
```

Next, what we have to do is to find the base64-encoded-auth string. From earlier, we are able to know that the username is ```dynadns``` and the password is ```sndanyd```. Hence, we 
can know that the auth-string will be ```dynadns:sndanyd```. Now we we base64 encode the authentication string.
```
┌──(kali㉿kali)-[~]
└─$ echo -n "dynadns:sndanyd" | base64
ZHluYWRuczpzbmRhbnlk
```
Editing the request for ```/nic/update```, we get a wrong domain error ```911 [wrngdom: htb]```

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/dyntsr/dynstr_wrongdom.PNG" width = "2000">

After a while, 
