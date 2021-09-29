## Default Information
IP Address: 10.10.10.7\
OS: Linux

## Enumeration

First, let's add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.7    beep.htb
```

Next, we will scan for open ports using masscan. Form the output, we realize that there are numerous open ports on this machine.

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.7 --rate=1000 -e tun0                 1 ⚙

Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-09-29 01:50:04 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 5038/tcp on 10.10.10.7                                    
Discovered open port 993/tcp on 10.10.10.7                                     
Discovered open port 443/tcp on 10.10.10.7                                     
Discovered open port 22/tcp on 10.10.10.7                                      
Discovered open port 111/tcp on 10.10.10.7                                     
Discovered open port 4559/tcp on 10.10.10.7                                    
Discovered open port 878/tcp on 10.10.10.7                                     
Discovered open port 3306/tcp on 10.10.10.7                                    
Discovered open port 4190/tcp on 10.10.10.7                                    
Discovered open port 143/tcp on 10.10.10.7                                     
Discovered open port 80/tcp on 10.10.10.7                                      
Discovered open port 10000/udp on 10.10.10.7                                   
Discovered open port 10000/tcp on 10.10.10.7                                   
Discovered open port 995/tcp on 10.10.10.7                                     
Discovered open port 25/tcp on 10.10.10.7                                      
Discovered open port 110/tcp on 10.10.10.7                                     
Discovered open port 4445/tcp on 10.10.10.7   
```

Now, we will scan these open ports using Nmap to identify the service behind each of these open ports.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| ssh | OpenSSH 4.3 (protocol 2.0) | Open |
| 25	| smtp | Postfix smtpd | Open |
| 80	| http | Apache httpd 2.2.3 | Open |
| 143	| imap | NIL | Open |
| 443	| SSL/https | NIL | Open |
| 878	| status | NIL | Open |
| 993	| imaps | NIL | Open |
| 995	| pop3s | NIL | Open |
| 3306	| mysql | MYSQL | Open |
| 5038	| asterisk | Asterisk Call Manager 1.1 | Open |
| 10000	| http | MiniServ 1.570 (Webmin httpd) | Open |

From the masscan, we notice that there is an open UDP port. We will use nmap to scan the UDP port, but we did not notice anything of interest from the nmap scan. 

## Discovery

