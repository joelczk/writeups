## Default Information
IP Address: 10.10.10.76\
OS: Solaris

## Background about Solaris

Soolaris is a Unix operating system that was developed by Sun Microsystems and is currently mostly used as an enterprise operating system in many industry softwares.
## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.76    sunday.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop/htb_stuff]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.76 --rate=1000 -e tun0                1 ⨯
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-04 12:26:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 43397/tcp on 10.10.10.76                                  
Discovered open port 22022/tcp on 10.10.10.76                                  
Discovered open port 111/tcp on 10.10.10.76    
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 111	| rpcbind | 2-4 (RPC #100000) | Open |
| 22022	| SSH | SunSSH 1.3 (protocol 2.0) | Open |
| 43397	| unknown | unknown | Open |

Since there ports 80 and 443 are not open, there is no web service running on this machine. THis would mean that our exploitation would depend solely on the open ports.

Next, we will do a more complete scan of all the ports using Nmap.
```
```

Afterwards, we will also do a UDP scan of all the ports. However, the results obtained are not promising.

```
PORT      STATE         SERVICE         REASON
111/udp   open|filtered rpcbind         no-response
137/udp   open|filtered netbios-ns      no-response
518/udp   open|filtered ntalk           no-response
773/udp   open|filtered notify          no-response
5353/udp  open|filtered zeroconf        no-response
31335/udp open|filtered Trinoo_Register no-response
32773/udp open|filtered sometimes-rpc10 no-response
```
Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```
### Sslyze

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://sunday.htb

```
{Gobuster output}
```
We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
{Gobuster output}
```

### Ferox Buster
We will also use Ferox Buster to check if we are able to find any new endpoints, that was previously not discovered by Gobuster.

### Web-content discovery

## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
