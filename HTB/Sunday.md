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
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. An additional Nmap scan on all the ports furthur revealed that port 79 is open and running on Sun Solaris finger.

From the scan, we can also see that there are no users that is currently logged into port 79. 

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 79	| finger | Sun Solaris fingerd | Open |
| 111	| rpcbind | 2-4 (RPC #100000) | Open |
| 22022	| SSH | SunSSH 1.3 (protocol 2.0) | Open |
| 43397	| unknown | unknown | Open |

Since there ports 80 and 443 are not open, there is no web service running on this machine. THis would mean that our exploitation would depend solely on the open ports.

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
Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports, but we were unable to find anything related CVEs.
`
### Username Enumeration on Finger

Next, what we will do is a username enumeration on finger using the script [here](https://github.com/pentestmonkey/finger-user-enum). 

### Web-content discovery

## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
