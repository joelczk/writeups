## Default Information
IP Address: 10.10.10.111\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.111    frolic.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.111 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.111
Discovered open port 137/tcp on 10.10.10.111
Discovered open port 139/tcp on 10.10.10.111
Discovered open port 445/tcp on 10.10.10.111
Discovered open port 1880/tcp on 10.10.10.111
Discovered open port 9999/tcp on 10.10.10.111
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, there are 2 ports with web services, namely port 1880 and port 9999.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0) | Open |
| 139	| netbios-ssn | Samba smbd 3.X - 4.X | Open |
| 445	| netbios-ssn | Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP) | Open |
| 1880	| http | Node.js (Express middleware) | Open |
| 9999	| http | nginx 1.10.3 (Ubuntu) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports, but the main exploits are DDOS, which is not very useful in our case.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://frolic.htb

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
