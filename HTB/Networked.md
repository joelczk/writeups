## Default Information
IP Address: 10.10.10.146\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.146    networked.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
{masscan output}
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| {Port}	| {Service} | {Version} | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```
### Sslyze

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://networked.htb

```
{Gobuster output}
```
We will also tried to find virtual hosts on http://networked.htb, but we were unable to find any vhosts.

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
