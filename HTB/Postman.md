## Default Information
IP Address: 10.10.10.160\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.160    postman.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.160 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.111
Discovered open port 80/tcp on 10.10.10.111
Discovered open port 6379/tcp on 10.10.10.111
Discovered open port 10000/tcp on 10.10.10.111
Discovered open port 10000/udp on 10.10.10.111
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.29 ((Ubuntu)) | Open |
| 6379	| redis | Redis key-value store 4.0.9 | Open |
| 10000	| HTTP | MiniServ 1.910 (Webmin httpd) | Open |

We also discovered that the service behind UDP port 10000
| Port Number | Service | Reason | State |
|-----|------------------|----------------------|----------------------|
| 10000	| webmin | udp-response ttl 63 (https on TCP port 10000) | open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. From the output, we discovered that port 80 might be vulnerable to SQL injection, while port 10000 might be vulnerbale to CVE-2006-3392

```
80/tcp    open  http             syn-ack ttl 63
|_http-sql-injection: 
|   Possible sqli for queries:
|     http://postman.htb:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|_    http://postman.htb:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       http://www.exploit-db.com/exploits/1997/
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://postman.htb

```
http://postman.htb/images               (Status: 301) [Size: 311] [--> http://postman.htb/images/]
http://postman.htb/upload               (Status: 301) [Size: 311] [--> http://postman.htb/upload/]
http://postman.htb/css                  (Status: 301) [Size: 308] [--> http://postman.htb/css/]
http://postman.htb/js                   (Status: 301) [Size: 307] [--> http://postman.htb/js/]
http://postman.htb/fonts                (Status: 301) [Size: 310] [--> http://postman.htb/fonts/]
http://postman.htb/server-status        (Status: 403) [Size: 299]
```

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://postman.htb/index.html           (Status: 200) [Size: 3844]
http://postman.htb/upload               (Status: 301) [Size: 311] [--> http://postman.htb/upload/]
http://postman.htb/css                  (Status: 301) [Size: 308] [--> http://postman.htb/css/]
http://postman.htb/js                   (Status: 301) [Size: 307] [--> http://postman.htb/js/]
http://postman.htb/fonts                (Status: 301) [Size: 310] [--> http://postman.htb/fonts/]
http://postman.htb/server-status        (Status: 403) [Size: 299]
```
### Autorecon

From the outputs of autorecon, we are able to determine the configurations of the server

```
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:637
run_id:73c691791a8db843715eabdd643e2037b9c304df
tcp_port:6379
uptime_in_seconds:7860
uptime_in_days:0
hz:10
lru_clock:7430281
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
```
### Redis enumeration

We shall first check if this redis server can be accessed while authenticated. From the output, we are able to view the keys of the redis server while we are unauthenticated. This provides a possible point of exploitation as we can access the redis server while authenticated and carry out malicious actions. We are also able to know that we have a user ```redis``` in this server.

```
┌──(kali㉿kali)-[~]
└─$ redis-cli -h 10.10.10.160 -p 6379
10.10.10.160:6379> keys *
(empty array)
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis"
```

### Web-content discovery

Exploring http://postman.htb:80 does not yield any desirable results. Navigating to http://postman.htb:10000 on the other hand, points us to another endpoint which is https://Postman:10000/

![Image of website at port 10000](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/port10000.PNG)

Next we will add the new endpoint to our /etc/hosts fil

```
10.10.10.160    postman.htb postman
```

Lastly, we will enumerate the endpoints on https://postman:10000 with Gobuster.

## Exploit
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag
