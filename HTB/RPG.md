## Enumeration
For this endgame challenge, we are provided with 2 IP addresses --> ```10.13.38.18``` and ```10.13.38.19```
First, we will try to do a ```NMAP``` scan on the 2 IP addresses
* sV : service detection
* sC : run default nmap scripts
* A : identify OS running on each port
* -p- : Scan all ports
```code
sudo nmap -sC -sV -A 10.13.38.18 -p- -T4 -vv  
sudo nmap -sC -sV -A 10.13.38.19 -p- -T4 -vv  
```
From the output of ```NMAP```, we can identify the following information about the ports at the respective IP addresses
| Port Number | Service | Version | IP address |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | 10.13.38.18 |
| 80	| http | Apache httpd 2.4.29 (Ubuntu) | 10.13.38.18 |
| 3000	| ppp? | NIL | 10.13.38.18 |
| 80	| http | Microsoft IIS httpd 10.0 | 10.13.38.19 |
| 8081	| http | Apache Tomcat 8.5.41 | 10.13.38.19 |

## Discovery
### 10.13.38.18
10.13.38.18 is a web server running on Ubuntu and Apache, while 10.13.38.18:3000 is a rocket chat application. However, new user registration is currently disabled 
which means that CVE-2021-22911 cannot be exploited on the current version of Rocketchat
### 10.13.38.19
