## Default Information
IP address : 10.10.10.242\
Operating system : Linux

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.10.242 -vv
```
From the output of ```nmap```, we are able to know the following informtion about the ports:
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |
| 80	| HTTP | Apache httpd 2.4.41 (Ubuntu) |

## Discovery
Visting the website does not yield any promising results as there are only 2 urls that can be found --> ```http://10.10.10.242``` and ```http://10.10.10.242/robots.txt```\
Next, we will scan the website with ```Nikto``` to uncover potential vulnerabilities in the website and the web server used. The following interesting information were uncovered:
```code
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: PHP/8.1.0-dev
```

## Exploitation
CVE 2020-1927 was found to be related to ```Apache/2.4.41```, but it was found not to be exploitable on the website.\
However, we were able to find a POC [here](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py) for ```PHP/8.1.0-dev```
