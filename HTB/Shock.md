## Default Information
IP address : 10.10.10.56\
Operating System : Linux

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.10.56 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 80	| HTTP | Apache httpd 2.4.18 (Ubuntu) |
| 2222	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) |
