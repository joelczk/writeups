## Default Information
IP address : 10.10.10.242
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
