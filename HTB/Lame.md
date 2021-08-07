## Enumeration
Lets start with doing a network scan of the IP address to identify the open ports and the services running on the ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : run default nmap scripts
* O : identify OS running on each port
* -p- : Scan all ports
```code
sudo nmap -sV -sC -A -p- 10.10.10.3 -vv  
```
From the output of ```nmap```, we are able to know the following information about the ports: 
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 21	| FTP | vsftpd 2.3.4 |
| 22	| SSH | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) |
| 139	| netbios-ssn | Samba smbd 3.X - 4.X |
| 445	| netbios-ssn | Samba smbd 3.0.20-Debian |
| 3632	| distccd | distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) |

## Exploitation
### VSFTPD
From the results of ```searchsploit```, we know that ```vsftpd 2.3.4``` is vulnerable to backdoor command execution
```code
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remot | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote D | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote D | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service           | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution  | unix/remote/17491.rb
vsftpd 2.3.4 - Backdoor Command Execution  | unix/remote/49757.py
vsftpd 3.0.3 - Remote Denial of Service    | multiple/remote/49719.py
------------------------------------------- ---------------------------------
```
We will then scan for the vulnerability using ```nmap```
```code
sudo nmap --script ftp-vsftpd-backdoor.nse -p 21 10.10.10.3
```
However, the output shows that the port is not vulnerable to such a vulnerability.
### OpenSSH
The results from ```searchsploit``` of ```OpenSSH``` shows nothing promising, so we will be skipping this

