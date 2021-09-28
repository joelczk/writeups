## Default Information
IP Address: 10.10.10.68\
OS: Linux


## Enumeration
First, let us add the the IP address and host to our ```/etc/hosts``` file

```
10.10.10.68    bashed.htb
```

Next, let us do a masscan to identify the ports of interest

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.68 --rate=1000 -e tun0

[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-09-28 13:30:32 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.68 
```

Using the ports obtained from masscan, we will then run a scan using nmap to enumerate the services operating behind each port. For this machine, only port 80 is open, which
means that only web service is available on this machine.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.18 ((Ubuntu)) | Open |

## Discovery

First, we will use Gobuster to find the endpoints that are accessible from http://bashed.htb

```
──(kali㉿kali)-[~]
└─$ gobuster dir -u http://bashed.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bashed.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/28 09:31:43 Starting gobuster in directory enumeration mode
===============================================================
http://bashed.htb/uploads              (Status: 301) [Size: 310] [--> http://bashed.htb/uploads/]
http://bashed.htb/images               (Status: 301) [Size: 309] [--> http://bashed.htb/images/] 
http://bashed.htb/php                  (Status: 301) [Size: 306] [--> http://bashed.htb/php/] 
http://bashed.htb/css                  (Status: 301) [Size: 306] [--> http://bashed.htb/css/] 
http://bashed.htb/dev                  (Status: 301) [Size: 306] [--> http://bashed.htb/dev/]  
http://bashed.htb/js                   (Status: 301) [Size: 305] [--> http://bashed.htb/js/] 
http://bashed.htb/fonts                (Status: 301) [Size: 308] [--> http://bashed.htb/fonts/]  
http://bashed.htb/server-status        (Status: 403) [Size: 298]
```

Next, we will try to enumerate for VHosts using Gobuster. However, there doesn't seem to have any interesting outputs. 

Navigating to http;//bashed.htb/dev, we notice that there are a few php files that can be accessed. Clicking on the ```phpbash.php``` file, we realize that we have spawned a web shell

![Spawning web shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bashed/web_shell.PNG)

## Obtaining user flag

Using the web shell that we obtained, we will now get our user flag

```
www-data@bashed:/home# cd /home
www-data@bashed:/home# ls
arrexel
scriptmanager
www-data@bashed:/home# ls -la arrexel
total 36
drwxr-xr-x 4 arrexel arrexel 4096 Dec 4 2017 .
drwxr-xr-x 4 root root 4096 Dec 4 2017 ..
-rw------- 1 arrexel arrexel 1 Dec 23 2017 .bash_history
-rw-r--r-- 1 arrexel arrexel 220 Dec 4 2017 .bash_logout
-rw-r--r-- 1 arrexel arrexel 3786 Dec 4 2017 .bashrc
drwx------ 2 arrexel arrexel 4096 Dec 4 2017 .cache
drwxrwxr-x 2 arrexel arrexel 4096 Dec 4 2017 .nano
-rw-r--r-- 1 arrexel arrexel 655 Dec 4 2017 .profile
-rw-r--r-- 1 arrexel arrexel 0 Dec 4 2017 .sudo_as_admin_successful
-r--r--r-- 1 arrexel arrexel 33 Dec 4 2017 user.txt
www-data@bashed:/home# cd arrexel
www-data@bashed:/home/arrexel# cat user.txt
<Redacted user flag>
```

## Obtaining root flag

Executing ```sudo -l```, we realize that we can execute commands as the user ```scriptmanager```, but with root privileges

```

www-data@bashed:/var/www/html/uploads# sudo -l
Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

