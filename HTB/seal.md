## Default Information
OS : Linux\
IP Address: 10.10.10.250

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.250 -vv
```

From the output, we can obtain the SSL cert, and we will add the IP address to our ```/etc/hosts``` file so that we will be able to visit the site on our web browser.

```
ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK/localityName=Hackney/emailAddress=admin@seal.htb/organizationalUnitName=Infra
| Issuer: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK/localityName=hackney/emailAddress=admin@seal.htb/organizationalUnitName=Infra
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-05-05T10:24:03
| Not valid after:  2022-05-05T10:24:03
| MD5:   9c4f 991a bb97 192c df5a c513 057d 4d21
| SHA-1: 0de4 6873 0ab7 3f90 c317 0f7b 872f 155b 305e 54ef
| -----BEGIN CERTIFICATE-----
| MIIDiDCCAnACAWQwDQYJKoZIhvcNAQELBQAwgYkxCzAJBgNVBAYTAlVLMQ8wDQYD
| VQQIDAZMb25kb24xEDAOBgNVBAcMB2hhY2tuZXkxFTATBgNVBAoMDFNlYWwgUHZ0
| IEx0ZDEOMAwGA1UECwwFSW5mcmExETAPBgNVBAMMCHNlYWwuaHRiMR0wGwYJKoZI
| hvcNAQkBFg5hZG1pbkBzZWFsLmh0YjAeFw0yMTA1MDUxMDI0MDNaFw0yMjA1MDUx
| MDI0MDNaMIGJMQswCQYDVQQGEwJVSzEPMA0GA1UECAwGTG9uZG9uMRAwDgYDVQQH
| DAdIYWNrbmV5MRUwEwYDVQQKDAxTZWFsIFB2dCBMdGQxDjAMBgNVBAsMBUluZnJh
| MREwDwYDVQQDDAhzZWFsLmh0YjEdMBsGCSqGSIb3DQEJARYOYWRtaW5Ac2VhbC5o
| dGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDafbynnscdjWeuXTrD
| M36rTJ0y2pJpDDFe9ngryz/xw1KsoPfEDrDE0XHc8LVlD9cxXd/8+0feeV34d63s
| YyZ0t5tHlAKw1h9TEa/og1yR1MyxZRf+K/wcX+OwXYFtMHkXCZFH7TPXLKtCrMJM
| Z6GCt3f1ccrI10D+/dMo7eyQJsat/1e+6PgrTWRxImcjOCDOZ1+mlfSkvmr5TUBW
| SU3uil2Qo5Kj9YLCPisjKpVuyhHU6zZ5KuBXkudaPS0LuWQW1LTMyJzlRfoIi9J7
| E2uUQglrTKKyd3g4BhWUABbwyxoj2WBbgvVIdCGmg6l8JPRZXwdLaPZ/FbHEQ47n
| YpmtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJZGFznhRSEa2DTgevXl1T8uxpiG
| PPd9R0whiIv3s225ir9SWW3Hl1tVkEY75G4PJA/DxmBIHxIK1OU8kZMuJUevnSIC
| rK16b9Y5Y1JEnaQwfKCoQILMU40ED76ZIJigGqAoniGCim/mwR1F1r1g63oUttDT
| aGLrpvN6XVkqSszpxTMMHk3SqwNaKzsaPKWPGuEbj9GGntRo1ysqZfBttgUMFIzl
| 7un7bBMIn+SPFosNGBmXIU9eyR7zG+TmpGYvTgsw0ZJqZL9yQIcszJQZPV3HuLJ8
| 8srMeWYlzSS1SOWrohny4ov8jpMjWkbdnDNGRMXIUpapho1R82hyP7WEfwc=
|_-----END CERTIFICATE-----
```

```
nmap -sU -Pn 10.10.10.244 -T4 -vv 
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0) | Open |
| 443	| ssl/http | nginx 1.18.0 (Ubuntu) | Open |
| 8080	| http-proxy |  NIL | Open |

Now, we will do a scan on the UDP ports to find any possible open UDP ports. Hoowever, there isn't much information for UDP ports that is worth exploring.

```
nmap -sU -Pn 10.10.10.250 -T4 -vv 
```

## Discovery

First we will use ```gobuster``` to enumerate ```https://seal.htb```

```
                                                                                                 
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster dir -u https://seal.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://seal.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/28 03:07:39 Starting gobuster in directory enumeration mode
===============================================================
https://seal.htb/images               (Status: 302) [Size: 0] [--> http://seal.htb/images/]
https://seal.htb/admin                (Status: 302) [Size: 0] [--> http://seal.htb/admin/] 
https://seal.htb/icon                 (Status: 302) [Size: 0] [--> http://seal.htb/icon/]  
https://seal.htb/css                  (Status: 302) [Size: 0] [--> http://seal.htb/css/]   
https://seal.htb/js                   (Status: 302) [Size: 0] [--> http://seal.htb/js/]    
https://seal.htb/manager              (Status: 302) [Size: 0] [--> http://seal.htb/manager/]
https://seal.htb/http%3A%2F%2Fwww     (Status: 400) [Size: 813]                             
https://seal.htb/http%3A%2F%2Fyoutube (Status: 400) [Size: 813]                             
https://seal.htb/http%3A%2F%2Fblogs   (Status: 400) [Size: 813]                             
https://seal.htb/http%3A%2F%2Fblog    (Status: 400) [Size: 813]                             
https://seal.htb/**http%3A%2F%2Fwww   (Status: 400) [Size: 813]                             
https://seal.htb/External%5CX-News    (Status: 400) [Size: 804]                             
https://seal.htb/http%3A%2F%2Fcommunity (Status: 400) [Size: 813]                           
https://seal.htb/http%3A%2F%2Fradar   (Status: 400) [Size: 813]                             
https://seal.htb/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 813]                    
https://seal.htb/http%3A%2F%2Fweblog  (Status: 400) [Size: 813]                             
https://seal.htb/http%3A%2F%2Fswik    (Status: 400) [Size: 813] 
```

Next, we will use ```gobuster``` to enumerate ```https://seal.htb/admin```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://seal.htb/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://seal.htb/admin
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2021/08/28 03:07:50 Starting gobuster in directory enumeration mode
===============================================================
https://seal.htb/admin/dashboard            (Status: 403) [Size: 162]
https://seal.htb/admin/http%3A%2F%2Fwww     (Status: 400) [Size: 813]
https://seal.htb/admin/http%3A%2F%2Fyoutube (Status: 400) [Size: 813]
https://seal.htb/admin/http%3A%2F%2Fblogs   (Status: 400) [Size: 813]
https://seal.htb/admin/http%3A%2F%2Fblog    (Status: 400) [Size: 813]
https://seal.htb/admin/dashboard_small1     (Status: 403) [Size: 162]
https://seal.htb/admin/dashboard_large      (Status: 403) [Size: 162]
https://seal.htb/admin/**http%3A%2F%2Fwww   (Status: 400) [Size: 813]
https://seal.htb/admin/External%5CX-News    (Status: 400) [Size: 804]
https://seal.htb/admin/http%3A%2F%2Fcommunity (Status: 400) [Size: 813]
https://seal.htb/admin/http%3A%2F%2Fradar   (Status: 400) [Size: 813]  
https://seal.htb/admin/dashboard-dev        (Status: 403) [Size: 162]  
https://seal.htb/admin/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 813]
https://seal.htb/admin/http%3A%2F%2Fweblog  (Status: 400) [Size: 813]         
https://seal.htb/admin/http%3A%2F%2Fswik    (Status: 400) [Size: 813]         
                                                                              
===============================================================
2021/08/28 03:27:30 Finished
===============================================================
```
Similarly, we will use ```gobuster``` to enumerate ```https://seal.htb/manager```, but there are not output that caught my attention.0

Accessing ```http://seal.htb:8080```, we realize that this is a GitBucket portal for the site. Signing up for an account, we can login to the GitBucket account where we will be shown with a homepage of all the code changes of ```seal_market``` site.

![Gitbucket site](https://github.com/joelczk/writeups/blob/main/HTB/Images/seal/gitbucket_site.PNG)

From this site, we are able to obtain a set of credentials (```<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>```) that was previously committed by luis (Commit ```971f3aa3f0a0cc8aac12fd696d9631ca540f44c7```). Afterwards, we try to login to gitbucket on using this set of credentials, but it failed.

![Gitbucket credentials](https://github.com/joelczk/writeups/blob/main/HTB/Images/seal/gitbucket_exposed_credential.PNG)

Next, we will try to find the login page for ```https://seal.htb/admin```. This page redirects us to an error page that reveals that we are using ```Apache Tomcat 9.0.31```. From the documentation for Apache Tomcat and from the previous results from ```gobuster```, we realize that we are able to access the ```/manager/status``` endpoint with the credentials (However, we do not have sufficient permissions to view the ```/manager/text``` endpoint)

![/manager/status endpoint](https://github.com/joelczk/writeups/blob/main/HTB/Images/seal/manager_status_endpoint.PNG)
