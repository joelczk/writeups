## Default Information
IP address : 10.10.10.241\
OS : Linux

## Enumeration
Firstly, let us enumerate all the open ports using ```Nmap```
* sV : service detection
* sC : Run default nmap scripts
* A : identify the OS behind each ports
* -p- : scan all ports

```bash
nmap -sC -sV -A -p- -T4 10.10.10.241 -vv
```

From the output of ```NMAP```, we are able to obtain the following information about the open TCP ports:
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 22	| SSH | OpenSSH 8.0 (protocol 2.0) | Open |
| 80	| HTTP | nginx 1.14.1 | Open |
| 9090	| zeus-admin | NIL | Open |

From the output, we are also able to observe an SSL certificate with issuer name
```
| ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US
| Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US/organizationalUnitName=ca-5763051739999573755
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-16T23:29:12
| Not valid after:  2030-06-04T16:09:12
| MD5:   0146 4fba 4de8 5bef 0331 e57e 41b4 a8ae
| SHA-1: 29f2 edc3 7ae9 0c25 2a9d 3feb 3d90 bde6 dfd3 eee5
| -----BEGIN CERTIFICATE-----
| MIIEpjCCAo6gAwIBAgIISl2h4yex5dEwDQYJKoZIhvcNAQELBQAwbzELMAkGA1UE
| BhMCVVMxKTAnBgNVBAoMIDRjZDkzMjk1MjMxODRiMGVhNTJiYTBkMjBhMWE2Zjky
| MR8wHQYDVQQLDBZjYS01NzYzMDUxNzM5OTk5NTczNzU1MRQwEgYDVQQDDAtkbXMt
| cGl0Lmh0YjAeFw0yMDA0MTYyMzI5MTJaFw0zMDA2MDQxNjA5MTJaME4xCzAJBgNV
| BAYTAlVTMSkwJwYDVQQKDCA0Y2Q5MzI5NTIzMTg0YjBlYTUyYmEwZDIwYTFhNmY5
| MjEUMBIGA1UEAwwLZG1zLXBpdC5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
| ggEKAoIBAQDZLaNRUf3BXYCd+Df9XZwMBmIwGzy/yX+9fPY6zGXYEYS7SeH9xZ7p
| GTUQMfk30Olb7rzftCKx9xSMHyoCJIAWFeVDV9vxJbGaEqFRvKHPeqcpQbRAKoqL
| xWaqbDZCXsBtTVYEwpRHvJ/GoGEWAQSbP1zkHzvVBkHuXE7Sj0zlW5NaBjvG/wEe
| wAB6crwnIYoqC550cMPritvjLwijk9nhwaPJ462anhJR5vFBvkR4nqD3mhIytUOb
| YMsfVoI0FiXtlBdu1ApABxtIdQgkY94eRAaMTkQ4Je0a8G5PlRZ20xCdqHb3xIZV
| 1mphZehkUeN0MzgEloL5TX8Zab+LZW+ZAgMBAAGjZzBlMA4GA1UdDwEB/wQEAwIF
| oDAJBgNVHRMEAjAAMCcGA1UdEQQgMB6CC2Rtcy1waXQuaHRigglsb2NhbGhvc3SH
| BH8AAAEwHwYDVR0jBBgwFoAUc8ssOet8O2a3+F2If4eQixSV7PwwDQYJKoZIhvcN
| AQELBQADggIBAG8kou51q78wdzxiPejMv9qhWlBWW3Ly5TvAav07ATx8haldEHvT
| LlFNGPDFAvJvcKguiHnGrEL9Im5GDuzi31V4fE5xjzWJdkepXasK7NzIciC0IwgP
| 7G1j11OUJOt9pmDRu2FkTHsSdr5b57P4uXS8rRF5lLCEafuemk6ORXa07b9xSrhC
| 3pWl22RtVlTFQ3wX8OsY0O3w5UUz8T/ezhKYUoM/mYQu+ICTAltlX4xae6PGauCh
| uaOY+/dPtM17KfHSbnCS1ZnR0oQ4BXJuYNfOR/C59L5B7TWzaOx5n1TD6JHOzrDu
| LxjO0OTeFaBRXL/s2Z5zNPTpZVnHyKEmHr5ZObjR6drDGqXfShPq5y70RfE28Pxm
| VTCdK4MCqDkELIlXrxzHQ/IPC8pxho6WEQsY80xZ1nXbLshlymh6clgblOetToZT
| HObIkEoPBtszUssFmWSN5hd4JcuyqSbJhichYtFQRASb2I4jWdP831LPir+MCGQv
| iAnieBF8zYus7kboTwfXmBGUt6r6eNE1yr4ZXPxOZoWq2ob6aAeLp2mqif+jgUSk
| fiG9oiAoyXWxw5pLfYHxVQGY+rGbjOs8gCAxBaTPt6dCkHZy/nU8PNZtV6QC4OME
| LI/sYtmG8XENdQhsLM2sewOMvv5rgsZ8SlX05Bw8C1xuq5Rg1KewCjlY
|_-----END CERTIFICATE-----
```
We shall first add our hostname to the /etc/hosts file
```
10.10.10.241    pit.htb dms-pit.htb
```
Now, we will do a scan on the UDP ports to find any possible open UDP ports
```
sudo nmap -sU -Pn 10.10.10.241 -T4 -vv 
```
From the output of ```NMAP```, we are able to obtain the following information about the open UDP ports
| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| 161	| snmp | NMPv1 server; net-snmp SNMPv3 server (public) | Open |
| 593	| http-rpc-epmap | admin-prohibited | Open |
| 17455	| unknown | admin-prohibited | Open |
| 34862	| unknown | admin-prohibited | Open |

## Discovery
Lets now visit the web server and observe what happens
* ```http://dms-pit.htb``` returns a status code of 403 which means that the webpage exists but we are not authorized to view it. 
* ```http://pit.htb:80``` returns a test page for Nginx HTTP Server on Red Hat Enterprise Linux 
* ```https://pit.htb:9090``` returns an admin page for CentOS

Next, we will run whatweb on the 3 URLs, and we observed that the whatweb output for ```https://pit.htb:9090``` contains ```cockpit```, which is a GUI made for sysadmins.
```
┌──(kali㉿kali)-[~]
└─$ whatweb https://pit.htb:9090
https://pit.htb:9090 [200 OK] Cookies[cockpit], Country[RESERVED][ZZ], HTML5, HttpOnly[cockpit], IP[10.10.10.241], PasswordField, Script, Title[Loading...], UncommonHeaders[content-security-policy,x-dns-prefetch-control,referrer-policy,x-content-type-options,cross-origin-resource-policy]
                                                                             
┌──(kali㉿kali)-[~]
└─$ whatweb http://pit.htb:80  
http://pit.htb:80 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.241], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
                                                                             
┌──(kali㉿kali)-[~]
└─$ whatweb http://dms-pit.htb
http://dms-pit.htb/ [403 Forbidden] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.241], Title[403 Forbidden], nginx[1.14.1]   
```
Directory enumeration with ```dirb``` on ```pit.htb:9090``` returns some meaningful output. However, upon furthur investigation they are not exploitable.
```
┌──(kali㉿kali)-[~]
└─$ dirb https://pit.htb:9090

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Aug 15 10:38:54 2021
URL_BASE: https://pit.htb:9090/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------
GENERATED WORDS: 4612

---- Scanning URL: https://pit.htb:9090/ ----
+ https://pit.htb:9090/favicon.ico (CODE:200|SIZE:819)                      
+ https://pit.htb:9090/ping (CODE:200|SIZE:24)                              
                                                                               
-----------------
END_TIME: Sun Aug 15 11:37:22 2021
DOWNLOADED: 4612 - FOUND: 2
```

From the previous ```NMAP``` scan, we know that port 161 is running on SNMP server and it is using a Public community string for authentication. 
Public community string is a default community string and is used as a password to access the SNMP server. However, this public string only allows users to have read access but not write access.
```
NMPv1 server; net-snmp SNMPv3 server (public)
```

Next, we will use ```snmpwalk``` to enumerate all the information on the SNMP server. The information that is outputted is very massive so we will redirect all the input into a file.
```
snmpwalk -v 1 -c public 10.10.10.241 .1 > snmp    
```
Analyzing the file, we are able to discover a few interesting information such as the existence of a directory ```/var/www/html/seeddms51x/seeddms```, which may be accessible from the website as well as, several credentials 
```
## Suspicious directory (might be accessible from the web server)
iso.3.6.1.4.1.2021.9.1.2.2 = STRING: "/var/www/html/seeddms51x/seeddms"
## Credentials on SNMP server
Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *
```

Let's now try to access ```/seeddms51x/seeddms``` on the web server.
* ```http://pit.htb/seeddms51x/seeddms``` returns a Nginx error on the webpage
* ```https://pit.htb:9090/seeddms51x/seeddms``` just returns a CentOS admin login page
*  ```http://dms-pit.htb/seeddms51x/seeddms/``` redirects us to a login page

However, we do not know the credentials to login to the SeedDMS. First we try to use the default username and password of ```admin``` to login to SeedDMS, but it seems that this username-password combination is invalid. Now, we will try to brute force login into the webpage using ```rockyou.txt``` file as the password file for the 2 users that we have discovered earlier \
Using intruder, we will bruteforce all the username-password combinations using clusterbomb mode. We would then realize that the password is also ```michelle``` as we are redirected to an internal URL in the response
```
HTTP/1.1 302 Found
Server: nginx/1.14.1
Date: Sun, 15 Aug 2021 19:31:18 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.24
Set-Cookie: mydms_session=30bc74de3d5d3f515046b817c127d006; path=/seeddms51x/seeddms/; HttpOnly
Location: /seeddms51x/seeddms/out/out.ViewFolder.php?folderid=1
Content-Length: 0
```
Logging into the site using the discovered credentials, we were able to find a ```CHANGELOG``` file that tells use that the SeedDMS is version ```5.1.15```. We will then look for exploits related to SeedDMS 5.1.15 using exploitDB.