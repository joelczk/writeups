# Funbox Rookie
## Enumeration
Lets start with doing a network scan of the IP address to identify possible assets (NOTE: This might take up quite some time)
```code
nmap -sV -sC -A -p- 192.168.54.107 -vv
```

## Exploit
Now we know that the service running running on port 21 is FTP, we will visit the FTP server in our browser and download all the ZIP files.
![image](https://user-images.githubusercontent.com/42378287/128554707-c95e2405-e5f0-4345-8b9b-03831450da2d.png)
