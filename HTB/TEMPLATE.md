## Default Information
IP Address: {IP}\
OS: {OS}

## Enumeration

First, let's add the IP address and the host to our ```/etc/hosts``` file.

```
{IP}    {host}
```

Next, we will scan for open ports using masscan. Form the output, we realize that there are numerous open ports on this machine.

```
{masscan output} 
```

Now, we will scan these open ports using Nmap to identify the service behind each of these open ports.

| Port Number | Service | Version | State |
|-----|------------------|----------------------|----------------------|
| {Port}	| {Service} | {Version} | Open |

## Discovery

First, we will try to find the endpoints of {host}

```
{Gobuster output}
```

Next, we will try to find to find Vhosts on http://{host}, but we were unable to find any vhosts.

## Obtaining user flag

## Obtaining root flag
