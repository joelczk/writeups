# Emdee Five for life
This is a simple web CTF challenge where our main objective is to MD5 encrypt a given text to obtain our flag.

# Exploit
For this exploitation, all we have to do is to write a script to first encrypt the given text in MD5 and send it back to the website. 

```
import requests
import hashlib
from bs4 import BeautifulSoup

session = requests.Session()
resp = session.get("http://209.97.132.64:31640")
soup = BeautifulSoup(resp.text, "html.parser")
text = soup.find_all('h3')[0].text
result = hashlib.md5(text.encode('utf-8')).hexdigest()

data = {'hash': result}
post_resp = session.post("http://209.97.132.64:31640", data=data)
post_text = post_resp.text
post_soup = BeautifulSoup(post_text, "html.parser")
post_flag = post_soup.find_all('p')[0].text
if "HTB{" in post_flag:
    print(post_flag)
else:
    print("Try again! Too slow!"))
```

Executing the script will allow us to obtain the flag

```
┌──(HTB)─(kali㉿kali)-[~/Desktop]
└─$ python3 script.py
<HTB Flag>
```
