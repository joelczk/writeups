# Where are the robots - Writeup

## Problem
Can you find the robots? https://jupiter.challenges.picoctf.org/problem/56830/ or http://jupiter.challenges.picoctf.org:56830

## Solution
1. Looking at the question name, this might be related to the `robots.txt` file in any webpages.
2. Visiting `https://jupiter.challenges.picoctf.org/problem/56830/robots.txt`, we are presented with the following:
```code
User-agent: *
Disallow: /1bb4c.html
```
3. This tells us that the flag might have been hidden in the `/1bb4c.html` page, and when we visit the page, we are presented with the flag.
```code
Guess you found the robots
picoCTF{ca1cu1at1ng_Mach1n3s_1bb4c}
```

## Flag
flag : picoCTF{ca1cu1at1ng_Mach1n3s_1bb4c}
