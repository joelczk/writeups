## Summary
Uncrackable1 is an Android application where the main aim is to find the secret string hidden somewhere in the application.

## Preparation

For this challenge, we will be using:
1. Genymotion Emulator
2. Frida
3. MobSF

## Exploitation
Firstly, we will first install the application on our Genymotion Emulator using adb

```
nil@ubuntu:~/Desktop/genymotion/tools$ ./adb install uncrackable.apk
Performing Push Install
uncrackable.apk: 1 file pushed. 20.9 MB/s (66651 bytes in 0.003s)
	pkg: /data/local/tmp/uncrackable.apk
Success
```

Afterwards, we will try to access the application on our Genymotion Emulator, and we realize that this application does root detection. Since our Genymotion Emulator is rooted 
by default, the application will throw an error message and exit.

Now, let's move on to do a static analysis to see how we can bypass the root detection. For me, I am lazy to extract the files using the traditional dex2jar and JD-GUI. Hence, I
will extract the source code using MobSF instead.
