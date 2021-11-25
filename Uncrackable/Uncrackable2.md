#### Summary
Similiar to Uncrackable1, the main objective of Uncrackable2 is to find the secret string hidden in the application. However, what is different in this challenge is that we will need to extract a native library and analyze the code in the native library. 

## Preparation

For this challenge, we will be using:
1. Genymotion Emulator
2. Frida
3. MobSF

## Exploitation
Firstly, we will install the apk file into our emulator using adb

```
joelczk@ubuntu:~/Desktop/genymotion/tools$ ./adb install UnCrackable-Level2.apk
Performing Push Install
UnCrackable-Level2.apk: 1 file pushed. 26.8 MB/s (901022 bytes in 0.032s)
	pkg: /data/local/tmp/UnCrackable-Level2.apk
Success

```

### Android Manifest
From the AndroidManifest.xml file, we are able to obtain a few pieces of information.
- Targetted SDK version : 28
- Minimum SDK Version : 19
- Backups can be extracted from the Android device if developer options are enable. However, this piece of information is not very useful in this case.
```
<?xml version="1.0" encoding="utf-8"?>
<manifest android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="28" android:compileSdkVersionCodename="9" package="owasp.mstg.uncrackable2" platformBuildVersionCode="1" platformBuildVersionName="1.0"
  xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="28" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true">
        <activity android:name="sg.vantagepoint.uncrackable2.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### Root detection
Similiar to UnCrackable1, we can see from the extracted code that this apk has root detection.

```
    public void onCreate(Bundle bundle) {
        init();
        if (b.a() || b.b() || b.c()) {
            a("Root detected!");
        }
        if (a.a(getApplicationContext())) {
            a("App is debuggable!");
        }
```

The code for root detection can be found from *sg.vantagepoint.a.b*, where there are 3 ways of checking if the android device is rooted.
1. Obtain the path variables and check if any of the string contains "su"
2. Obtain the Build.TAGS and checks if the Build.TAGS are not null and contains the string "test-keys"
3. Checks if the following paths exist:
- /system/app/Superuser.apk
- /system/xbin/daemonsu
- /system/etc/init.d/99SuperSUDaemon
- /system/bin/.ext/.su
- /system/etc/.has_su_daemon
- /system/etc/.installed_su_daemon
- /dev/com.koushikdutta.superuser.daemon/

We can use the same method that was used in Uncrackable1 to bypass all the root detection. However, for this time we shall use a "dirty" trick to bypass all the root detection at once by hijacking the control of the application that closes the apk. In this case, the pop-up telling us that there is root detection still occurs. However, clicking the pop-up will no longer close down the apk.

```
Java.perform(function(){
    console.log("[+] Bypassing root detection");
    var exit_function = Java.use("java.lang.System");
    exit_function.exit.implementation = function() {
        console.log("[+] Overwriting exit function");
    }
});
```

Another way that we could possibly avoid root detection is to overwrite the onClick() event that shuts down the apk once the button is clicked. Since we know that the onClick() event can be found in the sg.vantagepoint.uncrackable2.MainActivity$1.smali file that we have extracted, we can load this function and overwrite the onClick() event.

```
Java.perform(function() {
    console.log("[+] Bypassing root detection")
    var clazz_main = Java.use('sg.vantagepoint.uncrackable2.MainActivity$1')
     clazz_main.onClick.implementation = function () {
        console.log("[+] Overwriting onClick() function");        
    };
});
```

## Reversing Native Library

In *uncrackable2.MainActivity*, we observe that a Native Library is being loaded into the system

```
static {
    System.loadLibrary("foo");
}
```

From *uncrackable2.CodeCheck*, we also see that a native function is being called. Since there is only 1 native library being called earlier, we can infer that it is calling the native library

```
public class CodeCheck {
    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```
Let's try to extract this native library from the apk to furthur examine it. However before we extract the native library, we would need to know the arm processor version on the android emulator that we are running on.

```
(mobile) joelczk@ubuntu:~/Desktop/genymotion/tools$ ./adb shell getprop ro.product.cpu.abi
x86
```

Afterwards, we can then proceed to extract the native library. The native library can be extracted by renaming the apk file to .zip file and the native library can be found at /lib/x86.

### Reversing Native Library with IDA Pro
Opening libfoo.so file in IDA Pro, we are able to easily identify the key. In the *Java_sg_vantagepoint_uncrackable2_CodeCheck_bar* function, the string "Thanks for all the fish" is copied into the variable *s2* and a string comparison is made between *s2* and *v3*. Hence, the key must be "Thanks for all the fish"
![Obtaining the key from IDA Pro](https://github.com/joelczk/writeups/blob/main/Uncrackable/Images/Uncrackable2/key.png)

### Reversing Native Linrary with Frida
From *Java_sg_vantagepoint_uncrackable2_CodeCheck_bar* function, we realize that ```strncmp(v3, s2, 0x17u)``` is being called. However, for the strings *v3* and *s2* to be compared, they would first have to be loaded into memory. From here, we could modify the js script to hook ```strncmp``` function call and obtain the secret code.

```
Java.perform(function(){
    console.log("[+] Bypassing root detection");
    var exit_function = Java.use("java.lang.System");
    exit_function.exit.implementation = function() {
        console.log("[+] Overwriting exit function");
    }
    Interceptor.attach(Module.getExportByName("libfoo.so","strncmp"), {
        onEnter: function(args) {
            var param1 = args[0];
            var param2 = args[1];
            if (Memory.readUtf8String(param2).length == 23) {
                console.log("[+] Param 2 of length 23!")
                console.log("[+] Param1 : " + Memory.readUtf8String(param1))
                console.log("[+] Param2 : " + Memory.readUtf8String(param2));
            }
        }
    });
});
```
