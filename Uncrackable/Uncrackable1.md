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

### Android Manifest
From the AndroidManifest.xml file, we are able to get a few piece of basic information about the application.
- Minimum API level that the apk can run on: 19
- Targetted API level for the apk to run on: 28
- Backups can be extracted from any android device with developer options activated, but that is not very useful in our case here
```
<?xml version="1.0" encoding="utf-8"?>
<manifest android:versionCode="1" android:versionName="1.0" package="owasp.mstg.uncrackable1"
  xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="28" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true">
        <activity android:label="@string/app_name" android:name="sg.vantagepoint.uncrackable1.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

## Root detection
From the extracted android code (_sg.vantagepoint.uncrackable1.MainActivity_), we can see that this apk has root detection capabilities.

```
    public void onCreate(Bundle bundle) {
        if (c.a() || c.b() || c.c()) {
            a("Root detected!");
        }
        if (b.a(getApplicationContext())) {
            a("App is debuggable!");
        }
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }
```

The code for root detection can be found in _sg.vantagepoint.a.c_, and there are 3 ways the apk is checking whether the phone is rooted.
1. Obtain the PATH name from the environment variables, and check whether "su" is in any of the path.
2. Obtain the Build.TAGS and ensuring that the Build.TAGS are not null and that the Build.TAGS does not contain the string "test-keys"
3. Checking if the following files exist: 
   - "/system/app/Superuser.apk"
   - "/system/xbin/daemonsu"
   - "/system/etc/init.d/99SuperSUDaemon
   - "/system/bin/.ext/.su
   - "/system/etc/.has_su_daemon"
   - "/system/etc/.installed_su_daemon"
   - "/dev/com.koushikdutta.superuser.daemon/"

```
public class c {
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

To avoid root detection, all we have to do is to ensure that the function a(), b() and c() returns false. We can use frida to interact with the functions to return false in all these functions.

```
Java.perform(function(){
    var rootClass = Java.use("sg.vantagepoint.a.c");
    rootClass.a.implementation = function(v) {
        console.log("[+]Avoiding root detection in function a");
        return false;
    }
    
    rootClass.b.implementation = function(v) {
        console.log("[+]Avoiding root detection in function b");
        return false;
    }
    
    rootClass.c.implementation = function(v) {
        console.log("[+]Avoiding root detection in function c");
        return false;
    }
    console.log("[*]Root Bypass Completed");
})
```

To execute the script in Frida, we will use ```frida -U --no-pause -l avoidRootDetection.js -f owasp.mstg.uncrackable1```. The ```--no-pause``` is used to allow us to continue the execution in the mobile application after we bypass the root detection.

![Bypassing root detection](https://github.com/joelczk/writeups/blob/main/Uncrackable/Images/Uncrackable1/rootdetection.png)
