# Cat
Cat is a one of HTB's mobile challenge that revolves around the extraction of an Android backup file. 

## Exploitation
Extracting out the files from the downloaded challenge files, we are able to retrieve a ```cat.ab``` file, which is an Android Backup file.

```
┌──(kali㉿kali)-[~/Desktop]
└─$ file cat.ab        
cat.ab: Android Backup, version 5, Compressed, Not-Encrypted
```

Next, we will just have to extract the backup file to a tar folder using the [Android Backup Extractor](https://github.com/nelenkov/android-backup-extractor)

```
┌──(kali㉿kali)-[~/Desktop]
└─$ java -jar abe.jar unpack cat.ab cat.tar                              1 ⨯
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
0% 1% 2% 3% 4% 5% 6% 7% 8% 9% 10% 11% 12% 13% 14% 15% 16% 17% 18% 19% 20% 21% 22% 23% 24% 25% 26% 27% 28% 29% 30% 31% 32% 33% 34% 35% 36% 37% 38% 39% 40% 41% 42% 43% 44% 45% 46% 47% 48% 49% 50% 51% 52% 53% 54% 55% 56% 57% 58% 59% 60% 61% 62% 63% 64% 65% 66% 67% 68% 69% 70% 71% 72% 73% 74% 75% 76% 77% 78% 79% 80% 81% 82% 83% 84% 85% 86% 87% 88% 89% 90% 91% 92% 93% 94% 95% 96% 97% 98% 99% 100% 
4853760 bytes written to cat.tar.
```

Afterwards, we will extract the tar file to obtain 2 folders - apps and shared

```
┌──(kali㉿kali)-[~/Desktop]
└─$ tar -xf cat.tar  
```

Viewing the shared/0/Pictures folder, we are able to find a bunch of images, that are mainly cat images. However, out of these images, IMAG0004.jpg is an image of a human. 
Upon closer inspection of this image, we are able to discover that the flag is hidden in the image.

FLAG: HTB{ThisBackupIsUnprotected}
