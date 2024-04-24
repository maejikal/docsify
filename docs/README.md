*Link to game* [here](https://overthewire.org/wargames/bandit/)
1. it's okay to cheat :)
2. Run *man* or *--help* on a command you need help with
3. iirc the passwords change regularly (due to server updates and stuff) but the solutions remain the same

```shell
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

[what is ssh?](https://youtu.be/v45p_kJV9i4?si=0b6z2_EzX6SSrqj9) <br>

# 0-1
use common sense
# 1-2
**Problem**
The password for the next level is stored in a file called **-** located in the home directory

**Solution**

```shell
cat ./-
```

# 2-3
use common sense

# 3-4
**Problem**
The password for the next level is stored in a hidden file in the **inhere** directory.

**Solution**
1. List all the files in the directory with ```ls```

```shell
ls -la

total 12
drwxr-xr-x 2 root    root    4096 Oct  5 06:19 **.**
drwxr-xr-x 3 root    root    4096 Oct  5 06:19 **..**
-rw-r----- 1 bandit4 bandit3   33 Oct  5 06:19 .hidden
```

2. ```cat .hidden```

# 4-5
**Problem**
The password for the next level is stored in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.

**Solution**
1. ```cd inhere```
2. Listing the files, we get:

```shell
ls

-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09
```

3. Running the ```file``` command on a file returns the file type and from there we can deduce the only human-readable file in the directory. 
4. However it's tedious to run the command on every single file, plus we run into the problem of file starting with ```-```. We use the technique in [1-2](#1-2) to tackle this. 
5. ```file *``` would list down the types of all files in the directory and combining the technique above:

```shell
file ./*

./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
```

6. ```cat ./-file07```

# 5-6
**Problem**
The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

**Solution**
1. You could search for the file with separate conditions but it would be best if we can find a one line command that would only give return us one file. For this , just searching for the file with the correct size will do

```shell
du -a -b  | grep 1033

1033	./maybehere07/.file2
```

However, what if there are multiple files with the same size? 

2. ```find``` will list all files in a directory. There should also be enough options to combine the conditions

```shell
find . -type f -size 1033c ! -executable -exec file '{}' \;  | grep ASCII

./maybehere07/.file2: ASCII text, with very long lines (1000)
```

```find .```: find in the current working directory, <br>
```-type f```: the regular files (as opposed to directories, symbolic links, etc.) that are <br>
```-size 1033c```: 1033 bytes in size and <br>
```! -executable```: are not executable, <br>
```-exec file '{}' \;```: run the ```file``` command on every file found, <br>```{}``` represents the filename found by ```find```, ```\;``` marks the end of the command to be executed<br>
``` | grep ASCII```: filter to display only those are human-readable (ASCII)

# 6-7
**Problem**
The password for the next level is stored **somewhere on the server** and has all of the following properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

**Solution**
1. we should start searching for files from the root directory (somewhere on the server), ```find /```
2. to find files owned by user bandit7, ```-user bandit7```
3. to find files owned by group bandit6, ```-group bandit6```
4. 33 bytes in size, ```-size 33c```
5. hide ```Permission Denied``` errors, ```2>/dev/null```: basically dumps all errors into the /dev/null directory
6. Together,

```shell
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null

/var/lib/dpkg/info/bandit7.password
```

# 7-8
**Problem**
The password for the next level is stored in the file **data.txt** next to the word **millionth**

**Solution**
1. use ```grep``` to find the word millionth

```shell
grep "millionth" data.txt
millionth	TESKZC0XvTetK0S9xNwm25STk5iWrBvP
```

# 8-9
**Problem**
The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once

**Solution**
1. the ```sort``` command sorts the lines in a text file alphabetically by default
2. the ```uniq``` command filters out duplicate lines from the sorted input it received, ```-u``` tells it to only display the unique lines

```shell
sort data.txt  | uniq -u
EN632PlfYiZbn3PhVK3XOGSlNInNE00t
```

#  9-10
**Problem**
The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, preceded by several ‘=’ characters.

**Solution**
1. ```strings``` command extracts all readable strings from a file
2. ```grep``` can be used to find the several = characters

```shell
strings data.txt  | grep ===

x]T========== theG)"
========== passwordk^
========== is
========== G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
```

#  10-11
**Problem**
The password for the next level is stored in the file **data.txt**, which contains base64 encoded data

**Solution**
1. you can use online tools such as CyberChef to decode the base64 data
2. or you can use built-in base64 command line tools

```shell
base64 -d data.txt

The password is 6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM
```

#  11-12
**Problem**
The password for the next level is stored in the file **data.txt**, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

**Solution**
1. this is a simple caesar cipher, [ROT13](https://en.wikipedia.org/wiki/ROT13)
2. you can use online tools such as CyberChef to decrypt the cipher but there is also a command line solution with the ```tr``` command

```shell
cat data.txt  | tr "A-Za-z" "N-ZA-Mn-za-m"

The password is JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv
```

#  12-13
**Problem**
The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this  it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)

**Solution**
1. Create a directory to work on the file since we do not have permissions to work in the root directory.

```shell
mktemp -d
/tmp/tmp.sc0kPF5eiy
```

2. Copy ```data.txt``` into ```/tmp/tmp.sc0kPF5eiy```

```shell
cd /tmp/tmp.sc0kPF5eiy
cp ~/data.txt .
```

3. Reverse hexdump (data.txt) and output it into a file

```shell
cat data.txt | xxd -r > compressed_data
```

```xxd```: tool used for generating/reversing hex dumps

4. Running ```file``` on compressed_data,

```shell
file compressed_data

compressed_data: gzip compressed data, was "data2.bin", last modified: Thu Oct  5 06:19:20 2023, max compression, from Unix, original size modulo 2^32 573
```

5. Rename the file to its respective extension, decompress the gzip file

```shell
mv compressed_data compressed.gz
gzip -d compressed.gz
```

6. Repeat 4-5, checking the type of compressed data and use the correct method of decompressing until you get an ASCII text file

#  13-14
**Problem**
The password for the next level is stored in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this , you don’t get the next password, but you get a private SSH key that can be used to log into the next level. **Note:** **localhost** is a hostname that refers to the machine you are working on

**Solution** <br>
There are 2 solutions to solve this:<br>
**A.**
1. We are given a private ssh key, what we need to do is extract it into our local machine (own computer, not the server machine) and then use the credentials to log into the next level
2. ```scp``` can be used to transfer files between computers, run this command from your own terminal/command prompt (disconnected from game server)

```shell
scp -P 2220 bandit13@bandit.labs.overthewire.org:sshkey.private .
```

3. Enter the password to complete the download
4. Log in

```shell
ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

You will get a permission error:

```
Permissions 0640 for 'sshkey.private' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
```

5. Modify the key permissions such that only you can access it

```shell
chmod 700 sshkey.private
```

6. Step 4

**B.**
1. Since you are already logged into bandit13, you can ssh to bandit14 directly via localhost without disconnecting from the game server. 

```shell
ssh -i sshkey.private bandit14@localhost -p 2220
```

#  14-15
**Problem**
The password for the next level can be retrieved by submitting the password of the current  to **port 30000 on localhost**.

**Solution**
1. netcat (```nc```) is a utility program used for creating network connections and managing data flow. It functions on both TCP and UDP protocols, the building blocks of communication across networks. Use ```nc``` to connect to port 30000

```shell
nc localhost 30000
```

2. Enter the password found in previous level

#  15-16
**Problem**
The password for the next level can be retrieved by submitting the password of the current  to **port 30001 on localhost** using SSL encryption.
**Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…**

**Solution**
1. ```openssl``` is the foundation of secure communications on the internet (https) 

```shell
openssl s_client -connect localhost:30001

CONNECTED(00000003)
Can't use SSL_get_servername
...
---
read R BLOCK
```

2. After running the above, there will be a prompt on the line after read R BLOCK, paste the password and you will be given the password for the next level

#  16-17
**Problem**
The credentials for the next level can be retrieved by submitting the password of the current  to **a port on localhost in the range 31000 to 32000**. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

**Solution**
1. To scan for an open port, use ```nmap```. Checking the help page, 

```shell
nmap -h

Usage: nmap [Scan Type(s)] [Options] {target specification}
...
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
...
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
    ---
```

2. Since the port is on localhost and in the range 31000-32000, follow the usage guide above

```shell
nmap -sV localhost -p31000-32000

PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
```

3. Only port 31790 doesn't echo back whatever you send it, seems promising

```shell
openssl s_client localhost:31790

CONNECTED(00000003)
Can't use SSL_get_servername
...
---
read R BLOCK
```

4. Enter the password for current level

#  17-18
**Problem**
There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new**

**NOTE: if you have solved this  and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19**

**Solution**
1. To check for differences between 2 files, use ```diff```

```shell
diff --suppress-common-lines passwords.new passwords.old 

42c42
< hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg
---
> p6ggwdNHncnmCNxuAt0KtKVq185ZU7AW
```

2. The first password in the output is the new password since passwords.new was specified first before passwords.old in the command we ran

#  18-19
**Problem**
The password for the next level is stored in a file **readme** in the homedirectory. Unfortunately, someone has modified **.bashrc** to log you out when you log in with SSH.

**Solution**
1. ```ssh``` allows you to run a command on the target machine/environment after a connection is successfully established. 

```shell
ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
readme
```

2. Notice that ```ls``` was run successfully and we see the readme file that was mentioned above.
3. All we have to now is to login again and display the file

```shell
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
awhqfNnAbc1naukrpqDYcF95h7HoMTrC
```

#  19-20
**Problem**
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this  can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary. <br>
**Solution**
1. A *setuid binary* is a special type of program on Unix-based systems (like Linux and macOS) that has its permissions adjusted to allow it to run with the privileges of the file's owner, even if the user running the program is not the owner. (explained by Gemini)
2. There is a file named *bandit20-do* in the homedirectory

```shell
./bandit20-do

Run a command as another user.
  Example: ./bandit20-do id
```

3. We could probably just *cat* out /etc/bandit_pass/bandit20 then

```shell
./bandit20-do cat /etc/bandit_pass/bandit20

VxCazJaVykI6W36BkBU0mJTCM8rR95XT
```

#  20-21
**Problem**
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous  (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

**NOTE:** Try connecting to your own network daemon to see if it works as you think

**Solution**
1. The setuid binary can be used as follows:

```shell
./suconnect

Usage: ./suconnect <portnumber>
```

2. For the setuid binary to connect to localhost, we need to first create a server using ```nc```. the ```-l``` flag means listening and is needed to create a server. the ```-p``` flag is used to specify a port. then we can use ```echo``` to send the password via piping (because you only want a one-time server that sends a message and then disconnects). ```-n``` is to prevent newline characters ```&``` pushes the process to run in the background (so that you can continue to use the terminal/interface in the meantime).

```shell
echo -n 'VxCazJaVykI6W36BkBU0mJTCM8rR95XT' | nc -l -p 1234 &

[1] 1212452
```

3. Connect to the specified port using the setuid binary

```shell
./suconnect 1234

Read: VxCazJaVykI6W36BkBU0mJTCM8rR95XT
Password matches, sending next password
NvEJF7oVjkddltPSrdKEFOllh9V1IBcq
```

#  21-22
**Problem**
A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

**Solution**
1. ```cron``` jobs are background processes that run at regular intervals on your computer
2. ```cd``` to the directory

```shell
cd /etc/cron.d
```

3. We see that */usr/bin/cronjob_bandit22.sh* is running for bandit22

```shell
ls

cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24       e2scrub_all  sysstat
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root  otw-tmp-dir

cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

4. ```chmod``` is used to manage file permissions, ```chmod 644``` is changing the permissions to the directory */tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv*, it is allowing the owner of file to read and write, the 'group the file belongs to' and 'others' to only read from the directory. then the file writes the password for bandit22 into the directory. read about [chmod](https://www.redhat.com/sysadmin/introduction-chmod)

```shell
cat /usr/bin/cronjob_bandit22.sh

#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

5. We can just read the file directly without having to modify any permission

```shell
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff
```

#  22-23
**Problem**
A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

**NOTE:** Looking at shell scripts written by other people is a very useful skill. The script for this  is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

**Solution** <br>
1. navigate to the target directory and look at what the script is doing

```shell
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

2. the script is writing the password to /tmp/$mytarget. We just need to figure out what mytarget is. luckily, we are given the step to find it on line 4. ```echo I am user $myname | md5sum | cut -d ' ' -f 1```. We are bandit22 (to be sure, you can also run *whoami*), so running

```shell
echo I am user bandit22 | md5sum | cut -d " " -f 1

8169b67bd894ddbb4412f91573b38db3
```

3. Replacing *mytarget* with the result we just found, we get */tmp/8169b67bd894ddbb4412f91573b38db3*

```shell
cat /tmp/8169b67bd894ddbb4412f91573b38db3

WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff
```

#  23-24
**Problem**
A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

**NOTE:** This  requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this !

**NOTE 2:** Keep in mind that your shell script is removed once executed, so you may want to keep a copy around… <br>

**Solution**
1. Let's dissect the script. It executes (only if the owner of the file is bandit23) and deletes every file in /var/spool/bandit23/foo. So we need to create a script that will give us the password for the next level and move it into the directory to be executed

```shell
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

2. First, we create a temporary directory to work in. then we create a bash script with ```nano```.

```shell
mktemp -d

/tmp/tmp.EBCPI7mvfb

cd /tmp/tmp.EBCPI7mvfb

nano pass.sh
```

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp.EBCPI7mvfb/password
```

3. create a file for the password to be written into

```shell
touch password
```

4. Give the directory and file the relevant permissions

```shell
chmod +rwx password
chmod 777 /tmp/tmp.EBCPI7mvfb
```

5. Move the bash script into /var/spool/bandit23/foo

```shell
cp pass.sh /var/spool/bandit24/foo/pass.sh
```

6. Wait for a minute, try to read /var/spool/bandit24/foo/pass.sh. If the file doesn't exist, it means that the cron job has finished running
7. You can now read the password in the temporary directory

```shell
cat password

VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar
```

# 24-25
**Problem**
A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.  
You do not need to create new connections each time. <br>

**Solution**
1. Try connecting to port 30002 and entering a random code just to see the output
2. Write a script to generate a text file that contains the previous password and each of the 10000 combinations, each on a new line into a file called possibilities.txt. Next, pipe every line in possibilities.txt into netcat and output the result into results.txt. (do all of this in a temporary directory)

```bash
#!/bin/bash

for i in {0000..9999}
do
        echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i >> possibilities.txt
done

cat possibilities.txt | nc localhost 30002 > results.txt
```

3. Then we can sort and filter out all the lines which contain the string "Wrong"

```shell
sort results.txt | grep -v "Wrong"

Correct!
Exiting.
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
The password of user bandit25 is p7TaowMYrmu23Ol8hiZh9UvD0O9hpx8d
```

4. If you find that you were unable to get the password, it could be that the game server was updated to only accept up to 6000 brute force entries.
5. In this case, just break the *for* loop into 2, one from 0000 to 5999 and the other from 5999 to 9999. You would also need to put them into 2 different text files and bruteforce each one as well.

```bash
#!/bin/bash

for i in {0000..5999}
do
        echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i >> possibilities1.txt
done

for i in {5999..9999}
do
        echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i >> possibilities2.txt
done

cat possibilities2.txt | nc localhost 30002 > results2.txt
cat possibilities1.txt | nc localhost 30002 > results1.txt
exit
```

6. Search both text files for the the password.

# 25-26
**Problem**
Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not **/bin/bash**, but something else. Find out what it is, how it works and how to break out of it. <br>

**Solution**
1. There is a private ssh key for the next level in the current directory, we need to limit the rights to the key to use it to log in. 

```bash
ls

bandit26.sshkey

chmod 700 bandit26.sshkey
```

2. A default shell is the program that automatically launches when you open your terminal/command prompt. For macOS, the default shell is zsh.
3. On Unix-like systems, there is an important file called /etc/passwd that stores critical information about user accounts on the system. The default login shell can also be found here. To find the file for bandit26,

```shell
cat /etc/passwd | grep bandit26

bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

4. User bandit26 uses the Bourne Shell (sh). ```more``` is a shell command that allows files to be displayed in an interactive mode when the contents of the file are too large to fit into the terminal window. It allows the text editor 'vim' to be opened with ```v```. The script opens a file called *text.txt* in the home directory of bandit26 with the *more* program.

```shell
cat /usr/bin/showtext

#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
```

5. When we try to log in, the connection is immediately closed because the */usr/bin/showtext* is executed

```shell
ssh -i bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220
```

6. This is because the contents of *text.txt* is too short and ```more``` does not need to go into command mode. If we make the window extremely small, it will force the ```more``` command to run. Press 'v' to open vim. 
7. Change the shell to bash

```vim
:set shell=/bin/bash
```

8. Now, you have a shell you can use to read text.txt

```bash
ls

bandit27-do  text.txt

cat text.txt

5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
```

# 26-27
**Problem**
Good job getting a shell! Now hurry and grab the password for bandit27! <br>
**Solution**
1. In the shell of bandit26, we can run commands as bandit27 using the setuid binary given.

```shell
./bandit27-do cat /etc/bandit\_pass/bandit27

3ba3118a22e93127a4ed485be72ef5ea
```

# 27-28
**Problem**
There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo` via the port `2220`. The password for the user `bandit27-git` is the same as for the user `bandit27`.

Clone the repository and find the password for the next level. <br> <br>
**Solution** <br>
Read about git [here](https://youtu.be/mJ-qvsxPHpY?si=4OgIDh30A8PquvPY) <br>
[Cheatsheet](https://www.geeksforgeeks.org/git-cheat-sheet/)
1. Create and move to a temporary directory

```shell
mktemp -d
/tmp/tmp.2Ldm7pFdcy

cd /tmp/tmp.2Ldm7pFdcy
```

2. Clone the git repository, this will overwrite all the contents in the directory

```shell
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo

Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit27/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

bandit27-git@localhost's password: 
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (3/3), done.
```

3. Explore

```shell
ls

repo

cd repo

ls

README

cat README

The password to the next level is: AVanL161y9rsbcJIsFHuw35rjaOM19nR
```

# 28-29
**Problem**
There is a git repository at `ssh://bandit28-git@localhost/home/bandit28-git/repo` via the port `2220`. The password for the user `bandit28-git` is the same as for the user `bandit28`.

Clone the repository and find the password for the next level. <br>
**Solution**
1. Create and move to a temporary directory

```shell
mktemp -d
/tmp/tmp.tGm1qKPkoZ

cd /tmp/tmp.tGm1qKPkoZ
```

2. Clone repository, if you run into permission/rights error, correct it first by `chmod 777 /tmp/tmp.tGm1qKPkoZ`
3. Explore

```shell
ls

repo

cd repo

ls

README.md

cat README.md

# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```

4. Check the logs, there might have been modifications to the file

```shell
git log

commit 14f754b3ba6531a2b89df6ccae6446e8969a41f3 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    fix info leak

commit f08b9cc63fa1a4602fb065257633c2dae6e5651b
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    add missing data

commit a645bcc508c63f081234911d2f631f87cf469258
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    initial commit of README.md
```

5. Since the last commit was about fixing info leak...the password might be in the version before it which is commit f08b9cc63fa1a4602fb065257633c2dae6e5651b.

```shell
git show f08b9cc63fa1a4602fb065257633c2dae6e5651b

commit f08b9cc63fa1a4602fb065257633c2dae6e5651b
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    add missing data

**diff --git a/README.md b/README.md**
**index 7ba2d2f..b302105 100644**
**--- a/README.md**
**+++ b/README.md**

@@ -4,5 +4,5 @@ Some notes for level29 of bandit.

 ## credentials

 - username: bandit29

-- password: <TBD>

+- password: tQKvmcwNYcFS6vmPHIUSI3ShmsrQZK8S
```

# 29-30
**Problem**
There is a git repository at `ssh://bandit29-git@localhost/home/bandit29-git/repo` via the port `2220`. The password for the user `bandit29-git` is the same as for the user `bandit29`.

Clone the repository and find the password for the next level. <br>

**Solution**
1. Temp directory + clone repository. usual stuff
2. Read readme

```bash
cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```

3. In tech lingo, if something isn't in production, it's in development! so we can check if there are other branches to this project (basically, when documenting new features of a project in git, new features are stored in separate branches for testing purposes, if everything is good to go, the code will be merged into the main project branch)

```shell
git branch -a

* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
```

4. let's check out the 'dev' branch

```shell
git checkout dev

Branch 'dev' set up to track remote branch 'dev' from 'origin'.
Switched to a new branch 'dev'

ls
code  README.md

cat README.md

# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: xbhV3HpNGlTIdnjUrdAlPzc2L6y9EOnS
```

# 30-31
**Problem**
There is a git repository at `ssh://bandit30-git@localhost/home/bandit30-git/repo` via the port `2220`. The password for the user `bandit30-git` is the same as for the user `bandit30`.

Clone the repository and find the password for the next level. <br> <br>
**Solution**
1. Temp directory + clone repository. usual stuff
2. Read readme

```shell
cat README.md
just an epmty file... muahaha
```

3. Git tagging can be used to mark specific points in the history of the repository. e.g. release points of software
4. To view the tags in a branch,

```shell
git tag
secret
```

5. To see more details,

```shell
git show secret

OoffzGDlzhAlerFJ2cAiz1D41JW1Mhmt
```

# 31-32
**Problem**
There is a git repository at `ssh://bandit31-git@localhost/home/bandit31-git/repo` via the port `2220`. The password for the user `bandit31-git` is the same as for the user `bandit31`.

Clone the repository and find the password for the next level. <br> <br>
**Solution** <br>
[read](https://stackoverflow.com/questions/2745076/what-are-the-differences-between-git-commit-and-git-push) about the differences between "git commit" and "git push"
1. Usual stuff
2. Listing all contents in the directory

```shell
ls -la

total 20
drwxrwxr-x 3 bandit31 bandit31 4096 Mar 11 13:39 .
drwxrwxrwx 3 bandit31 bandit31 4096 Mar 11 13:39 ..
drwxrwxr-x 8 bandit31 bandit31 4096 Mar 11 13:39 .git
-rw-rw-r-- 1 bandit31 bandit31    6 Mar 11 13:39 .gitignore
-rw-rw-r-- 1 bandit31 bandit31  147 Mar 11 13:39 README.md
```

3. readme says the following

```shell
cat README.md

This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```

4. Create a key.txt that contains "May I come in?"

```shell
echo "May I come in?" > key.txt
```

5. .gitignore lists the file type that will not be pushed into the repository. this particular file ignores all files with the *.txt* extension. so making a commit and then pushing it will not work. 

```shell
cat .gitignore
*.txt
```

6. We need to use ```git add``` with the flag "-f" which will force files to be committed even if they are normally ignored. commit all files in the local repository and then push it into the remote repository

```shell
git add -f key.txt

git commit -a

git push origin master

remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: rmCBvG56y58BXzv98yZGdO7ATVL5dW8y 
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
```

# 32-33
**Problem**
After all this `git` stuff its time for another escape. Good luck! <br>
**Solution**
1. We realise upon testing the shell that all our commands are being made UPPERCASE

```bash
>> ls  
sh: 1: LS: not found
```

2. The only thing in Linux that is uppercase is variables. Some common that are good to know are:
- `TERM` -  current terminal emulation
- `HOME` - the path to home directory of currently logged in user
- `LANG` - current locales settings
- `PATH` - directory list to be searched when executing commands
- `PWD` - pathname of the current working directory
- `SHELL`/`0` - the path of the current user’s shell
- `USER` - currently logged-in user the variable <br>
`$0` has a reference to a shell, it might let us break out of the uppercase shell

```bash
>> $0
$ ls -la
total 28
drwxr-xr-x  2 root     root     4096 May  7  2020 .
drwxr-xr-x 41 root     root     4096 May  7  2020 ..
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
-rwsr-x---  1 bandit33 bandit32 7556 May  7  2020 uppershell
```

3. The file 'uppershell' can only be run by bandit33, running `whoami` confirms that we are bandit33.
4. We can just read the password file

```shell
cat /etc/bandit_pass/bandit33

odHo63fHiFqcWWJG9rLiLDtPm45KzUKy
```

# 33-34
**Problem**
**At this moment, level 34 does not exist yet.** <br><br>
**Solution**<br>

```shell
cat README.txt 

Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.
