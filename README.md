# sec_handover

## Description

sec_handover is a program that tries to handover a password to a program in a secure way.

## Example

Assume you have the shell script `/tmp/example.sh`, that requires a password and is 
called with two parameters `arg1` and `arg2`. The password can be read from stdin like 
the following example:

```shell
#!/bin/bash

echo "SHELL Called with: $*"
read -sp "SHELL Password: " password

sleep 10

echo "SHELL Found password: $password"

exit 0
```
You can create a configuration file called `/tmp/example.sign`, which contains the 
command, including the args and a list of files, which the command is based of. All files
have to be given with absolut paths.

```
[cmd]   

/bin/bash /tmp/example.sh arg1 arg2
     
[hash]

/bin/bash

/tmp/example.sh
```
Now you can sign the file `/tmp/example.sign` with the following command. At this point 
you are asked for the password, you want to hand over to the script. The result is stored
in an output file, here called `/tmp/example.launch`.

```
./sec_handover -s /tmp/example.sign -o /tmp/example.launch
Enter password:
Reenter password:
```
The output or launch file `/tmp/example.launch` is an encrypted file. The unencrypted 
content of the file looks like the following. It contains the origional command including
the arguments. For each file in the "hash" list an hmac is computed. With the hmacs 
manipulations on the files can be detected. The last thing is the password from the sign
call.

```
[cmd]
/bin/bash /tmp/example.sh arg1 arg2 
[hash]
21a1ec01b71db95338ba88da2ffcd64f34e174e6f765ee65b3903a1a7e1223bb1d9fa8d08f540d62c619b3372511e2a1d92b9164a61e6cafaa4aa66216be5781=/bin/bash
03c42c9417b11af7b960027028c78ac96251e30b669ec474aff335555d18a05ac0663e788153360230eca44e88987836ede40bdaadf0a364651b835d0a68b1d0=/tmp/example.sh
[password]
changeit
```
Now you can call the `sec_handover` with the launch file, which starts the shell script and hands over the password.

```
./sec_handover -l /tmp/example.launch
SHELL Called with: arg1 arg2
SHELL Found password: changeit
```

## TODO's

* Allow dynamic arguments on the launch call like `./sec_handover -l /tmp/example.launch arg3 arg4`
* Compute an hmac over the binaries of the `sec_handover` program and store the hmac with the encrypted
launch file. If the binaries are manipulated do not decrypt the program.

