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
command, including the args and a list of files, which the command is based of.
```
[cmd]   

/bin/bash /tmp/example.sh arg1 arg2
     
[hash]

/bin/bash

/tmp/example.sh
```

