```C
                                __  __      _                
                                \ \/ /_ __ | | ___  _ __ ___ 
                                 \  /| '_ \| |/ _ \| '__/ _ \
                                 /  \| |_) | | (_) | | |  __/
                                /_/\_\ .__/|_|\___/|_|  \___|
                                     |_|                     

                         -------Exploring linux rootkit techniques------

```


> [!Important]
> This repository was created due to my interest for rootkits as an educational purpose only.

## Features :

- 🟢 Syscall hooking
- 🟢 Set root using creds abuse
- 🟢 Char random & urandom read abuse
- 🟢 Hiding current loaded module
- 🟢 Hiding directories
...

> [!Note]
> Some of techniques use .h files you can find in /lib folder.

## Ressources : 

links to the articles I used for all code samples & techniques.

**Utils :** 
- https://docs.kernel.org/trace/kprobes.html
- https://github.com/xcellerator/linux_kernel_hacking/issues/3#issuecomment-757951117
- https://www.kernel.org/doc/html/v4.17/trace/ftrace-uses.html
- https://syscalls64.paolostivanin.com/
- https://github.com/torvalds/linux
- https://syscalls64.paolostivanin.com/

**Source code :** 
- https://github.com/xcellerator/linux_kernel_hacking
- https://github.com/MatheuZSecurity/Singularity

**Linux rootkit development :** 
- https://www.kernel.org/doc/html/v4.17/security/credentials.html
- https://xcellerator.github.io/posts/linux_rootkits_01/

**GCC macros :**
- https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
