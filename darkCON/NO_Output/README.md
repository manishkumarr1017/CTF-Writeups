## NO OUTPUT

Given the description:

```
Ok !!! This challenge doesn't give any output. Now try to get the shell.
The libc has tcache enabled (not libc-2.32) and you don't require libc for this challenge at all. This challenge can be done without having libc. You don't need to guess or bruteforce libc.
connection: nc 13.233.166.242 49153
```

So as the description says The binary doesn't give any output. No where in the binary we can see any output related functions like puts, printf etc. So we don't have any way for getting the leak.

Let's check the binary protections:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
``` 



By reversing the binary we get:

```
void main(void)

{
  EVP_PKEY_CTX *ctx;
  int local_c;
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  ctx = (EVP_PKEY_CTX *)0x40;
  alarm(0x40);
  init(ctx);
  while( true ) {
    while( true ) {
      __isoc99_scanf(&DAT_00402004,&local_c);
      getchar();
      if (local_c != 3) break;
      delete();
    }
    if (3 < local_c) break;
    if (local_c == 1) {
      add();
    }
    else {
      if (local_c != 2) break;
      edit();
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

The binary has ```init()``` and standard functions such as ```add() edit() show() delete()``` are used like in any other heap challenges in CTF.

Now we will check what does ```init()``` do

```

int init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  long in_FS_OFFSET;
  int local_2c;
  char acStack40 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_2c = 0;
  while (local_2c < 0x48) {
    iVar1 = fgetc(stdin);
    if ((char)iVar1 == '\n') break;
    acStack40[local_2c] = (char)iVar1;
    local_2c = local_2c + 1;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

we can see here that a buffer is of size 24 is declared but taking an input of size 72 (0x48) . So we clearly have an overflow vulnerability but we can't take the advantage of that (for now) because we have stack canary enabled.

So we can't exploit this overflow vulnerbility due to stack canary.(for now)

Let's continue our reversing:

```
void add(void)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int local_14;
  
  iVar1 = getIndex();
  iVar2 = getValidSize();
  *(int *)(chunks_len + (long)iVar1 * 4) = iVar2;
  pvVar3 = malloc((long)iVar2);
  *(void **)(chunks + (long)iVar1 * 8) = pvVar3;
  local_14 = 0;
  while( true ) {
    if (*(int *)(chunks_len + (long)iVar1 * 4) <= local_14) {
      return;
    }
    iVar2 = fgetc(stdin);
    if ((char)iVar2 == '\n') break;
    *(char *)(*(long *)(chunks + (long)iVar1 * 8) + (long)local_14) = (char)iVar2;
    local_14 = local_14 + 1;
  }
  return;
}
```

Here it allocates a chunk at the index and size we speciified and stores the pointer in global pointer ```chunks``` and the size is stored in ```chunks_len```.

```

int getIndex(void)

{
  int local_c;
  
  __isoc99_scanf(&DAT_00402004,&local_c);
  getchar();
  if ((-1 < local_c) && (local_c < 0x10)) {
    return local_c;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

This function takes the index from user and it should be greater than -1 and less than 16(0x10). So we don't have any index bug here.

```
int getValidSize(void)

{
  int local_c;
  
  __isoc99_scanf(&DAT_00402004,&local_c);
  getchar();
  if ((-1 < local_c) && (local_c < 0x1001)) {
    return local_c;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This function takes the  ize as input and sees that the size is in the range 0x0 to 0x1001.If it is not present in the given range it exits.

```

void edit(void)

{
  int iVar1;
  int iVar2;
  int local_10;
  
  iVar1 = getIndex();
  if (*(long *)(chunks + (long)iVar1 * 8) == 0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  local_10 = 0;
  while( true ) {
    if (*(int *)(chunks_len + (long)iVar1 * 4) <= local_10) {
      return;
    }
    iVar2 = fgetc(stdin);
    if ((char)iVar2 == '\n') break;
    *(char *)(*(long *)(chunks + (long)iVar1 * 8) + (long)local_10) = (char)iVar2;
    local_10 = local_10 + 1;
  }
  return;
}
```

we specify an index to a chunk, and it checks if it is a non-null pointer. If so it allows us to edit the contents in the chunk.

```
void delete(void)

{
  int iVar1;
  
  iVar1 = getIndex();
  if (*(long *)(chunks + (long)iVar1 * 8) != 0) {
    free(*(void **)(chunks + (long)iVar1 * 8));
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
Similarly above it asks for the index and frees the chunk. So we have UAF vulnerability (use after free).

As the libc has tcache we can use this to get the arbitary write previlege.

So for getting arbitary write previlege we will be using tcache poisoning attack.

## The attack vector is:

- Use the tcache poisoning attack for overwriting ```exit() to point init()``` and ```__stack_chk_fail() to leave;ret```
- Then use the overflow present in ```init()``` to perform ret2dlresolve attack to get the shell.
- Here in my [exploit](./exploit.py) I have manually exploited without using inbuil ret2dlresolve present in pwntools.
- I resolved ```free``` to  ```system```.
- Atlast used free("/bin/sh") for getting the shell.
