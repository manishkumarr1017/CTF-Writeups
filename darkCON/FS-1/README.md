## FS-1

we are given a binary and libc-2.23

The protections for the given binary:

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So the full protections are present.

Let's reverse the binary

```

void main(void)

{
  EVP_PKEY_CTX *ctx;
  long in_FS_OFFSET;
  int local_14;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  ctx = (EVP_PKEY_CTX *)0x40;
  alarm(0x40);
  init(ctx);
  while( true ) {
    while( true ) {
      while( true ) {
        banner();
        __isoc99_scanf(&DAT_00101540,&local_14);
        getchar();
        if (local_14 != 2) break;
        edit();
      }
      if (local_14 < 3) break;
      if (local_14 == 3) {
        delete();
      }
      else {
        if (local_14 != 4) goto LAB_00101216;
        show();
      }
    }
    if (local_14 != 1) break;
    add();
  }
LAB_00101216:
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

The binary has ```init()``` and standard functions such as ```add() edit() show() delete()``` are used like in any other heap challenge in CTF.

Let's examine each function and find the vulnerabilities.

```

int init(EVP_PKEY_CTX *ctx)

{
  long lVar1;
  void *__buf;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __buf = malloc(0x10);
  printf("Give me your name: ");
  read(0,__buf,0x10);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

There are no vulnerabilities seen here. It takes 16 bytes long input in the buffer of size 16 bytes.

```

void add(void)

{
  long lVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  size_t __size;
  void *pvVar5;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please state the index where you want to store this order?");
  lVar4 = getValidIndex();
  puts("Please state the size of the order?");
  __size = getValidSize();
  iVar3 = memcmp((void *)0x658480,&hook,8);
  if (iVar3 != 0) {
    puts("Don\'t spoil the service");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  pvVar5 = malloc(__size);
  *(void **)(orders + lVar4 * 8) = pvVar5;
  lVar2 = *(long *)(*(long *)(orders + lVar4 * 8) + -8);
  if (((ulong)((int)lVar2 + ((uint)(lVar2 >> 0x5f) >> 0x1c) & 0xf) -
       ((ulong)(lVar2 >> 0x3f) >> 0x3c) != 1) &&
     ((*(ulong *)(*(long *)(orders + lVar4 * 8) + -8) & 0xf) != 0)) {
    puts("Something went wrong, Please try again later.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  memset(*(void **)(orders + lVar4 * 8),0,0x20);
  puts("Please state the order?");
  read(0,*(void **)(orders + lVar4 * 8),__size);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
It takes the index and size from the users. By dynamic analysis I found that the ```memcmp()``` is checking whether the ```__malloc_hook``` has got corrupted or not. If it gets corrupted then the program will exit. So we can't hook the malloc for getting the shell. It also checks that the allocated chunk size & 0xf should be either 0x0 (or) 0x1 else it exits. This check is to prevent the fast bin attacks.


```

long getValidIndex(void)

{
  long in_FS_OFFSET;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_scanf(&DAT_00101326,&local_18);
  getchar();
  if ((-1 < local_18) && (local_18 < 4)) {
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return local_18;
  }
  printf("You can only place upto 4 orders");
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```


This function takes the index from user and it should be greater than -1 and less than 4. So we don't have any index bug here.

```
long getValidSize(void)

{
  long in_FS_OFFSET;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_scanf(&DAT_00101326,&local_18);
  getchar();
  if ((local_18 < 0) || (0x80 < local_18)) {
    if (flag != 0) {
      printf("We don\'t have much stock available");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    flag = 1;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_18;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

This function takes the  size as input and sees that the size is in the range 0x0 to 0x80. Only 1 chunk of size greater than 0x80 is allowed.

```
void edit(void)

{
  long in_FS_OFFSET;
  size_t local_20;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please state the index where you want to edit this order?");
  local_18 = getValidIndex();
  if (*(long *)(orders + local_18 * 8) == 0) {
    puts("Your order is already delivered");
  }
  else {
    puts("Please state the new size of the order?");
    __isoc99_scanf(&DAT_00101326,&local_20);
    getchar();
    puts("Please state the order?");
    read(0,*(void **)(orders + local_18 * 8),local_20);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here we specify an index to a chunk, and it checks if it is a non-null pointer. It prompts us the amount of bytes to scan in for editing the chunk. This leads to heap overflow vulnerability. 

** There is a heap overflow vulnerability **

```
void show(void)

{
  long lVar1;
  long lVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please state the order to show?");
  lVar2 = getValidIndex();
  if (*(long *)(orders + (long)(int)lVar2 * 8) == 0) {
    puts("Your order is already delivered");
  }
  else {
    puts(*(char **)(orders + (long)(int)lVar2 * 8));
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This is a standard function where we specify an index to a chunk, and it checks if it is a non-null pointer.If so the function prints the chunk contents. (We can abuse this for getting leaks) 

```
void delete(void)

{
  long lVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please state the order to deliver?");
  lVar4 = getValidIndex();
  iVar2 = (int)lVar4;
  if (*(long *)(orders + (long)iVar2 * 8) == 0) {
    puts("Your order is already delivered");
  }
  else {
    iVar3 = memcmp((void *)0x65a118,&hook,8);
    if (iVar3 != 0) {
      puts("Don\'t spoil the service");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    free(*(void **)(orders + (long)iVar2 * 8));
    *(undefined8 *)(orders + (long)iVar2 * 8) = 0;
    puts("Ok! Your order will be arrived shortly.");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
``` 

This function takes an input index and checks that if ```__free_hook``` is corrupted. If it is not, it frees the order and then makes all the pointers to 0. So there is no UAF vulnerability.

So we just have a heap overflow vulnerability.


## The attack vector is:

- First we need a heap leak and libc leak.
- Getting heap leak is easy. We have to free a chunk and use overflow vulnerability to get the heap leak.
- For getting the libc leak we have to overlap chunks. We have to create 4 chunks of size 0x60 and then we have to use overflow vulnerability for changing the size of chunk 2 to 0xe0. Then free the chunk 2. Now ```free``` thinks that the chunk 2 size is the total size of chunks 2 and 3 (which is 0xe0). This freed chunk will go into unsorted bins. Now allocate a new chunk of size 0x60 which will give a chunk at 2. We will have a libc address at the chunk 3 because the 0xe0 chunk got split into two chunks. 0x60 chunk is given when the malloc requested for it and the remaining chunk will still be in unsorted bin. After viewing the contents of chunk 3 we will have libc leak.
- We can allocate only one chunk of size greater than 0x80. We can use this to perform house of force (or) house of orange.
- I performed house of force but house of orange can also be performed.
- As the libc version is 2.23 we can forge the vtable to point to system and stdout flags should contain "/bin/sh" for executing ```system("/bin/sh")``` and the forged vtable should contain system at a particular offset. (Although we can find the exact offset and overwrite that but I just filled out a chunk with the address of system)
- Allocate a chunk and fill out the chunk with address of the system, overwrite the vtable with the address of the chunk and overwrite the stdout flags with "/bin/sh" (While overwriting values in the stdout structure, we don't have to bother about the whole file structure. we just have to take care of ```_ IO_lock_t``` which should point to a writable memory address and overwrite stdout flags and vtable for getting the shell.).

- when the next puts is called we will get the shell