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

Again the binary has ```init()``` and standard ```add() edit() show() delete()``` functions for the binary.

Let's examine each function and find the vulnerabilities

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

There is no vulnerabilities seen here it takes 16 bytes long input in the buffer of size 16 bytes.

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

Here again it takes the index and size from the users. By dynamic analysis I found that the memcmp is checking whether the ```__malloc_hook``` got corrupted or not. If it gets corrupted then the program will exit. So we can't hook the malloc for getting the shell and it is also checking that the allocated chunk size's & 0xf should be either 0x0 (or) 0x1 else it exits. This check is to prevent the fast bin attack so we can't do the fast bin attack.


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


Here, Takes the index from user and it sees if the index is greater than -1 and less than 4 and then it returns if the condtion is satisfied else exits. So we don't have any index bug here.

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

It only allocates the sizes of 0x0 to 0x80 and only one chunk can be allocated with the size greater than 0x80

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

Here we can edit the chunks as the chunks size are not stored there is overflow vulnerability as it is taking the size again from user input.

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

So it just takes the index and sees it is a valid index and just output's the given chunk contains. (So this function can be used for leaking libc address)

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

It takes the input for the index and checks the ```__free_hook``` is not corrupted and then frees the order and then clears all the pointers. So there is no UAF vulnerability.

So we just have a heap overflow vulnerability.


## The attack vector is

- First we need a heap leak and libc leak.
- getting heap leak is easy just we have to free a chunk and use overflow to leak the heap leak
- For getting the libc leak we have to overlap chunks. Created 4 chunks of size 0x60 and then using overflow change the size of chunk 2 to 0xe1 and then free it so now it thinks that the chunk size of 2 is the total chunk size of 2 and 3 now free it. This will go into unsorted bins. now allocate a new chunk of size 0x60 for which will overlap with chunk 3 and will have a libc address. After viewing the contents of chunk 3 we will have libc leak.
- Now as we can allocate a chunk of size greater than 0x80. We can use this to perform house of force (or) house of orange.
- I performed house of force for exploiting this program but house of orange can be used too
- Now as the libc is 2.23 we can use this to change the vtable of stdout structure to point to system and stdout flags should contain "/bin/sh" and the forged vtable should contain system. (Although we can find the exact offset and overwrite that)
- Allocate a chunk and fill out with address of the system and overwrite the vtable with this address and stdout flags with "/bin/sh" (We don't have to bother about the whole file structure just the ```_ IO_lock_t``` should point to writable memory address if so it is all good to go)

- when the next puts is called we will get the shell