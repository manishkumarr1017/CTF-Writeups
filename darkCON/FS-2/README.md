## FS-2

This time we are given a binary and libc-2.27

The binary protections 

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So the binary is fully protected.

Reversing the binary

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
      banner();
      __isoc99_scanf(&DAT_00102083,&local_14);
      getchar();
      if (local_14 != 3) break;
      delete();
    }
    if (3 < local_14) break;
    if (local_14 == 1) {
      add();
    }
    else {
      if (local_14 != 2) break;
      edit();
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This code is similar to FS-1 with little differences. Let us examine those differences.



```
int init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  void *__buf;
  
  __buf = malloc(0x10);
  printf("Give me your name: ");
  read(0,name,0x10);
  printf("Give me your address: ");
  read(0,__buf,0x10);
  DAT_001040b0 = __buf;
  iVar1 = printf("Welcome %s\n",name);
  return iVar1;
}
```

Here we can see something intersting, The ```name``` is global variable and just after the ```name``` the heap address for the ```address``` is stored. So we can leak this by filling the whole 16 bytes to leak the address of the ```address```. So now we have a heap leak.

```
void add(void)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  
  puts("Please state the index where you want to store this order?");
  iVar1 = getValidIndex();
  puts("Please state the size of the order?");
  iVar2 = getValidSize();
  *(int *)(orders_size + (long)iVar1 * 4) = iVar2;
  iVar2 = memcmp((void *)0x44ad48,&hook,8);
  if (iVar2 != 0) {
    puts("Don\'t spoil the service");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Please state the order?");
  pvVar3 = malloc((long)*(int *)(orders_size + (long)iVar1 * 4));
  *(void **)(orders + (long)iVar1 * 8) = pvVar3;
  read(0,*(void **)(orders + (long)iVar1 * 8),(long)*(int *)(orders_size + (long)iVar1 * 4));
  return;
}
```

Similar to ```add()``` in FS-1 with no fast bin check.

```
int getValidIndex(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_scanf(&DAT_00102083,&local_14);
  getchar();
  if ((-1 < local_14) && (local_14 < 0x10)) {
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return local_14;
  }
  printf("You can only place upto 16 orders");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
Unlike FS-1 we can allocate 16 chunks.

```
int getValidSize(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_scanf(&DAT_00102083,&local_14);
  getchar();
  if ((-1 < local_14) && (local_14 < 0x301)) {
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return local_14;
  }
  printf("We don\'t have much stock available");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

We can only allocate a chunk with maximum of size 0x300.

```
void edit(void)

{
  int iVar1;
  ulong uVar2;
  
  puts("Please state the index where you want to edit this order?");
  iVar1 = getValidIndex();
  if (*(long *)(orders + (long)iVar1 * 8) == 0) {
    puts("Your order is already delivered");
  }
  else {
    puts("Please edit the order?");
    uVar2 = read(0,*(void **)(orders + (long)iVar1 * 8),
                 (long)*(int *)(orders_size + (long)iVar1 * 4));
    printf("%d\n",uVar2 & 0xffffffff);
    *(undefined *)((long)(int)uVar2 + *(long *)(orders + (long)iVar1 * 8)) = 0;
  }
  return;
}
```

So this time the order_size has been stored so we don't have a full overflow. But the code ```*(undefined *)((long)(int)uVar2 + *(long *)(orders + (long)iVar1 * 8)) = 0;``` adds a null byte at the end leads to null byte overflow.

```
void delete(void)

{
  int iVar1;
  int iVar2;
  
  puts("Please state the order to deliver?");
  iVar1 = getValidIndex();
  if (*(long *)(orders + (long)iVar1 * 8) == 0) {
    puts("Your order is already delivered");
  }
  else {
    iVar2 = memcmp((void *)0x44ca00,&hook,8);
    if (iVar2 != 0) {
      puts("Don\'t spoil the service");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    free(*(void **)(orders + (long)iVar1 * 8));
    *(undefined8 *)(orders + (long)iVar1 * 8) = 0;
    puts("Ok! Your order will be arrived shortly.");
  }
  return;
}
```

No vulnerabilities can be seen here. No UAF.

There is no show function too So leaking libc might be difficult.

## So the only vulnerability is null byte overflow we have to use this to get the shell

## The attack vector is:

- First we have to perform house of einherjar combining with tcache poisoning attack for getting an arbitary write. But we don't have any leak besides heap so we partially overwrite the ```main_arena``` to point to the ```stdout``` structure to get a chunk on the stdout structure.
- Then we will overwrite the stdout structure with the flags ```0xfbad1800``` and partailly overwrite ```write_base``` to ```\x00``` 

- As we can't overwrite the hooks of malloc and free. We just have to hijack puts for getting the shell

Here is the full writeup for hijacking [puts](https://faraz.faith/2020-10-13-FSOP-lazynote/)