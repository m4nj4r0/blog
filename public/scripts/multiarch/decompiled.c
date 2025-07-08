#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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

uint8_t neg1_4[] = {0xff, 0xff, 0xff, 0xff};
uint8_t zeros3[] = {0, 0, 0};
uint8_t zeros2[] = {0, 0};

char *getflag()
{
    char *v0; // rbx

    v0 = getenv("FLAG");
    if ( !v0 )
        fwrite("[E] no $FLAG set! do you need to hack harder?\n", 1uLL, 0x2EuLL, stderr);
    return v0;
}

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

void vm_destroy(VM *vm)
{
    MemSeg *add_mems; // rbx
    int v2; // r12d

    munmap(vm->code, 0x1000uLL);
    vm->code = 0LL;
    munmap(vm->data, 0x1000uLL);
    vm->data = 0LL;
    munmap(vm->stack, 0x1000uLL);
    free(vm->bitmask);
    if ( vm->mems_cnt )
    {
        add_mems = vm->add_mems;
        v2 = 0;
        do
        {
        free(add_mems->data);
        add_mems->data = 0LL;
        ++v2;
        ++add_mems;
        }
        while ( vm->mems_cnt > v2 );
    }
    free(vm);
}

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

bool vm_read_mem(VM *vm, uint32_t addr, void *data, size_t size)
{
    void *parsed_addr; // rax

    parsed_addr = vm_parse_addr(vm, addr, size);
    if ( parsed_addr )
    {
        memcpy(data, parsed_addr, size);
        return 1;
    }
    else
    {
        fprintf(stderr, "[E] invalid eva, can't read: %#x\n", addr);
        return 0;
    }
}

bool vm_load_int(VM *vm, uint32_t addr, uint32_t *result)
{
    return vm_read_mem(vm, addr, result, 4uLL);
}

bool vm_load_word(VM *vm, uint32_t addr, void *result)
{
    return vm_read_mem(vm, addr, result, 2uLL);
}

bool vm_load_byte(VM *vm, uint32_t addr, void *result)
{
    return vm_read_mem(vm, addr, result, 1uLL);
}

bool vm_write_mem(VM *vm, uint32_t addr, const void *src, size_t size)
{
    void *parsed_addr; // rax

    parsed_addr = vm_parse_addr(vm, addr, size);
    if ( parsed_addr )
    {
        memcpy(parsed_addr, src, size);
        return 1;
    }
    else
    {
        fprintf(stderr, "[E] invalid eva, can't write: %#x\n", addr);
        return 0;
    }
}

bool vm_store_int(VM *vm, uint64_t addr, uint32_t value)
{
    uint32_t data[3]; // [rsp+Ch] [rbp-Ch] BYREF

    data[0] = value;
    return vm_write_mem(vm, addr, data, 4uLL);
}

bool vm_store_word(VM *vm, uint32_t addr, uint16_t value)
{
    uint16_t data[6]; // [rsp+Ch] [rbp-Ch] BYREF

    data[0] = value;
    return vm_write_mem(vm, addr, data, 2uLL);
}

bool vm_store_byte(VM *vm, uint32_t addr, uint8_t value)
{
    uint8_t data[12]; // [rsp+Ch] [rbp-Ch] BYREF

    data[0] = value;
    return vm_write_mem(vm, addr, data, 1uLL);
}

bool vm_stack_pushb(VM *vm, uint8_t value)
{
    uint32_t SP; // esi

    SP = vm->SP - 1;
    vm->SP = SP;
    return vm_store_byte(vm, SP, value);
}

bool vm_stack_pushw(VM *vm, uint16_t value)
{
    uint32_t SP; // esi

    SP = vm->SP - 2;
    vm->SP = SP;
    return vm_store_word(vm, SP, value);
}

bool vm_stack_push(VM *vm, uint32_t value)
{
    uint64_t SP; // rsi

    SP = vm->SP - 4;
    vm->SP = SP;
    return vm_store_int(vm, SP, value);
}

bool vm_stack_popb(VM *vm, uint8_t *result)
{
    bool byte; // al

    byte = vm_load_byte(vm, vm->SP, result);
    if ( byte )
        ++vm->SP;
    return byte;
}

bool vm_stack_popw(VM *vm, uint16_t *result)
{
    bool ok; // al

    ok = vm_load_word(vm, vm->SP, result);
    if ( ok )
        vm->SP += 2;
    return ok;
}

bool vm_stack_pop(VM *vm, uint32_t *result)
{
    bool read_ok; // al

    read_ok = vm_load_int(vm, vm->SP, result);
    if ( read_ok )
        vm->SP += 4;
    return read_ok;
}

bool vm_sys_mode(VM *vm)
{
    bool result; // al

    result = fwrite("[D] executing as system now\n", 1uLL, 0x1CuLL, stderr);
    vm->mode_flag = 1;
    return result;
}

bool vm_user_mode(VM *vm)
{
    bool result; // al

    result = fwrite("[D] executing as user now\n", 1uLL, 0x1AuLL, stderr);
    vm->mode_flag = 0;
    return result;
}

bool vm_check_syscall(VM *vm)
{
    unsigned int RA_low; // edx
    bool good; // al

    RA_low = (uint8_t)(vm->RA);
    good = 1;
    if ( RA_low > 5 )
    {
        if ( RA_low == 6 )
        {
            return vm->mode_flag != 0;
        }
        else
        {
            fprintf(stderr, "[E] invalid syscall! %#x\n", RA_low);
            return 0;
        }
    }
    return good;
}

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

bool vm_input_int(VM *vm, uint32_t *addr)
{
    __isoc99_fscanf(stdin, "%u", addr);
    fgetc(stdin);
    return 1;
}

bool vm_input_mem(VM *vm, uint32_t addr, uint8_t size)
{
    size_t size_; // r13
    char *tmp_data; // r12
    char *tmp_data_; // rbx
    char v6; // al
    bool v7; // bl

    size_ = size;
    tmp_data = (char *)calloc(1uLL, size);
    tmp_data_ = tmp_data;
    do
    {
        if ( tmp_data_ == &tmp_data[size_] )
            break;
        v6 = fgetc(stdin);
        *tmp_data_++ = v6;
    }
    while ( v6 != 10 );
    tmp_data[strcspn(tmp_data, "\n")] = 0;
    v7 = vm_write_mem(vm, addr, tmp_data, size_);
    free(tmp_data);
    return v7;
}

bool vm_output_mem(VM *vm, uint32_t addr, uint8_t size)
{
    size_t size_; // rbp
    void *tmp_data; // rbx
    bool ok; // r12

    size_ = size;
    tmp_data = malloc(size);
    ok = vm_read_mem(vm, addr, tmp_data, size_);
    if ( ok )
    {
        fwrite(tmp_data, 1uLL, size_, stdout);
        free(tmp_data);
    }
    else
    {
        free(tmp_data);
        vm->err_flag = 1;
    }
    return ok;
}

bool vm_srand(VM *vm, unsigned int seed)
{
    srand(seed);
    return 1;
}

bool vm_rand(VM *vm, uint32_t *result)
{
    *result = (uint16_t)rand();
    *result |= rand() << 16;
    return 1;
}

bool vm_print_flag(VM *vm)
{
    const char *flag; // rax

    flag = vm->getflag();
    if ( flag )
    {
        fprintf(stdout, "Here, have a flag: %s\n", flag);
        return 1;
    }
    else
    {
        vm->err_flag = 1;
        return 0;
    }
}

bool vm_expand_mem(VM *vm, int addr, uint32_t *result)
{
    uint8_t mems_cnt; // r12
    bool ok; // al
    uint32_t vaddr; // ebx
    void *data; // rax
    uint64_t ind; // rdx

    mems_cnt = vm->mems_cnt;
    ok = 0;
    if ( mems_cnt != 5 )
    {
        vaddr = addr & 0xFFFFF000;
        if ( (addr & 0xFFFFF000) == 0 )
            vaddr = 0xA000;
        while ( vm_parse_addr(vm, vaddr, 1uLL) )
            vaddr += 4096;
        vm->mems_cnt = mems_cnt + 1;
        data = calloc(0x200uLL, 1uLL);
        ind = mems_cnt;
        vm->add_mems[ind].data = data;
        vm->add_mems[ind].vaddr = vaddr;
        *result = vaddr;
        return 1;
    }
    return ok;
}

bool vm_execute_stack(VM *vm)
{
    bool read_ok; // bp
    uint8_t sysnum; // [rsp+7h] [rbp-31h] BYREF
    int arg2; // [rsp+8h] [rbp-30h] BYREF
    uint32_t arg1; // [rsp+Ch] [rbp-2Ch] BYREF
    uint8_t instr_type; // [rsp+13h] [rbp-25h] BYREF
    unsigned int instr; // [rsp+14h] [rbp-24h] BYREF
    uint64_t canary; // [rsp+18h] [rbp-20h]

    canary = __readfsqword(0x28u);
    read_ok = vm_read_mem(vm, vm->PC, &instr_type, 5uLL);
    if ( read_ok )
    {
        if ( instr_type <= 0x80u )
        {
            if ( instr_type > 0x2Fu )
            {
                switch ( instr_type )
                {
                    case 0x30u:
                        if ( vm_stack_push(vm, instr) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x40u:
                        if ( vm_load_int(vm, instr, &arg1) )
                        {
                            if ( vm_stack_push(vm, arg1) )
                                goto LABEL_22;
                        }
                        else
                        {
                            fwrite("[E] invalid S.LDP, bad addr\n", 1uLL, 0x1CuLL, stderr);
                        }
                        vm->err_flag = 1;
                        return 0;
                    case 0x50u:
                        if ( vm_stack_pop(vm, &arg1) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x60u:
                        if ( vm_stack_pop(vm, (uint32_t *)&arg2) && vm_stack_pop(vm, &arg1) && vm_stack_push(vm, arg2 + arg1) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x61u:
                        if ( vm_stack_pop(vm, (uint32_t *)&arg2) && vm_stack_pop(vm, &arg1) && vm_stack_push(vm, arg2 - arg1) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x62u:
                        if ( vm_stack_pop(vm, (uint32_t *)&arg2) && vm_stack_pop(vm, &arg1) && vm_stack_push(vm, arg1 ^ arg2) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x63u:
                        if ( vm_stack_pop(vm, (uint32_t *)&arg2) && vm_stack_pop(vm, &arg1) && vm_stack_push(vm, arg1 & arg2) )
                            goto LABEL_22;
                        vm->err_flag = 1;
                        return 0;
                    case 0x70u:
                        vm->PC = instr;
                        return read_ok;
                    case 0x71u:
                        if ( (vm->FLAGS & 1) == 0 )
                            goto LABEL_22;
                        vm->PC = instr;
                        return read_ok;
                    case 0x72u:
                        if ( (vm->FLAGS & 1) != 0 )
                            goto LABEL_22;
                        vm->PC = instr;
                        return read_ok;
                    case 0x80u:
                        if ( !vm_stack_pop(vm, (uint32_t *)&arg2) || !vm_stack_pop(vm, &arg1) )
                        {
                            vm->err_flag = 1;
                            return 0;
                        }
                        vm_stack_compare(vm, arg2, arg1);
                        break;
                    default:
                        goto LABEL_91;
                }
                goto LABEL_22;
            }
            if ( instr_type == 0x10 )
            {
                if ( memcmp((char *)&instr + 1, &zeros3, 3uLL) )
                {
                    fwrite("[E] invalid S.LDB\n", 1uLL, 0x12uLL, stderr);
                    vm->err_flag = 1;
                    return 0;
                }
                if ( !vm_stack_pushb(vm, instr) )
                {
                    vm->err_flag = 1;
                    return 0;
                }
                goto LABEL_22;
            }
            if ( instr_type == 0x20 )
            {
                if ( memcmp((char *)&instr + 2, &zeros2, 2uLL) )
                {
                    fwrite("[E] invalid S.LDW\n", 1uLL, 0x12uLL, stderr);
                    vm->err_flag = 1;
                    return 0;
                }
                if ( !vm_stack_pushw(vm, instr) )
                {
                    vm->err_flag = 1;
                    return 0;
                }
LABEL_22:
                vm->PC += 5;
                return read_ok;
            }
LABEL_91:
            fprintf(stderr, "[E] invalid StackVM instruction, pc=%#x leader=%#x\n", vm->PC, instr_type);
            vm->err_flag = 1;
            return 0;
        }
        if ( instr_type == 0xA0 )
        {
            if ( vm_check_syscall(vm) )
            {
                if ( vm_stack_popb(vm, &sysnum) )
                {
                    switch ( sysnum )
                    {
                        case 0u:
                            if ( vm_input_int(vm, &arg1) && vm_stack_push(vm, arg1) )
                                goto LABEL_22;
                            vm->err_flag = 1;
                            return 0;
                        case 1u:
                            fwrite("[E] unsupported syscall!\n", 1uLL, 0x19uLL, stderr);
                            vm->err_flag = 1;
                            return 0;
                        case 2u:
                            if ( vm_stack_pop(vm, &arg1) && vm_stack_popb(vm, (uint8_t *)&arg2) && vm_output_mem(vm, arg1, arg2) )
                                goto LABEL_22;
                            vm->err_flag = 1;
                            return 0;
                        case 3u:
                            if ( !vm_stack_pop(vm, &arg1) )
                            {
                                vm->err_flag = 1;
                                return 0;
                            }
                            srand(arg1);
                            break;
                        case 4u:
                            if ( vm_rand(vm, &arg1) && vm_stack_push(vm, arg1) )
                                goto LABEL_22;
                            vm->err_flag = 1;
                            return 0;
                        case 5u:
                            if ( vm_print_flag(vm) )
                                goto LABEL_22;
                            vm->err_flag = 1;
                            return 0;
                        case 6u:
                            if ( vm_stack_pop(vm, (uint32_t *)&arg2) && vm_expand_mem(vm, arg2, &arg1) && vm_stack_push(vm, arg1) )
                                goto LABEL_22;
                            vm->err_flag = 1;
                            return 0;
                        default:
                            fwrite("[E] bad syscall!\n", 1uLL, 0x11uLL, stderr);
                            vm->err_flag = 1;
                            return 0;
                    }
                    goto LABEL_22;
                }
                vm->err_flag = 1;
            }
            else
            {
                fwrite("[E] can't execute that syscall!\n", 1uLL, 0x20uLL, stderr);
                vm->err_flag = 1;
            }
            return 0;
        }
        if ( instr_type != 0xFF )
            goto LABEL_91;
        read_ok = 0;
        if ( memcmp(&instr, &neg1_4, 4uLL) )
        {
            fwrite("[E] invalid S.HLT\n", 1uLL, 0x12uLL, stderr);
            vm->err_flag = 1;
        }
    }
    else
    {
        vm->err_flag = 1;
    }
    return read_ok;
}

bool vm_execute_reg(VM *vm)
{
    uint32_t PC; // esi
    bool ok; // bp
    uint8_t instr_0; // r12
    uint8_t instr_2; // r14
    uint8_t instr_; // r12
    uint32_t PC_; // esi
    char instr__; // al
    char instr_2_; // r13
    uint32_t reg; // esi
    uint32_t v11; // esi
    uint32_t v12; // esi
    uint32_t PC__; // esi
    uint32_t _PC; // esi
    uint32_t __PC; // esi
    uint32_t PC___; // esi
    int64_t rel_ind; // rax
    uint32_t ___PC; // esi
    uint64_t prod; // rax
    uint32_t _PC_; // esi
    uint64_t prod_; // rax
    uint32_t __PC_; // ebp
    uint32_t ___PC_; // esi
    uint8_t instr; // [rsp+Fh] [rbp-49h] BYREF
    uint32_t value; // [rsp+10h] [rbp-48h] BYREF
    uint32_t result; // [rsp+14h] [rbp-44h] BYREF
    uint64_t canary; // [rsp+18h] [rbp-40h]

    canary = __readfsqword(0x28u);
    PC = vm->PC;
    vm->PC = PC + 1;
    ok = vm_load_byte(vm, PC, &instr);
    if ( !ok )
    {
        vm->err_flag = 1;
        return ok;
    }
    instr_0 = instr;
    instr_2 = 0;
    if ( instr >> 4 == 0xA )
    {
        PC_ = vm->PC;
        vm->PC = PC_ + 1;
        if ( !vm_load_byte(vm, PC_, &instr) )
        {
            vm->err_flag = 1;
            return 0;
        }
        instr_2 = instr_0 & 0xF;
    }
    instr_ = instr;
    if ( (~instr & 0xC0) == 0 )
    {
        instr__ = instr & 7;
        instr_2_ = instr_2 & 3;
        if ( (instr & 4) == 0 )
        {
            reg = *(&vm->RA + (instr & 7));
LABEL_16:
            value = reg;
            if ( instr_2_ && !vm_load_int(vm, reg, &value) )
            {
                vm->err_flag = 1;
                return 0;
            }
LABEL_17:
            if ( instr_2 >> 2 )
            {
                if ( ((instr_ >> 3) & 4) != 0 )
                {
                    vm->err_flag = 1;
                }
                else
                {
                    if ( vm_store_int(vm, *(&vm->RA + ((instr_ >> 3) & 7)), value) )
                        return ok;
                    vm->err_flag = 1;
                }
            }
            else
            {
                if ( (instr_ & 0x20) == 0 )
                {
                    *(&vm->RA + ((instr_ >> 3) & 7)) = value;
                    return ok;
                }
                if ( ((instr_ >> 3) & 7) != 4 || (instr_ & 7) == 6 )
                {
                    vm->err_flag = 1;
                }
                else
                {
                    if ( vm_load_int(vm, vm->PC, &result) )
                    {
                        vm->PC += 4;
                        if ( vm_store_int(vm, result, value) )
                            return ok;
                    }
                    vm->err_flag = 1;
                }
            }
            return 0;
        }
        switch ( instr__ )
        {
            case 4:
                if ( !vm_load_int(vm, vm->PC, &result) || (vm->PC += 4, !vm_load_int(vm, result, &value)) )
                {
                    vm->err_flag = 1;
                    return 0;
                }
                break;
            case 5:
                if ( !vm_load_int(vm, vm->PC, &value) )
                {
                    vm->err_flag = 1;
                    return 0;
                }
                vm->PC += 4;
                break;
            case 6:
                reg = vm->SP;
                goto LABEL_16;
            default:
                vm->err_flag = 1;
                return 0;
        }
        if ( instr_2_ )
        {
            vm->err_flag = 1;
            return 0;
        }
        goto LABEL_17;
    }
    if ( (uint8_t)(instr - 0x11) <= 3u )
    {
        ok = vm_stack_push(vm, *(&vm->RA + instr - 17));
        if ( !ok )
            vm->err_flag = 1;
    }
    else if ( (uint8_t)(instr - 0x15) <= 3u )
    {
        ok = vm_stack_pop(vm, &result);
        if ( ok )
            *(&vm->RA + instr_ - 21) = result;
        else
            vm->err_flag = 1;
    }
    else if ( instr >> 4 == 7 )
    {
        vm_stack_compare(vm, *(&vm->RA + ((instr >> 2) & 3)), *(&vm->RA + (instr & 3)));
    }
    else if ( instr >> 4 == 8 )
    {
        ok = vm_load_int(vm, vm->PC, &result);
        if ( ok )
        {
            vm->PC += 4;
            vm_stack_compare(vm, *(&vm->RA + (instr_ & 3)), result);
        }
        else
        {
            vm->err_flag = 1;
        }
    }
    else
    {
        switch ( instr )
        {
            case 0u:
                return 0;
            case 1u:
                ok = vm_check_syscall(vm);
                if ( ok )
                {
                    switch ( vm->RA )
                    {
                        case 0u:
                            ok = vm_input_int(vm, &result);
                            if ( ok )
                                vm->RA = result;
                            else
                                vm->err_flag = 1;
                            break;
                        case 1u:
                            ok = vm_input_mem(vm, vm->RB, vm->RC);
                            if ( !ok )
                                vm->err_flag = 1;
                            break;
                        case 2u:
                            ok = vm_output_mem(vm, vm->RB, vm->RC);
                            if ( !ok )
                                vm->err_flag = 1;
                            break;
                        case 3u:
                            srand(vm->RB);
                            break;
                        case 4u:
                            ok = vm_rand(vm, &result);
                            if ( ok )
                                vm->RA = result;
                            else
                                vm->err_flag = 1;
                            break;
                        case 5u:
                            fwrite("[E] unsupported syscall!\n", 1uLL, 0x19uLL, stderr);
                            vm->err_flag = 1;
                            ok = 0;
                            break;
                        case 6u:
                            ok = vm_expand_mem(vm, vm->RB, &result);
                            if ( ok )
                                vm->RA = result;
                            else
                                vm->err_flag = 1;
                            break;
                        default:
                            fwrite("[E] bad syscall!\n", 1uLL, 0x11uLL, stderr);
                            vm->err_flag = 1;
                            ok = 0;
                            break;
                    }
                }
                else
                {
                    fwrite("[E] can't execute that syscall!\n", 1uLL, 0x20uLL, stderr);
                    vm->err_flag = 1;
                }
                return ok;
            case 0x10u:
                if ( !vm_load_int(vm, vm->PC, &result) || (vm->PC += 4, !(ok = vm_stack_push(vm, result))) )
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x20u:
                v11 = vm->PC;
                vm->PC = v11 + 1;
                ok = vm_load_byte(vm, v11, &result);
                if ( ok )
                    *(&vm->RA + ((((uint8_t)result >> 4) - 1) & 3)) += *(&vm->RA + (((uint8_t)result - 1) & 3));
                else
                    vm->err_flag = 1;
                return ok;
            case 0x21u:
                v12 = vm->PC;
                vm->PC = v12 + 1;
                if ( vm_load_byte(vm, v12, &value) && (ok = vm_load_int(vm, vm->PC, &result)) )
                {
                    vm->PC += 4;
                    *(&vm->SP + ((uint8_t)value >> 4)) += result;
                }
                else
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x30u:
                PC__ = vm->PC;
                vm->PC = PC__ + 1;
                ok = vm_load_byte(vm, PC__, &result);
                if ( ok )
                    *(&vm->RA + (uint8_t)(((uint8_t)result >> 4) - 1)) -= *(&vm->RA + (uint8_t)((result & 0xF) - 1));
                else
                    vm->err_flag = 1;
                return ok;
            case 0x31u:
                _PC = vm->PC;
                vm->PC = _PC + 1;
                if ( !vm_load_byte(vm, _PC, &value) )
                    goto LABEL_89;
                ok = vm_load_int(vm, vm->PC, &result);
                if ( !ok )
                    goto LABEL_89;
                vm->PC += 4;
                if ( (uint8_t)(((uint8_t)value >> 4) - 1) <= 3u )
                {
                    *(&vm->RA + (uint8_t)(((uint8_t)value >> 4) - 1)) -= result;
                }
                else if ( (uint8_t)value >> 4 == 5 )
                {
                    vm->SP -= result;
                }
                else
                {
LABEL_89:
                    vm->err_flag = 1;
                    ok = 0;
                }
                break;
            case 0x40u:
                __PC = vm->PC;
                vm->PC = __PC + 1;
                ok = vm_load_byte(vm, __PC, &result);
                if ( ok )
                    *(&vm->RA + (uint8_t)(((uint8_t)result >> 4) - 1)) ^= *(&vm->RA + (uint8_t)((result & 0xF) - 1));
                else
                    vm->err_flag = 1;
                return ok;
            case 0x41u:
                PC___ = vm->PC;
                vm->PC = PC___ + 1;
                if ( vm_load_byte(vm, PC___, &value) && (ok = vm_load_int(vm, vm->PC, &result)) )
                {
                    vm->PC += 4;
                    rel_ind = ((uint8_t)value >> 4) - 1 + 12LL;
                    *(uint32_t *)((char *)&vm->data + 4 * rel_ind + 3) ^= result;
                }
                else
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x50u:
                ___PC = vm->PC;
                vm->PC = ___PC + 1;
                ok = vm_load_byte(vm, ___PC, &result);
                if ( ok )
                {
                    prod = *(&vm->RA + (uint8_t)(((uint8_t)result >> 4) - 1))
                             * (uint64_t)*(&vm->RA + (uint8_t)((result & 0xF) - 1));
                    vm->RA = prod;
                    vm->RD = HIDWORD(prod);
                }
                else
                {
                    vm->err_flag = 1;
                }
                return ok;
            case 0x51u:
                _PC_ = vm->PC;
                vm->PC = _PC_ + 1;
                if ( vm_load_byte(vm, _PC_, &value) && (ok = vm_load_int(vm, vm->PC, &result)) )
                {
                    vm->PC += 4;
                    prod_ = result * (uint64_t)*(&vm->RA + ((((uint8_t)value >> 4) + 3) & 3));
                    vm->RA = prod_;
                    vm->RD = HIDWORD(prod_);
                }
                else
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x60u:
                __PC_ = vm->PC;
                if ( vm_load_int(vm, __PC_, &result) && (ok = vm_stack_push(vm, __PC_ + 4)) )
                {
                    vm->PC = result;
                }
                else
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x61u:
                ___PC_ = vm->PC;
                vm->PC = ___PC_ + 1;
                if ( vm_load_byte(vm, ___PC_, &value) && (vm->SP += 4 * (uint8_t)value, ok = vm_stack_pop(vm, &result)) )
                {
                    vm->PC = result;
                }
                else
                {
                    vm->err_flag = 1;
                    return 0;
                }
                return ok;
            case 0x62u:
                if ( (vm->FLAGS & 1) != 0 )
                {
                    ok = vm_load_int(vm, vm->PC, &result);
                    if ( ok )
                        vm->PC = result;
                    else
                        vm->err_flag = 1;
                }
                else
                {
                    vm->PC += 4;
                }
                return ok;
            case 0x63u:
                if ( (vm->FLAGS & 1) != 0 )
                {
                    vm->PC += 4;
                }
                else
                {
                    ok = vm_load_int(vm, vm->PC, &result);
                    if ( ok )
                        vm->PC = result;
                    else
                        vm->err_flag = 1;
                }
                return ok;
            case 0x64u:
                if ( (vm->FLAGS & 2) != 0 )
                {
                    ok = vm_load_int(vm, vm->PC, &result);
                    if ( ok )
                        vm->PC = result;
                    else
                        vm->err_flag = 1;
                }
                else
                {
                    vm->PC += 4;
                }
                return ok;
            case 0x68u:
                ok = vm_load_int(vm, vm->PC, &result);
                if ( ok )
                    vm->PC = result;
                else
                    vm->err_flag = 1;
                return ok;
            default:
                fprintf(stderr, "[E] invalid RegVM instruction, pc=%#x leader=%#x\n", vm->PC, instr);
                vm->err_flag = 1;
                return 0;
        }
    }
    return ok;
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

void vm_error(VM *vm, bool print_stk)
{
    int i; // ebp
    uint32_t stk_addr; // r12d
    const char *ptr_char; // rsi
    uint32_t stk_value; // [rsp+Ch] [rbp-44h] BYREF
    uint64_t canary; // [rsp+10h] [rbp-40h]

    canary = __readfsqword(0x28u);
    printf(
        "    ---[ PC=0x%08x SP=0x%08x | A=0x%08x B=0x%08x C=0x%08x D=0x%08x\n",
        vm->PC,
        vm->SP,
        vm->RA,
        vm->RB,
        vm->RC,
        vm->RD);
    if ( print_stk )
    {
        puts("    ---[ STACK CONTENTS");
        for ( i = -8; i != 20; i += 4 )
        {
            stk_addr = vm->SP + i;
            if ( !vm_load_int(vm, stk_addr, &stk_value) )
                break;
            ptr_char = "    ";
            if ( vm->SP == stk_addr )
                ptr_char = "* ";
            printf("\t%s0x%08x    0x%08x\n", ptr_char, stk_addr, stk_value);
        }
    }
}

bool read_seg(VMSegs *vmsegs, size_t off, FILE *fptr)
{
    int *errno_ptr_; // rax
    char *errstr_; // rax
    int *errno_ptr; // rax
    char *errstr; // rax
    int *errno_ptr__; // rax
    char *errstr__; // rax
    int *errno_ptr___; // rax
    char *errstr___; // rax
    size_t size; // r14
    void *seg_data; // rbp
    size_t seg_read; // rax
    size_t size_; // rdx
    int *errno_ptr____; // rax
    char *errstr____; // rax
    int *errno_ptr_____; // rax
    char *errstr_____; // rax
    SegInfo seg_info; // [rsp+3h] [rbp-35h] BYREF
    uint64_t canary; // [rsp+8h] [rbp-30h]

    canary = __readfsqword(0x28u);
    if ( fseek(fptr, off, 0) == -1 )
    {
        errno_ptr = __errno_location();
        errstr = strerror(*errno_ptr);
        fprintf(stderr, "[E] couldn't seek to segment header - %s\n", errstr);
        return 0;
    }
    if ( fread(&seg_info, 1uLL, 1uLL, fptr) != 1 )
    {
        errno_ptr_ = __errno_location();
        errstr_ = strerror(*errno_ptr_);
        fprintf(stderr, "[E] couldn't read segment type - %s\n", errstr_);
        return 0;
    }
    if ( fread(&seg_info.offset, 2uLL, 1uLL, fptr) != 1 )
    {
        errno_ptr__ = __errno_location();
        errstr__ = strerror(*errno_ptr__);
        fprintf(stderr, "[E] couldn't read segment offset - %s\n", errstr__);
        return 0;
    }
    if ( fread(&seg_info.size, 2uLL, 1uLL, fptr) != 1 )
    {
        errno_ptr___ = __errno_location();
        errstr___ = strerror(*errno_ptr___);
        fprintf(stderr, "[E] couldn't read segment size - %s\n", errstr___);
        return 0;
    }
    if ( fseek(fptr, seg_info.offset, 0) == -1 )
    {
        errno_ptr____ = __errno_location();
        errstr____ = strerror(*errno_ptr____);
        fprintf(stderr, "[E] couldn't seek to segment chunk at %#x - %s\n", seg_info.offset, errstr____);
        return 0;
    }
    size = seg_info.size;
    seg_data = malloc(seg_info.size);
    seg_read = fread(seg_data, 1uLL, size, fptr);
    size_ = seg_info.size;
    if ( seg_read != seg_info.size )
    {
        errno_ptr_____ = __errno_location();
        errstr_____ = strerror(*errno_ptr_____);
        fprintf(stderr, "[E] couldn't read segment data - %s\n", errstr_____);
LABEL_17:
        free(seg_data);
        return 0;
    }
    switch ( seg_info.type )
    {
        case 2u:
            vmsegs->seg2.data = seg_data;
            vmsegs->seg2.size = size_;
            return 1;
        case 3u:
            vmsegs->seg3.data = seg_data;
            vmsegs->seg3.size = size_;
            return 1;
        case 1u:
            vmsegs->seg1.data = seg_data;
            vmsegs->seg1.size = size_;
            return 1;
        default:
            fprintf(stderr, "[E] invalid segment type: %d\n", seg_info.type);
            goto LABEL_17;
    }
}

void clear_vmsegs(VMSegs *vmsegs)
{
    void *data; // rdi
    void *data_; // rdi
    void *data__; // rdi

    if ( vmsegs )
    {
        data = vmsegs->seg1.data;
        if ( data )
        {
            free(data);
            vmsegs->seg1.data = 0LL;
        }
        data_ = vmsegs->seg2.data;
        if ( data_ )
        {
            free(data_);
            vmsegs->seg2.data = 0LL;
        }
        data__ = vmsegs->seg3.data;
        if ( data__ )
        {
            free(data__);
            vmsegs->seg3.data = 0LL;
        }
    }
}

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