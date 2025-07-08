class Segment:
    def __init__(self, off, size):
        self.off = off
        self.size = size

    def __repr__(self):
        return f"({self.off:#x} : {self.size:#x})"


class MemSeg:
    def __init__(self, data, vaddr):
        self.data = data
        self.vaddr = vaddr


class VM:
    def __init__(self, fname):
        self.content = open(fname, "rb").read()
        self.fp = 4
        assert(self.content[:4] == b"MASM")

        self.segs = [None] * 3

        for _ in range(3): self.parse_seg()

        self.init_vm()

    def parse_seg(self):
        seg_type = self.content[self.fp]
        seg_off = int.from_bytes(self.content[self.fp+1:self.fp+3], 'little')
        seg_size = int.from_bytes(self.content[self.fp+3:self.fp+5], 'little')
        self.fp += 5

        self.segs[seg_type - 1] = Segment(seg_off, seg_size)
    
    def init_vm(self):
        self.code = self.content[self.segs[0].off:self.segs[0].off+self.segs[0].size] + bytes([0] * (0x1000 - self.segs[0].size))
        self.data = self.content[self.segs[1].off:self.segs[1].off+self.segs[1].size] + bytes([0] * (0x1000 - self.segs[1].size))
        self.stack = bytes([0] * 0x1000)
        self.bitmask = self.content[self.segs[2].off:self.segs[2].off+self.segs[2].size]

        self.pc = 0

    def get_reg(self, i):
        if i > 3:
            return 'SP'
        return 'R' + chr(ord('A') + i)
    
    def run(self):
        while self.pc < self.segs[0].size:
            self.execute()
    
    def execute(self):
        print(f"{self.pc + 0x1000:#06x} : ", end='')
        if self.test_bit():
            self.execute_reg()
        else:
            self.execute_stack()
        
    def test_bit(self):
        ind = self.pc
        byte = self.bitmask[ind >> 3] >> (self.pc & 7)
        return byte & 1

    def execute_stack(self):
        instr = self.code[self.pc:self.pc+5]
        itype = instr[0]
        ival = int.from_bytes(instr[1:], 'little')
        self.pc += 5

        if itype == 0x10:
            print(f"PUSHB {ival & 0xff:#x}")
        elif itype == 0x20:
            print(f"PUSHW {ival & 0xffff:#x}")
        elif itype == 0x30:
            print(f"PUSH {ival:#x}")
        elif itype == 0x40:
            print(f"PUSH [{ival:#x}]")
        elif itype == 0x50:
            print(f"POP")
        elif itype == 0x60:
            print(f"STACK_ADD")
        elif itype == 0x61:
            print(f"STACK_SUB")
        elif itype == 0x62:
            print(f"STACK_XOR")
        elif itype == 0x63:
            print(f"STACK_AND")
        elif itype == 0x70:
            print(f"JMP {ival:#x}")
        elif itype == 0x71:
            print(f"JE {ival:#x}")
        elif itype == 0x72:
            print(f"JNE {ival:#x}")
        elif itype == 0x80:
            print(f"STACK_CMP")
        elif itype == 0xa0:
            print(f"STACK_SYSCALL")

    def execute_reg(self):
        instr = self.code[self.pc]
        self.pc += 1

        instr0 = instr
        instr2 = 0
        if instr >> 4 == 0xa:
            instr = self.code[self.pc]
            self.pc += 1
            instr2 = instr0 & 0xf
        
        if (~instr & 0xc0) == 0:
            if instr & 4 == 0:
                ri = instr & 7
                rj = (instr >> 3) & 7
                if instr2 & 3:
                    val = f"[{self.get_reg(ri)}]"
                else:
                    val = f"{self.get_reg(ri)}"
                
                if instr2 >> 2:
                    print(f"MOV [{self.get_reg(rj)}], {val}")
                else:
                    if instr & 0x20 == 0:
                        print(f"MOV {self.get_reg(rj)}, {val}")
                if (instr >> 3) & 7 == 4 and instr & 7 != 6:
                    res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
                    self.pc += 4
                    print(f"MOV [{res:#x}], {val}")
            else:
                if instr & 7 == 4:
                    res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
                    self.pc += 4
                    val = f"[{res:#x}]"
                elif instr & 7 == 5:
                    res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
                    self.pc += 4
                    val = f"{res:#x}"
                elif instr & 7 == 6:
                    if instr2 & 3:
                        val = f"[SP]"
                    else:
                        val = f"SP"
                
                rj = (instr >> 3) & 7
                
                if instr2 >> 2:
                    print(f"MOV [{self.get_reg(rj)}], {val}")
                else:
                    if instr & 0x20 == 0:
                        print(f"MOV {self.get_reg(rj)}, {val}")
                if (instr >> 3) & 7 == 4 and instr & 7 != 6:
                    res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
                    self.pc += 4
                    print(f"MOV [{res:#x}], {val}")
            return
        
        if instr == 0:
            print(f"HALT")
        elif instr == 1:
            print(f"SYSCALL")
        elif instr >> 4 == 7:
            ri1 = (instr >> 2) & 3
            ri2 = instr & 3
            print(f"CMP {self.get_reg(ri1)}, {self.get_reg(ri2)}")
        elif instr >> 4 == 8:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            ri = instr & 3
            print(f"CMP {self.get_reg(ri)}, {res:#x}")
        elif instr == 0x10:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"PUSH {res:#x}")
        elif instr - 0x11 <= 3:
            print(f"PUSH {self.get_reg(instr - 0x11)}")
        elif instr - 0x15 <= 3:
            print(f"POP {self.get_reg(instr - 0x15)}")
        elif instr == 0x20:
            regs = self.code[self.pc]
            self.pc += 1
            ri1 = ((regs >> 4) - 1) & 3
            ri2 = (regs - 1) & 3
            print(f"ADD {self.get_reg(ri1)}, {self.get_reg(ri2)}")
        elif instr == 0x21:
            regs = self.code[self.pc]
            self.pc += 1
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"ADD {self.get_reg((regs >> 4) - 1)}, {res}")
        elif instr == 0x30:
            regs = self.code[self.pc]
            self.pc += 1
            ri1 = ((regs >> 4) - 1) & 3
            ri2 = (regs - 1) & 3
            print(f"SUB {self.get_reg(ri1)}, {self.get_reg(ri2)}")
        elif instr == 0x31:
            regs = self.code[self.pc]
            self.pc += 1
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"SUB {self.get_reg((regs >> 4) - 1)}, {res}")
        elif instr == 0x40:
            regs = self.code[self.pc]
            self.pc += 1
            ri1 = ((regs >> 4) - 1) & 3
            ri2 = (regs - 1) & 3
            print(f"XOR {self.get_reg(ri1)}, {self.get_reg(ri2)}")
        elif instr == 0x41:
            regs = self.code[self.pc]
            self.pc += 1
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"XOR {self.get_reg((regs >> 4) - 1)}, {res}")
        elif instr == 0x50:
            regs = self.code[self.pc]
            self.pc += 1
            ri1 = ((regs >> 4) - 1) & 3
            ri2 = (regs - 1) & 3
            print(f"MUL {self.get_reg(ri1)}, {self.get_reg(ri2)}")
        elif instr == 0x51:
            regs = self.code[self.pc]
            self.pc += 1
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"MUL {self.get_reg((regs >> 4) - 1)}, {res}")
        elif instr == 0x60:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"CALL {res:#x}")
        elif instr == 0x61:
            popn = self.code[self.pc]
            self.pc += 1
            print(f"RETN {popn:#x}")
        elif instr == 0x62:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"JE {res:#x}")
        elif instr == 0x63:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"JNE {res:#x}")
        elif instr == 0x64:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"JL {res:#x}")
        elif instr == 0x68:
            res = int.from_bytes(self.code[self.pc:self.pc+4], 'little')
            self.pc += 4
            print(f"JMP {res:#x}")


vm = VM("crackme.masm")
vm.run()